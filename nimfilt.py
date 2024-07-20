#!/bin/env python3
# -*- encoding: utf8 -*-
#
# Copyright (c) 2024 ESET
# Author: Alexandre Côté Cyr <alexandre.cote@eset.com>
# See LICENSE file for redistribution.

import string
import re
from binascii import unhexlify
from functools import reduce

NIM_STD = ["system", "core", "pure", "js", "impure", "std", "windows", "posix", "wrappers"]
NIM_FUNC_NAMES = ["NimMain", "NimMainInner", "NimMainModule"]
SUF_NONE = 0
SUF_NIM = 1
SUF_IDA = 2

SPECIAL_CHAR_CONVS = {
    "dollar": "$",
    "percent": "%",
    "amp": "&",
    "roof": "^",
    "emark": "!",
    "qmark": "?",
    "star": "*",
    "plus": "+",
    "minus": "-",
    "backslash": "\\",
    "slash": "/",
    "eq": "=",
    "lt": "<",
    "gt": ">",
    "tilde": "~",
    "colon": ":",
    "dot": ".",
    "at": "@",
    "bar": "|"
}

def _multi_replace(stri, conversions):
    """
    Replaces multiple characters in a string.

    :type stri: str
    :type conversion: dict

    :rtype: str
    """

    return reduce(lambda s, conv: s.replace(conv[0], conv[1]), conversions.items(), stri)

def __decode_specialchar(substring):
    """
    Finds first match of special character in substring.

    :type substring: str

    :return: First match and lenght of key
    :rtype: Tuple[str, int]
    """

    try:
        fnd_key = list(filter(lambda k: substring.startswith(k), SPECIAL_CHAR_CONVS.keys()))[0]
        return SPECIAL_CHAR_CONVS[fnd_key], len(fnd_key)
    except IndexError:
        return substring[0], 1

def _decode_specialchars(stri):
    """
    Decodes special characters in string.

    :type stri: str

    :rtype: str
    """

    return _multi_replace(stri, SPECIAL_CHAR_CONVS)

SPECIAL_CHAR_ENCODINGS = {
    "$": "DOLLAR",
    "%": "PERCENT",
    "&": "AND",
    "^": "ROOF",
    "!": "EXCL",
    "?": "QMARK",
    "*": "STAR",
    "+": "PLUS",
    "-": "MINUS",
    "/": "SLASH",
    "\\": "BSLASH",
    "=": "EQ",
    "<": "LT",
    ">": "GT",
    "~": "TILDE",
    ":": "COLON",
    ".": "DOT",
    "@": "AT",
    "|": "PIPE"
}

def _encode_specialchars(stri):
    """
    Encodes special characters in string.

    :type stri: str

    :rtype: str
    """

    return _multi_replace(stri, SPECIAL_CHAR_ENCODINGS)

MODULE_NAME_DECODINGS = {
    "@s": "/",
    "@h": "#",
    "@c": ":",
    "@m": "",
    "@@": "@"
}

def _decode_module_name(module_name):
    """
    Decodes a module name.

    See: compiler/modulepaths;.nim -> demangleModuleName

    :type module_name: str

    :rtype: str
    """

    dec = _multi_replace(module_name, MODULE_NAME_DECODINGS)
    if dec.endswith(".nim"):
        dec = dec[:-len(".nim")]
    return dec

IDA_STRIP_CHARS_RE = re.compile(r'[()\[\]{} "]')
IDA_REPLACE_CHARS_RE = re.compile(r'[,;]')

def _clean_name_ida(name):
    """
    Cleans up IDA name chars.

    :type name: str

    :rtype: str
    """

    name = IDA_STRIP_CHARS_RE.sub("", name)
    return IDA_REPLACE_CHARS_RE.sub("_", name)

def demangle_module(name):
    """
    Demangles a module name.

    See: compiler/msgs.nim -> uniqueModuleName

    :type name: str

    :rtype: str
    """

    plain = ""
    i = 0
    while i < len(name):
        if name[i] in string.ascii_uppercase:
            if name[i] == "Z":
                plain = plain + "/"
            elif name[i] == "O":
                plain = plain + "."
            else:
                raise ValueError("Invalid special character '{}' in module name".format(name[i]))
        elif name[i] in string.ascii_lowercase:
            plain = plain + name[i]
        elif name[i] in string.digits and len(name) > i + 1 and name[i + 1] in string.digits:
            plain = plain + chr(int(name[i:i + 2]))
            i += 1
        else:
            plain = plain + name[i]
        i += 1
    return plain

def __Xsubstring(substring):
    """
    Parses a hex encoded substrings strings
    
    :type substring: str

    :return: The parsed value and length and hown many characters were parsed
    :rtype: Tuple[str, int]
    """

    if len(substring) < 3:
        return "X", 1
    elif all(map(lambda c: c in string.hexdigits.upper(), substring[1:3])):
        return unhexlify(substring[1:3]).decode("utf-8"), 3
    else:
        return "X", 1

def demangle_function(name):
    """
    Demangles a function name.

    See: https://github.com/nim-lang compiler/ccgutils.nim:mangle

    :type name: str

    :rtype: str
    """

    plain = ""
    if name[-1] != "_":  # underscore is added at the end of the name if any special encoding had to be performed
        if name[0] == "X":
            name = name[1:]
        return name

    name = name[:-1]  # remove trailing _
    i = 0
    if name[0] == "X" and name[1] in string.digits and name[2] not in string.hexdigits.upper():
        plain = plain + name[1]
        i = 2

    while i < len(name):
        if name[i] == "X":
            v, ln = __Xsubstring(name[i:i + 3])
            i += ln
            plain = plain + v
        elif name[i] in string.ascii_lowercase:
            v, ln = __decode_specialchar(name[i:])
            i += ln
            plain = plain + v
        else:
            plain = plain + name[i]
            i += 1

    return plain

class NimName():
    """
    Represents a regular Package+function name
    """

    # <Function name>__<Package Name>_u<numeric ID>.cold_<numeric IDA suffix>.<compiler suffix>@<C++ mangled arguments>
    NAME_RE = re.compile(r'^@?([a-zA-Z0-9_]+_?)__([^@_]+)(_u[0-9]+)?(\.cold)?(_[0-9]+)?(\.[a-z]+\.[0-9]+)?(@[0-9]+)?$')

    RELATIVE_RE = re.compile(r"(\.\.\/)+")
    SLASH_RE = re.compile(r"[/\\\-.]")

    def __init__(self, namestr):
        m = NimName.NAME_RE.match(namestr)
        if m is None or len(m.group(1)) <= 1:
            raise ValueError("Invalid Nim function name \"{}\"".format(namestr))
        self.fnname = demangle_function(m.group(1)) + (".cold" if m.group(4) else "")
        self.pkgname = demangle_module(m.group(2))
        self.suffix = None if m.group(3) is None else m.group(3)[1:]
        self.ida_suffix = m.group(5)
        self.num_args = m.group(7)

    @property
    def _clean_pkgname(self):
        tmp = NimName.RELATIVE_RE.sub("../", self.pkgname)
        return NimName.SLASH_RE.sub("_", _clean_name_ida(tmp))

    @property
    def ida_dirname(self):
        return NimName.RELATIVE_RE.sub(r"(\.\./)+", "_/", self.pkgname)

    @property
    def _clean_fnname(self):
        name = _clean_name_ida(self.fnname)
        return _encode_specialchars(name)

    @property
    def clean_name(self):
        return "{}::{}".format(self._clean_pkgname, self._clean_fnname)

    def get_ida_name(self, suffix=SUF_NONE):
        name = self.clean_name
        if suffix & SUF_NIM and self.suffix is not None:
            name = "{}_{}".format(name, self.suffix)
        if suffix & SUF_IDA and self.ida_suffix is not None:
            name = "{}_{}".format(name, self.ida_suffix)
        if self.num_args is not None and len(self.num_args) > 0:
            name = "@{}{}".format(name, self.num_args)
        return name

    def is_std(self):
        """
        TODO: Implement check when a path is used as the package name
        """

        return any([self.pkgname.startswith(std) for std in NIM_STD])

    def is_nimble(self):
        return "/.nimble/" in self.pkgname

    def __str__(self):
        return "{}::{} {}".format(self.pkgname, self.fnname, self.suffix)

    def __repr__(self):
        return "{:s}({:s})".format(type(self).__name__, str(self))

class NimInitName(NimName):
    """
    Represents the NimInit name.
    """

    NAME_RE = re.compile(r'^@?((at|@)m.+)_((Dat|Hcr)?Init[0-9]{3})(_[0-9+])?(@[0-9]+)?$')

    def __init__(self, namestr):
        m = NimInitName.NAME_RE.match(namestr)
        if m is None:
            raise ValueError("Invalid NIM Init name \"{}\"".format(namestr))
        self.fnname = m.group(3)
        pkgname = m.group(1)
        if m.group(2) == "at":
            pkgname = _decode_specialchars(pkgname)
        self.pkgname = _decode_module_name(pkgname)
        self.suffix = None
        self.ida_suffix = m.group(5)
        self.num_args = m.group(6)

    def __str__(self):
        return "{}::{}".format(self.pkgname, self.fnname)

def NimNameCreator(namestr):
    """
    Returns an instance of the correct subtype of NimName based on the name given

    :type namestr: str

    :rtype: NimName
    """

    for T in [NimInitName, NimName]:
        try:
            name = T(namestr)
            return name
        except ValueError:
            pass
    raise ValueError("Invalid Nim name \"{}\"".format(namestr))

def main():
    from argparse import ArgumentParser
    import sys

    parser = ArgumentParser(
        prog="nimfilt",
        description="Demangle Nim module and method names",
        epilog="Demangled names are displayed to STDOUT. If a name cannot be demangled, it is output to STDOUT as is.")
    parser.add_argument("mangled_names", type=str, nargs="*", metavar="mangled_name",
                        help="Symbol name mangled by Nim")
    args = parser.parse_args()
    if len(args.mangled_names) > 0:
        names = args.mangled_names
    elif not sys.stdin.isatty():
        names = map(str.rstrip, sys.stdin)
    else:
        parser.print_help()
        names = []
    for name in names:
        try:
            n = NimNameCreator(name)
            print(n)
        except ValueError:
            print(name)

if __name__ == "__main__":
    main()
