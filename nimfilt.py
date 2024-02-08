#!/bin/env python3
import sys
import string
import re
import ntpath
from binascii import unhexlify
from functools import reduce

NIM_STD = ["system", "core", "pure", "js", "impure", "std", "windows", "posix", "wrappers"]
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

def _multi_replace(stri: str, conversions: dict) -> str:
    return reduce(lambda s, conv: s.replace(conv[0], conv[1]), conversions.items(), stri)

# return first match + length of key
def __decode_specialchar(substring):
    try:
        fnd_key = list(filter(lambda k: substring.startswith(k), SPECIAL_CHAR_CONVS.keys()))[0]
        return SPECIAL_CHAR_CONVS[fnd_key],len(fnd_key)
    except IndexError:
         return substring[0], 1

# Return string with replacements
def _decode_specialchars(stri: str) -> str:
    return _multi_replace(stri, SPECIAL_CHAR_CONVS)

def _encode_specialchars(stri: str) -> str:
    convs = {
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
    return _multi_replace(stri, convs)

# compiler/modulepaths;.nim -> demangleModuleName
def _decode_module_name(module_name: str) -> str:
    convs = {
        "@s": "/",
        "@h": "#",
        "@c": ":",
        "@m": "",
        "@@": "@"
    }
    return _multi_replace(module_name, convs)

# adapted from clean_function_name in https://github.com/SentineLabs/AlphaGolang/blob/main/2.function_discovery_and_renaming.py
def _clean_name_ida(name: str) -> str:
    STRIP_CHARS = r'[()\[\]{} "]'
    REPLACE_CHARS = r'[,;]'
    name = re.sub(STRIP_CHARS, "", name)
    return re.sub(REPLACE_CHARS, "_", name)

# compiler/msgs.nim -> uniqueModuleName
def demangle_module(name: str) -> str:
    plain = ""
    i = 0
    while i < len(name):
        if name[i] in string.ascii_uppercase:
            if name[i] == "Z":
                plain = plain + "/"
            elif name[i] == "O":
                plain = plain+"."
            else:
                raise ValueError("Invalid special character '{}' in module name".format(name[i]))
        elif name[i] in string.ascii_lowercase:
            plain = plain + name[i]
        elif name[i] in string.digits and name[i+1] in string.digits:
            plain = plain + chr(int(name[i:i+2]))
            i+=1
        else:
            plain = plain + name[i]
        i+=1
    return plain

# Parse hex encoded substrings strings
def __Xsubstring(substring):
    if len(substring) < 3:
        return "X", 1
    elif all(map(lambda c: c in string.hexdigits.upper(), substring[1:3])):
        return unhexlify(substring[1:3]).decode("utf-8"),3
    else:
        return "X", 1

# See https://github.com/nim-lang compiler/ccgutils.nim:mangle
def demangle_function(name: str) -> str:
    plain = ""
    if name[-1] != "_": #underscore is added at the end of the name if any special encoding had to be performed
        if name[0] == "X":
            name = name[1:]
        return name

    name = name[:-1] # remove trailing _
    i = 0
    if name[0] == "X" and name[1] in string.digits and name[2] not in string.hexdigits.upper():
        plain = plain + name[1]
        i = 2

    while i < len(name):
        if name[i] == "X":
            v,l = __Xsubstring(name[i:i+3])
            i += l
            plain = plain + v
        elif name[i] in string.ascii_lowercase:
            v,l = __decode_specialchar(name[i:])
            i += l
            plain = plain + v
        else:
            plain = plain + name[i]
            i += 1

    return plain

# Represents a regular Package+function name
class NimName():
    def __init__(self, namestr):
        # <Function name>__<Package Name>_u<numeric ID>_<numeric IDA suffix>.<compiler suffix>@<C++ mangled arguments>
        m = re.fullmatch(r'@?([a-zA-Z0-9_]+_?)__(.*)(_u[0-9]+)(_[0-9]+)?(\.[a-z]+\.[0-9]+)(@[0-9]+)?', namestr)
        if m is None or len(m.group(1)) <= 1:
            raise ValueError("Invalid Nim function name \"{}\"".format(namestr))
        self.fnname = demangle_function(m.group(1))
        self.pkgname = demangle_module(m.group(2))
        self.suffix = m.group(3)[1:]
        self.ida_suffix = m.group(4)
        self.num_args = m.group(6)

    @property
    def _clean_pkgname(self):
        return re.sub(r"[/\\\-.]", "_", _clean_name_ida(self.pkgname))

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

    # TODO: Implement check when a path is used as the package name
    def is_std(self):
        return any([self.pkgname.startswith(std) for std in NIM_STD])

    def is_nimble(self):
        return "/.nimble/" in self.pkgname

    def __str__(self):
        return "{}::{} {}".format(self.pkgname, self.fnname, self.suffix)

    def __repr__(self):
        return "{:s}({:s})".format(type(self).__name__, str(self))

class NimInitName(NimName):
    def __init__(self, namestr):
        m = re.fullmatch(r'@?((at|@)m.+)_((Dat|Hcr)?Init[0-9]{3})(_[0-9+])?(@[0-9]+)?', namestr)
        if m is None:
            raise ValueError("Invalid NIM Init name \"{}\"".format(namestr))
        self.fnname = m.group(3)
        pkgname = m.group(1)
        if m.group(2) == "at":
            pkgname = _decode_specialchars(pkgname)
        # TODO: Differentiate file and module name if they're not the same
        self.pkgname = _decode_module_name(pkgname)
        self.suffix = None
        self.ida_suffix = m.group(5)
        self.num_args = m.group(6)

    def __str__(self):
        return "{}::{}".format(self.pkgname, self.fnname)

# Returns an instance of the correct subtype of NimName based on the name given
def NimNameCreator(namestr: str) -> NimName:
    for T in [*NimName.__subclasses__(), NimName]:
        try:
            name = T(namestr)
            return name
        except ValueError:
            pass
    raise ValueError("Invalid Nim name \"{}\"".format(namestr))

if __name__ == "__main__":
    name = sys.argv[1]
    try:
        n = NimNameCreator(name)
        print(n)
    except ValueError:
        print(name)
