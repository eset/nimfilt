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

def _encode_specialchars(string):
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
    return reduce(lambda s, conv: s.replace(conv[0], conv[1]), convs.items(), string)

# adapted from clean_function_name in https://github.com/SentineLabs/AlphaGolang/blob/main/2.function_discovery_and_renaming.py
def _clean_name_ida(name):
    STRIP_CHARS = r'[()\[\]{} "]'
    REPLACE_CHARS = r'[,;]'
    name = re.sub(STRIP_CHARS, "", name)
    return re.sub(REPLACE_CHARS, "_", name)

# See https://github.com/nim-lang compiler/msgs.nim:uniqueModuleName
def demangle_module(name):
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


def __Xsubstring(substring):
    if len(substring) < 3:
        return "X",1
    elif all(map(lambda c: c in string.hexdigits.upper(), substring[1:3])):
        return unhexlify(substring[1:3]).decode("utf-8"),3
    else:
        return "X",1

def __decode_specialchar(substring):
    convs = {
        "dollar": "$",
        "percent": "%",
        "amp": "&",
        "roof": "^",
        "emark": "!",
        "qmark": "?",
        "star": "*",
        "plus": "+",
        "minus": "-",
        "slash": "/",
        "backslash": "\\",
        "eq": "=",
        "lt": "<",
        "gt": ">",
        "tilde": "~",
        "colon": ":",
        "dot": ".",
        "at": "@",
        "bar": "|"
    }
    try:
        fnd_key = list(filter(lambda k: substring.startswith(k), convs.keys()))[0]
        return convs[fnd_key],len(fnd_key)
    except IndexError:
         return substring[0], 1

# See https://github.com/nim-lang compiler/ccgutils.nim:mangle
def demangle_name(name):
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

class NimName():
    def __init__(self, namestr):
        m = re.fullmatch(r'@?([a-zA-Z0-9_]+_?)__(.*)(_u[0-9]+)(_[0-9]+)?(@[0-9]+)?', namestr)
        if m is None or len(m.group(1)) <= 1:
            raise ValueError("Invalid NIM name \"{}\"".format(namestr))
        self.fnname = demangle_name(m.group(1))
        self.pkgname = demangle_module(m.group(2))
        self.suffix = m.group(3)[1:]
        self.ida_suffix = m.group(4)
        self.num_args = m.group(5)

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
        if suffix & SUF_NIM:
            name = "{}_{}".format(name, self.suffix)
        if suffix & SUF_IDA:
            name = "{}_{}".format(name, self.ida_suffix)
        if self.num_args is not None and len(self.num_args) > 0:
            name = "@{}{}".format(name, self.num_args)
        return name

    def is_std_function(self):
        return any([self.pkgname.startswith(std) for std in NIM_STD])

    def is_nimble_function(self):
        return os.path.isabs(self.pkgname) and "/.nimble/" in self.pkgname

    def __repr__(self):
        return "{}::{}  {}".format(self.pkgname, self.fnname, self.suffix)

if __name__ == "__main__":
    name = sys.argv[1]
    try:
        demangled = NimName(name)
        print(demangled)
    except ValueError:
        print(name)
        exit(1)
