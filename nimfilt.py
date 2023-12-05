#!/bin/env python3
import sys
import string
import re
from binascii import unhexlify

NIM_STD = ["system", "pure", "impure", "std", "windows"]
# TODO check non-windows "wrappers"

# adapted from clean_function_name in https://github.com/SentineLabs/AlphaGolang/blob/main/2.function_discovery_and_renaming.py
def _clean_name_ida(name):
    STRIP_CHARS = r'[()\[\]{} "]'
    REPLACE_CHARS = r'[.*\-,;:/\\]'
    name = re.sub(STRIP_CHARS, "", name)
    name = re.sub("=", "EQ", name)
    name = re.sub("-", "MINUS", name)
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

def __specialchar(substring):
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
            v,l = __specialchar(name[i:])
            i += l
            plain = plain + v
        else:
            plain = plain + name[i]
            i += 1

    return plain

class NimName():
    def __init__(self, namestr):
        m = re.fullmatch(r'@?([a-zA-Z0-9]+_?)__(.*)(_[0-9]+)(@[0-9]+)?', namestr)
        if m is None:
            raise ValueError("Invalid NIM name \"{}\"".format(namestr))
        self.fnname = demangle_name(m.group(1))
        self.pkgname = demangle_module(m.group(2))
        self.suffix = m.group(3)[1:]
        self.num_args = m.group(4)

    @property
    def _clean_pkgname(self):
        return _clean_name_ida(self.pkgname)

    @property
    def _clean_fnname(self):
        return _clean_name_ida(self.fnname)

    @property
    def clean_name(self):
        return "{}::{}".format(self._clean_pkgname, self._clean_fnname)

    @property
    def ida_name(self):
        if len(self.num_args) > 0:
            return("@{}{}".format(self.clean_name, self.num_args))
        else:
            return self.clean_name

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
