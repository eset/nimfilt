# -*- encoding: utf8 -*-
#
# Copyright (c) 2024 ESET
# Author: Alexandre Côté Cyr <alexandre.cote@eset.com>
# See LICENSE file for redistribution.

import nimfilt
import posixpath

import ida_auto
import ida_bytes
import ida_dirtree
import ida_funcs
import ida_nalt
import ida_name
import ida_segment
import ida_struct
import ida_xref
import idaapi
import idautils

from ida_idp import ph_get_cnbits
from ida_ida import inf_get_app_bitness, inf_is_be
from collections import namedtuple

AUTO_RUN = False

PLUGIN_NAME = "Nimfilt"
VERSION = "1.0.0"

ST_NIMSTRING = 1
ST_NIMSTRING_PTR = 2

# These global variables can only be calculated after IDA has loaded the program
BITNESS = None
INT_BYTES = None
ENDIANNESS = None
# Flag that marks a string object as a string literal
NIM_STRLIT_FLAG = None

PROGRAM_END = None

def init_globals():
    global PROGRAM_END, BITNESS, INT_BYTES, ENDIANNESS, NIM_STRLIT_FLAG
    PROGRAM_END = ida_segment.get_last_seg().end_ea
    BITNESS = inf_get_app_bitness()
    INT_BYTES = BITNESS // ph_get_cnbits()
    ENDIANNESS = "big" if inf_is_be() else "little"
    # lib/nimbase.h: 1 << (sizeof(int) * CHAR_BITS - 2)
    # Nim's int type is 64bit on 64 bit architectures
    NIM_STRLIT_FLAG = 1 << (BITNESS - 2)

def get_uint(ea):
    bts = idaapi.get_bytes(ea, INT_BYTES, 0)
    return int.from_bytes(bts, ENDIANNESS, signed=False)

# bin_search is significantly faster than ida_search.find_text
# Unlike find_text, it also matches data that isn't typed as a string
def find_text(string: str):
    pattern = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(pattern, 0, '"{}"'.format(string), 0, ida_nalt.STRENC_DEFAULT)  # Strings must be inside double quotes
    return ida_bytes.bin_search3(0, ida_segment.get_last_seg().end_ea, pattern, idaapi.BIN_SEARCH_FORWARD)

class Nimfilt_plugin(idaapi.plugin_t):
    comment = ""
    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_FIX
    help = "Helps with reversing Nim compiled executables"
    wanted_hotkey = ""
    wanted_name = PLUGIN_NAME

    def init(self):
        idaapi.notify_when(idaapi.NW_OPENIDB, self._idb_loaded_handler)
        return idaapi.PLUGIN_KEEP

    # Check if the database is Nim and run if AUTO_RUN is on
    def _idb_loaded_handler(self, _, is_old_database):
        if is_nim_idb():
            print("IDB identified as Nim.")
            if not is_old_database and AUTO_RUN:
                print("Running Nimfilt.")
                self.run()
        else:
            print("IDB could not be confirmed as Nim. You can still run the plugin manually")

    def run(self, arg):
        main()

    def term(self):
        pass

def iterate_segments():
    seg = ida_segment.get_first_seg()
    while seg is not None:
        yield seg
        seg = ida_segment.get_next_seg(seg.start_ea)

def make_nim_strings():
    for seg in iterate_segments():
        if ida_segment.get_segm_name(seg) in [".rdata", ".rodata"] or (seg.type == ida_segment.SEG_DATA and seg.perm == ida_segment.SEGPERM_READ):
            ea = seg.start_ea
            while ea < seg.end_ea:
                # Skip if the address is already typed as a struct
                if not ida_bytes.is_struct(ida_bytes.get_flags(ea)) and (is_str := is_nim_str(ea)):
                    if is_str[0] == ST_NIMSTRING:
                        ea += apply_Nim_string_struct(*is_str[1:])
                    elif is_str[0] == ST_NIMSTRING_PTR:
                        ea += apply_Nim_string_ptr_struct(*is_str[1:])
                    else:
                        raise Exception()
                else:
                    ea += 1

# String is NUL terminated and contains only valid ascii non-NUL characters
# TODO: check encodings
def _is_valid_C_str(s: bytes):
    return s[-1] == 0x00 and all([x in range(0x01, 0x80) for x in s[:-1]])

def is_nim_str_payload(ea, ln):
    reserved = get_uint(ea)
    if reserved ^ NIM_STRLIT_FLAG in [0, ln] and ea + ln <= PROGRAM_END:
        return _is_valid_C_str(ida_bytes.get_bytes(ea + INT_BYTES, ln + 1))
    return False

# lib/system/strs_v2.nim -> NimStringV2
def is_nim_str(ea):
    ln = get_uint(ea)
    # Contiguous block string
    if ln > 0:
        if is_nim_str_payload(ea + INT_BYTES, ln):
            return (ST_NIMSTRING, ea, ln)
        elif (addr := ida_xref.get_first_dref_from(ea + INT_BYTES)) != idaapi.BADADDR and is_nim_str_payload(addr, ln):
            return (ST_NIMSTRING_PTR, ea, addr, ln)
    return False

"""
Depending on the Nim version, strings can be represented one of a few ways:
StringV2, lib/system/strs_v2.nim
    NimStrPayload {
        int cap;
        char data[len+1];
    }
    NimString {
        int len;
        NimStrPayload* p;
    }

Strings, lib/system.nim
    TGenericSeq { //Generic sequence type
        int len;
        int reserved;
    }
    NimStringDesc {
        TGenericSeq Sup;
        char data[len+1];
    }

For string literals, the value of cap/reserved is ORed with NIM_STRLIT_FLAG
reserved appears to be the same as cap
"""
StructMember = namedtuple("StructMember", "name, flag, member_type, size")
def create_Nim_string_structs():
    INT_TYPES = {1: ida_bytes.FF_BYTE, 2: ida_bytes.FF_WORD, 4: ida_bytes.FF_DWORD, 8: ida_bytes.FF_QWORD, 16: ida_bytes.FF_OWORD}
    str_opinfo = ida_nalt.opinfo_t()
    str_opinfo.strtype = ida_nalt.STRTYPE_TERMCHR
    if (nsc_struct_id := ida_struct.get_struc_id("NimStrPayload")) == idaapi.BADADDR:
        NimStrPayload = [
            StructMember("reserved", INT_TYPES[INT_BYTES] | ida_bytes.FF_DATA, None, INT_BYTES),
            StructMember("str", ida_bytes.FF_STRLIT, str_opinfo, 0)
        ]
        nsc_struct = create_IDA_struct("NimStrPayload", NimStrPayload)
        nsc_struct_id = nsc_struct.id
    # For structs or pointers to structs, the mt argument must be a opinfo_t struct with the tid field set to the structure's id
    nimstringcontent_opinfo = ida_nalt.opinfo_t()
    nimstringcontent_opinfo.tid = nsc_struct_id
    structs = {}
    if ida_struct.get_struc_id("NimString") == idaapi.BADADDR:
        structs["NimString"] = [
            StructMember("length", INT_TYPES[INT_BYTES] | ida_bytes.FF_DATA, None, INT_BYTES),
            StructMember("content", ida_bytes.FF_STRUCT | ida_bytes.FF_DATA, nimstringcontent_opinfo, INT_BYTES)  # Flags for structs
        ]
    if ida_struct.get_struc_id("NimStringPtr") == idaapi.BADADDR:
        structs["NimStringPtr"] = [
            StructMember("length", INT_TYPES[INT_BYTES] | ida_bytes.FF_DATA, None, 4),
            StructMember("content", INT_TYPES[INT_BYTES] | ida_bytes.FF_0OFF | ida_bytes.FF_1OFF | ida_bytes.FF_DATA, nimstringcontent_opinfo, 4)  # Flags for 32 bit pointers
        ]
    for name, members in structs.items():
        create_IDA_struct(name, members)

def create_IDA_struct(name: str, members: list):
    struct_id = ida_struct.add_struc(-1, name, False)
    struct = ida_struct.get_struc(struct_id)
    for field in members:
        field = field._asdict()
        ida_struct.add_struc_member(struct, field["name"], -1, field["flag"], field["member_type"], field["size"])
    return struct

def apply_Nim_string_struct(start_addr, length):
    struct_id = ida_struct.get_struc_id("NimString")
    size = ida_struct.get_struc_size(struct_id) + length
    ida_bytes.create_struct(start_addr, size, struct_id, True)
    content = ida_bytes.get_bytes(start_addr + 2 * INT_BYTES, length)
    ida_name.set_name(start_addr, str_to_name(content), ida_name.SN_AUTO | ida_name.SN_IDBENC | ida_name.SN_PUBLIC | ida_name.SN_FORCE)
    return size

def apply_Nim_string_ptr_struct(start_addr, content_addr, length):
    ptr_struct_id = ida_struct.get_struc_id("NimStringPtr")
    content_struct_id = ida_struct.get_struc_id("NimStrPayload")
    ida_bytes.create_struct(start_addr, ida_struct.get_struc_size(ptr_struct_id), ptr_struct_id, True)
    size = ida_struct.get_struc_size(content_struct_id) + length
    ida_bytes.create_struct(content_addr, size, content_struct_id, True)
    content = ida_bytes.get_bytes(content_addr + INT_BYTES, length)
    name = str_to_name(content)
    ida_name.set_name(content_addr, name, ida_name.SN_AUTO | ida_name.SN_IDBENC | ida_name.SN_PUBLIC | ida_name.SN_FORCE)
    name = ida_name.get_name(content_addr)  # Get final name in case IDA auto-added a suffix
    ida_name.set_name(start_addr, "ptr_{:s}".format(name), ida_name.SN_AUTO | ida_name.SN_IDBENC | ida_name.SN_PUBLIC | ida_name.SN_FORCE)
    return ida_struct.get_struc_size(ptr_struct_id)

# Returns a name like IDA's default names for string using s as a prefix instead of a
# TODO: handle strings that contain only special characters
def str_to_name(string):
    try:
        default_encoding = ida_nalt.get_encoding_name(ida_nalt.get_default_encoding_idx(1))
        string = string.decode(default_encoding)
    except AttributeError:
        pass
    cleaned = ida_name.validate_name(string, ida_name.NT_LOCAL, ida_name.SN_IDBENC).title().replace("_", "")
    return "s{:s}".format(cleaned[:0xE])

# Parse all functions in the current IDB for ones that have nim mangled names
def parse_nim_functions():
    for i in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(i)
        name = ida_funcs.get_func_name(func.start_ea)
        try:
            niname = nimfilt.NimNameCreator(name)
            yield func.start_ea, niname
        except ValueError:
            pass

# Rename function. Use mangler generated suffix if there is a duplicate
def rename(ea, nname: nimfilt.NimName):
    name = nname.get_ida_name()
    if ida_name.get_name_ea(0, name) != idaapi.BADADDR:
        name = nname.get_ida_name(suffix=nimfilt.SUF_NIM)
        if ida_name.get_name_ea(0, name) != idaapi.BADADDR:
            name = nname.get_ida_name(suffix=nimfilt.SUF_NIM | nimfilt.SUF_IDA)
    ida_name.set_name(ea, name, ida_name.SN_FORCE)
    return name

# Recursively merge directories that only have a single child that's also a directory
def merge_dir(dirtree: ida_dirtree.dirtree_t, path=""):
    iterator = ida_dirtree.dirtree_iterator_t()
    ok = dirtree.findfirst(iterator, "{}/*".format(path))
    has_fn = False

    # Moving and deleting directories messes with the iterator so we list all the children first
    children = []
    while ok:
        child_path = dirtree.get_abspath(iterator.cursor)
        children.append(child_path)
        ok = dirtree.findnext(iterator)

    new_children = []
    for child_path in children:
        if child_path.endswith("/.."):  # Avoid infinite recursion
            continue
        if dirtree.isdir(child_path):
            child_path = merge_dir(dirtree, child_path)
        else:
            has_fn = True
        new_children.append(child_path)
    if len(children) == 1 and not has_fn:
        # Ida uses POSIX-like path so we use the \\ as an internal separator in directory names
        new_path = "{}\\{}".format(path, posixpath.basename(child_path))
        dirtree.rename(child_path, new_path)
        dirtree.rmdir(path)
        return new_path
    return path

# Returns True if the function at ea has a name that matches known Nim functions
def _nim_func_filter(ea):
    NIM_FUNC_NAMES = ["NimMain", "NimMainInner", "NimMainModule"]
    name = ida_funcs.get_name(ea)
    return any(filter(lambda known_name: known_name in name, NIM_FUNC_NAMES))

# Use simple heuristics to see if the currently open program is Nim
def is_nim_idb():
    # Based on our tests, these strings are present in all Nim binaries even if they are stripped. However, it would be trivial for a threat actor to remove them
    if find_text("fatal.nim") != idaapi.BADADDR and find_text("sysFatal") != idaapi.BADADDR:
        return True
    # Function names
    if any(filter(_nim_func_filter, idautils.Functions())):
        return True
    # Other strings
    # Must contain at least 2 of those
    ERR_MSG = ["@value out of range", "@division by zero", "@over- or underflow", "@index out of bounds"]
    matches = 0
    for s in ERR_MSG:
        if find_text(s) != idaapi.BADDADDR:
            matches += 1
            if matches >= 2:
                return True
    return False

# TODO: create separate root level directories for Stdlib, project and nimble packages
# Rename functions and move them to subdirectories based on the package path/name
def main():
    ida_auto.auto_wait()
    init_globals()
    func_dirtree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    for ea, nname in parse_nim_functions():
        name = rename(ea, nname)
        func_dirtree.mkdir(nname.ida_dirname)
        func_dirtree.rename(name, "{}/{}".format(nname.ida_dirname, name))
    merge_dir(func_dirtree)
    create_Nim_string_structs()
    make_nim_strings()

if __name__ == "__main__":
    main()

def PLUGIN_ENTRY():
    return Nimfilt_plugin()
