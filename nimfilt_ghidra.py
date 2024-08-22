# -*- coding: utf-8 -*-
## ###
# Copyright (c) 2024 ESET
# Author: Alexandre Côté Cyr <alexandre.cote@eset.com>
# See LICENSE file for redistribution.
##
# Helps with reversing Nim compiled executables
# @authors Alexandre Côté Cyr, Alexandre Lavoie
# @category Nimfilt

## Imports

import re
import nimfilt

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StructureDataType, IntegerDataType, StringDataType, CategoryPath, PointerDataType, LongDataType

## Config

NAMESPACE_NAME = "Nim"
CATEGORY_PATH = "/Nim"
SOURCE_TYPE = SourceType.ANALYSIS

## Code

STRING_PREFIX = "ns_"
STRING_INVALID_RE = re.compile(r"[\s]")

def build_string_name(stri):
    """
    Converts a string to a string name.

    :type stri: str

    :rtype: str
    """

    return STRING_PREFIX + STRING_INVALID_RE.sub("_", stri)

def read_cstring(memory, address):
    """
    Reads a null terminated string at address from memory.

    :type memory: ghidra.program.model.mem.Memory
    :type address: ghidra.program.model.address.Address

    :rtype: str
    """

    buffer = []

    next_address = address
    while True:
        bt = memory.getByte(next_address)
        if bt == 0:
            break
        buffer.append(bt)
        next_address = next_address.add(1)

    return "".join(chr(c) for c in buffer)

def build_TGenericSeq(category):
    """
    Builds TGenericSeq.

    Strings, lib/system.nim
        TGenericSeq {
            int len;
            int reserved;
        }

    :type category: ghidra.program.model.symbol.Category
    
    :rtype: ghidra.program.model.data.DataType
    """

    struct_name = "TGenericSeq"

    data_type = category.getDataType(struct_name)
    if data_type:
        return data_type

    int32_t = IntegerDataType()

    data_type = StructureDataType(category.getCategoryPath(), struct_name, 0)
    data_type.add(int32_t, 4, "len", None)
    data_type.add(int32_t, 4, "reserved", None)

    return category.addDataType(data_type, None)

def build_NimStringDesc(category, length):
    """
    Builds a NimStringDesc of a specific length.

    Strings, lib/system.nim
        NimStringDesc {
            TGenericSeq Sup;
            char data[len+1];
        }

    :type category: ghidra.program.model.symbol.Category
    :type length: int
    
    :rtype: ghidra.program.model.data.DataType
    """

    struct_name = "NimStringDesc" + str(length)

    data_type = category.getDataType(struct_name)
    if data_type:
        return data_type

    TGenericSeq = build_TGenericSeq(category)

    data_type = StructureDataType(category.getCategoryPath(), struct_name, 0)
    data_type.add(TGenericSeq, TGenericSeq.getLength(), "Sup", None)
    data_type.add(StringDataType(), length + 1, "data", None)

    return category.addDataType(data_type, None)

def build_NimString(category):
    """
    Builds NimString.

    StringV2, lib/system/strs_v2.nim
        NimString {
            int len;
            NimStrPayload* p;
        }
    """

    struct_name = "NimString"

    data_type = category.getDataType(struct_name)
    if data_type:
        return data_type

    int64_t = LongDataType()
    pointer_t = PointerDataType()

    data_type = StructureDataType(category.getCategoryPath(), struct_name, 0)
    data_type.add(int64_t, 8, "len", None)
    data_type.add(pointer_t, 8, "p", None) # Generic pointer

    return category.addDataType(data_type, None)

def parse_nim_functions(program):
    """
    Parses all functions in the current program with Nim mangled names.

    :type program: ghidra.program.model.listing.Program

    :rtype: Generator[Tuple[ghidra.program.model.listing.Function, str], None, None]
    """

    listing = program.getListing()

    for function in listing.getFunctions(True):
        name = str(function.getName())
        try:
            nim_name = nimfilt.NimNameCreator(name)
            yield function, nim_name
        except ValueError:
            pass

def parse_nim_symbols(program):
    """
    Parses all symbols in the current program with Nim mangled names.

    :type program: ghidra.program.model.listing.Program

    :rtype: Generator[Tuple[ghidra.program.model.symbol.Symbol, str], None, None]
    """

    symbol_table = program.getSymbolTable()

    for sym in symbol_table.getAllSymbols(True):
        name = str(sym.getName())
        if name.startswith("PTR_") or name.startswith("Elf64_"):
            continue

        try:
            nimname = nimfilt.NimNameCreator(name)
            yield sym, nimname
        except ValueError:
            pass

def update_string_descs(program, category, namespace):
    """
    Creates NimStringDescs.

    :type program: ghidra.program.model.listing.Program
    :type category: ghidra.program.model.symbol.Category
    :type namespace: ghidra.program.model.symbol.Namespace

    :rtype: None
    """

    symbol_table = program.getSymbolTable()

    listing = program.getListing()

    memory = program.getMemory()
    valid_address_set = memory.getAllInitializedAddressSet()

    for symbol in symbol_table.getAllSymbols(True):
        symbol_addr = symbol.getAddress()
        if not valid_address_set.contains(symbol_addr, symbol_addr.add(8)):
            continue

        length = memory.getInt(symbol_addr)
        if length < 0:
            continue

        stri_end = symbol_addr.add(8 + length + 1)
        if not valid_address_set.contains(stri_end):
            continue

        if memory.getByte(stri_end) != 0:
            continue

        reserved = memory.getInt(symbol_addr.add(4))
        if reserved != 0x40000000:
            continue

        stri = read_cstring(memory, symbol_addr.add(8))

        symbol.setName(build_string_name(stri), SOURCE_TYPE)
        symbol.setNamespace(namespace)

        data_type = build_NimStringDesc(category, length)

        listing.clearCodeUnits(symbol_addr, symbol_addr.add(data_type.getLength()), True)
        listing.createData(symbol_addr, data_type)

def update_strings(program, category, namespace):
    """
    Creates NimStrings.

    Depends onf update_string_defs.

    :type program: ghidra.program.model.listing.Program
    :type category: ghidra.program.model.symbol.Category
    :type namespace: ghidra.program.model.symbol.Namespace

    :rtype: None
    """

    symbol_table = program.getSymbolTable()

    listing = program.getListing()

    memory = program.getMemory()
    valid_address_set = memory.getAllInitializedAddressSet()

    base_address = valid_address_set.getMinAddress() 

    for symbol in symbol_table.getAllSymbols(True):
        symbol_addr = symbol.getAddress()
        if not valid_address_set.contains(symbol_addr, symbol_addr.add(16)):
            continue

        length = memory.getLong(symbol_addr)
        if length < 0:
            continue

        if length > memory.getSize():
            continue

        pointer = memory.getLong(symbol_addr.add(8))
        if pointer <= 0:
            continue

        if pointer > memory.getSize():
            continue

        pointer_addr = base_address.add(pointer)

        for pointer_symbol in symbol_table.getSymbols(pointer_addr):
            pointer_symbol_name = str(pointer_symbol.getName())

            if not pointer_symbol_name.startswith(STRING_PREFIX):
                continue

            symbol.setName("ptr_" + pointer_symbol_name, SOURCE_TYPE)
            symbol.setNamespace(namespace)

            data_type = build_NimString(category)

            listing.clearCodeUnits(symbol_addr, symbol_addr.add(data_type.getLength()), True)
            listing.createData(symbol_addr, data_type)

            break

def nim_package(program, namespace, pkg_name):
    """
    Gets the namespace package for the package name.

    :type program: ghidra.program.model.listing.Program
    :type namespace: ghidra.program.model.symbol.Namespace
    :type pkg_name: str

    :rtype: ghidra.program.model.symbol.Namespace
    """

    symbol_table = program.getSymbolTable()

    if not pkg_name or pkg_name[0] == "\x00":
        return namespace

    if pkg_name.startswith("../"):
        idx = pkg_name.find("/nim/")

        if idx > 0:
            pkg_name = pkg_name[idx+5:]

    pkg_namespace = namespace
    for section in pkg_name.split("/"):
        pkg_namespace = symbol_table.getOrCreateNameSpace(pkg_namespace, section, SOURCE_TYPE)

    return pkg_namespace

def update_function(program, namespace, function, nim_name):
    """
    Updates a function definition.

    :type program: ghidra.program.model.listing.Program
    :type namespace: ghidra.program.model.symbol.Namespace
    :type function: ghidra.program.model.listing.Function
    :type nim_name: nimfilt.NimName
    
    :rtype: None
    """

    pkg = nim_package(program, namespace, nim_name.pkgname)

    function.setParentNamespace(pkg)
    function.setName(nim_name.fnname, SOURCE_TYPE)

def update_symbol(program, namespace, symbol, nim_name):
    """
    Updates a symbol definition.

    :type program: ghidra.program.model.listing.Program
    :type namespace: ghidra.program.model.symbol.Namespace
    :type symbol: ghidra.program.model.symbol.Symbol
    :type nim_name: nimfilt.NimName
    
    :rtype: None
    """

    pkg = nim_package(program, namespace, nim_name.pkgname)

    symbol.setNamespace(pkg)
    symbol.setName(nim_name.fnname, SOURCE_TYPE)

def update_nim_functions(program, namespace):
    """
    Update Nim function definitions.

    :type program: ghidra.program.model.listing.Program
    :type namespace: ghidra.program.model.symbol.Namespace

    :rtype: None
    """

    symbol_table = program.getSymbolTable()
    listing = program.getListing()

    for name in nimfilt.NIM_FUNC_NAMES:
        strip_name = name[3:]

        for sym in symbol_table.getSymbols(name, None):
            func = listing.getFunctionAt(sym.getAddress())
            if not func: 
                continue

            func.setParentNamespace(namespace)
            func.setName(strip_name, SOURCE_TYPE)

def demangle(program, category, namespace):
    """
    Runs demangling on program.

    :type program: ghidra.program.model.listing.Program
    :type category: ghidra.program.model.symbol.Category
    :type namespace: ghidra.program.model.symbol.Namespace

    :rtype: None
    """

    update_nim_functions(program, namespace)

    for function, nim_name in parse_nim_functions(program):
        update_function(program, namespace, function, nim_name)

    update_string_descs(program, category, namespace)
    update_strings(program, category, namespace)

    for symbol, nim_name in parse_nim_symbols(program):
        update_symbol(program, namespace, symbol, nim_name)

def main(program):
    """
    Entrypoint of script.

    :type program: ghidra.program.model.listing.Program

    :rtype: None
    """

    symbol_table = program.getSymbolTable()

    namespace = symbol_table.getNamespace(NAMESPACE_NAME, None)
    if not namespace:
        namespace = symbol_table.createNameSpace(None, NAMESPACE_NAME, SOURCE_TYPE)

    dtm = program.getDataTypeManager()

    category_path = CategoryPath(CATEGORY_PATH)
    category = dtm.getCategory(category_path)
    if not category:
        category = dtm.createCategory(category_path)

    demangle(program, category, namespace)

if __name__ == "__main__":
    main(currentProgram)
