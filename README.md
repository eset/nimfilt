# Nimfilt

This is a module to help with analyzing Nim executables. The main `nimfilt.py` script can be run directly to demangle Nim function and module names (à la `c++filt`, hence the name).

Also provided is `nimimfilt_ida.py`, an IDApython script.

## Context

Nim uses its own name mangling scheme distinct from C++'s. As far as I can tell, this scheme isn't documented so I relied on the source code of the [Nim compiler](https://github.com/nim-lang/Nim). Most of this name mangling in implemented in `compiler/msgs.nim` and `compiler/ccgtypes.nim`.

## IDA Script

Copy `nimfilt.py` to your IDAPython directory and run `nimfilt_ida.py` as a script file.

Current features include:

 - Demangling Nim function and package names
 - Organizing functions into directories by package
 - Identifying and properly typing Nim strings

## TODO/Known issues

 - [ ] Handle double mangling (C++ and Nim) for executables compiled with `cpp`
 - [ ] Simplify module paths
 - [ ] IDA Script: Format `Init` function' module paths to match regular function format
 - [ ] IDA Script: Group packages under root-level directories: Nimble, STD and local/main
 - [ ] IDA Script: Use simplified pkg name when renaming functions
