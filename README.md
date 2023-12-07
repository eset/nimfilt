# Nimfilt

This is a module to parse and demangle names in Nim executables.

## Context

Nim uses its own name mangling scheme distinct from C++'s. As far as I can tell, this scheme isn't documented so I relied on the source code of the [Nim compiler](https://github.com/nim-lang/Nim). Most of this name mangling in implemented in `compiler/msgs.nim` and `compiler/ccgtypes.nim`.

## IDA Script

Copy `nimfilt.py` to your IDAPython directory and run `nimfilt_ida.py` as a script file.

## TODO/Known issues

 - [ ] Handle double mangling (C++ and Nim) for executables compiled with `cpp`
 - [ ] Simplify module paths
 - [ ] IDA Script: Make the IDA function view demangle function names that start with `@`
 - [ ] IDA Script: Format `Init` function' module paths to match regular function format
 - [ ] IDA Script: Group packages under root-level directories: Nimble, STD and local/main
 - [ ] IDA Script: Use simplified pkg name when renaming functions
