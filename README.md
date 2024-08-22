# Nimfilt

Nimfilt is a collection of modules and scripts to help with analyzing [Nim](https://github.com/nim-lang/Nim/) binaries. It started out as a CLI demangling tool inspired by `c++filt`. It evolved into a larger set of tools for analyzing Nim, but the original name stuck.

 - `nimfilt.py`: a Python module that implements demangling for Nim. It can also be run as basic CLI tool.
 - `id_nim_binary.yar`: a set of YARA rules to identify Nim ELF and PE binaries.
 - `nimfilt_ida.py`: Nimfilt for IDA, an IDApython script to help reverse-engineers handle Nim binaries.
 - `nimfilt_ghidra.py`: Nimfilt for Ghidra, a GhidraScript to help reverse-engineers handle Nim binaries.


## Context

Nim is compiled to another language (usually C/C++) before being compiled to a native executable. It also doesn't include a large runtime. However, the process still leaves some Nim-specific artefacts and specificites in in the produced binary.

For one, method and module names are mangled using, Nim's own name scheme which is distinct from C++'s. This scheme isn't documented so I relied on the source code of the [Nim compiler](https://github.com/nim-lang/Nim). Most of this name mangling in implemented in `compiler/msgs.nim` and `compiler/ccgtypes.nim`.


## Nimfilt for IDA

The IDAPython script can be run as a one-off or installed as a plugin.

If running as a script, simply launch it from the Nimfilt project directory. It is recommended to do so after auto-analysis has completed and you've loaded any additional FLIRT signatures.

### Plugin setup using [Sark](https://github.com/tmr232/Sark)'s plugin loader

Add `<nimfilt_project_dir>/nimfilt_ida.py` to your your `plugins.list` as per their instruction on [installing plugins](https://sark.readthedocs.io/en/latest/plugins/installation.html).

### Manual plugin setup

1. Copy `nimfilt.py` to a directory that is included in your IDAPython's `PYTHONPATH` (commonly `<IDA_install_dir>/python/` or `%APPDATA%/Hex-Rays/IDA Pro/python/3/`).
2. Copy `nimfilt_ida.py` to your IDAPython plugin directory (usually `<IDA_install_dir>/plugins/`)

### Usage

*Note: The current version of Nimfilt for IDA only supports one command which runs all analyses.*

Navigate to Edit -> Plugins -> Nimfilt and click on it.

You can set Nimfilt to automatically execute when a loaded file is recognized as a Nim binary. To do so, set the `AUTO_RUN` global variable to `True` in `nimfilt_ida.py`


## Nimflit for Ghidra

The GhidraScript is a one-off script.

If running as a script, simply launch it from the Nimfilt project directory. It is recommended to do so after auto-analysis has completed and you've loaded any additional FLIRT signatures.

### Manual pluging setup

Copy `nimfilt.py` and `nimfilt_ghidra.py` to your `ghidra_script` directory (usually `$HOME/ghidra_scripts`)

### Usage

*Note: The current version of Nimfilt for Ghidra only supports one command which runs all analyses.*

Navigate to Window -> Script Manager. Find the `nimfilt_ghidra.py` script in the list. Select it and click the `Run` button.

## Running tests

Nimfilt uses the [unittest](https://docs.python.org/3/library/unittest.html) package from the Python standard library for unit testing. You can run the test suite using the following command: `python -m unittest test/*.py`.


## Features

Current features include:

 - Identifying if a loaded file is a Nim binary.
 - Demangling Nim function and package names.
 - Demangling Nim package init function names.
 - Organizing functions into directories by package.
 - Identifying, typing and renaming Nim strings.


## TODO/Known issues

 - [ ] Handle double mangling (C++ and Nim) for executables compiled with `cpp`
 - [ ] Simplify module paths
 - [ ] IDA Script: Format `Init` function' module paths to match regular function format
 - [ ] IDA Script: Group packages under root-level directories: Nimble, STD and local/main
 - [ ] IDA Script: Use simplified pkg name when renaming functions


## Similar and related work

[AlphaGolang](https://github.com/SentineLabs/AlphaGolang) is a project that fulfills a similar role for Go binaries. While none of AlphaGolang's code was used directly in Nimfilt, it served as a general inspiration and was useful in understanding IDA's folder API.

[Nim-IDA-FLIRT-Generator](https://github.com/Cisco-Talos/Nim-IDA-FLIRT-Generator) is another project that helps with reverse-engineering Nim binaries. It does so by greatly simplifying the process of creating IDA FLIRT signatures for Nim. It nicely complements Nimfilt for binaries that lack symbols: First generate then apply your FLIRT signatures, then run Nimfilt for the best results.
