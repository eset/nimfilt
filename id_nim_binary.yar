/* Copyright (c) 2024 ESET
   Author: Alexandre Côté Cyr <alexandre.cote@eset.com>
   See LICENSE file for redistribution.
*/

import "pe"
import "elf"

private rule has_Nim_strings {
	meta:
		description = "Detects common strings left in Nim compiled executables."
		author = "Alexandre Côté Cyr"
		date = "2024-03-06"
		license = "BSD 2-Clause"
        version = "1"
	strings:
		$error0 = "@value out of range" ascii wide
		$error1 = "@division by zero" ascii wide
		$error2 = "@over- or underflow" ascii wide
		$error3 = "@index out of bounds" ascii wide
		$fatal0 = "fatal.nim" ascii wide
		$fatal1 = "sysFatal" ascii wide
	condition:
		all of ($fatal*) or 2 of ($error*)
}

rule identify_Nim_PE {
     meta:
        description = "Detects Nim compiled PE files."
        author = "Alexandre Côté Cyr"
        date = "2024-03-06"
		license = "BSD 2-Clause"
        version = "1"
    strings:
		$NimMain = "NimMain"
		$PreMainInner = "PreMainInner"
    condition:
		pe.is_pe and (has_Nim_strings or pe.exports(/NimMain/) or
		(pe.number_of_symbols != 0 and (
			// A Nim function name appears in the symbol table
			$NimMain in (pe.pointer_to_symbol_table..pe.pointer_to_symbol_table + pe.number_of_symbols * 0x18) or
			$PreMainInner in (pe.pointer_to_symbol_table..pe.pointer_to_symbol_table + pe.number_of_symbols * 0x18)
		)))
}

rule identify_Nim_ELF {
     meta:
        description = "Detects Nim compiled ELF files."
        author = "Alexandre Côté Cyr"
        date = "2024-03-06"
		license = "BSD 2-Clause"
        version = "1"
    condition:
		uint32(0) == 0x464c457f and (has_Nim_strings or
			(elf.symtab_entries != 0 and (
				// A Nim function name appears in the symbol table
				for any sym in elf.symtab: (
					(sym.type == elf.STT_FILE and sym.name endswith ".nim") or
					(sym.type == elf.STT_FUNC and (sym.name contains "NimMain" or sym.name == "PreMainInner"))
				)
			))
		)
}
