# Input format and parser contract

Rudy BPF Atlas accepts one local ELF relocatable object at a time. It currently requires:

- ELF class 64-bit (`ELFCLASS64`)
- little-endian data encoding (`ELFDATA2LSB`)
- relocatable file type (`ET_REL`)
- BPF machine (`EM_BPF`, 247)
- section headers, including a valid section-name string table

ELF extended section counts and extended section-name table indexes are read from section header zero. The parser checks table multiplication, file ranges, string termination, symbol links, relocation links, BTF type/string areas, and CO-RE record lengths before reading them. Input size defaults to a 256 MiB maximum.

The parser intentionally does not support ELF32, big-endian ELF, executables/shared objects, non-BPF machine types, stripped section tables, or compressed sections. Unsupported formats fail explicitly; they are not silently treated as valid.

## eBPF instruction observations

Instructions are decoded as 8-byte slots. `ldimm64` consumes two slots. Jump and local-call targets are checked against the executable section, and direct frame-pointer memory accesses are checked against the 512-byte frame. The analyzer does not emulate the BPF virtual machine and does not prove register types, pointer provenance, packet bounds, helper argument validity, loop bounds, or verifier acceptance.

Program output includes function symbols in each executable section and local-call symbol names directly referenced by `R_BPF_64_32` relocations. It does not resolve a transitive call graph or map subprograms packed into `.text` back to a specific entry point.

## BTF and BTF.ext

The supported subset checks BTF header and type record sizes for standard kinds and counts types. It validates the BTF string area and the BTF.ext CO-RE relocation record layout. It does not decode every type into a human-readable schema, validate CO-RE access strings semantically, or resolve types against a kernel's BTF.

## Reports

Text is intended for interactive review. JSON is a versioned machine-readable report with stable field names. SARIF 2.1.0 is intended for code-scanning ingestion; findings use artifact-level locations and report section/instruction details in properties because instruction offsets are not source line numbers.
