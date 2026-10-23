# Rudy BPF Atlas rule catalogue

Findings are observations about the supplied object. They are not a verdict about what a particular kernel will accept or what the program will do at runtime.

| ID | Default level | Meaning |
| --- | --- | --- |
| `BPF-INSN-001` | error | Executable section length is not a whole number of 8-byte instruction slots. |
| `BPF-INSN-002` | error | An instruction references a register outside r0-r10. |
| `BPF-INSN-003` | error | A 64-bit immediate instruction is missing or has a malformed continuation slot. |
| `BPF-CFG-001` | error | A jump or program-local call target falls outside its section. |
| `BPF-CFG-002` | warning | A backward edge exists. This does not prove an unbounded loop. |
| `BPF-CFG-003` | error | A control-flow edge targets the continuation half of a 64-bit immediate instruction. |
| `BPF-STACK-001` | error | A direct r10-relative memory access is outside the 512-byte frame. |
| `BPF-HELPER-001` | warning | Helper ID 36 (`bpf_probe_write_user`) is present. Review need and scope. |
| `BPF-HELPER-002` | warning | Helper ID 58 (`bpf_override_return`) is present. Review attachment scope and effect. |
| `BPF-PROG-001` | warning | Executable section name does not match a recognized libbpf section convention. |
| `BPF-PROG-002` | error | No executable BPF program section was found. |
| `BPF-PROG-003` | warning | Executable sections exist, but none use a recognized program-section name. |
| `BPF-BTF-001` | error | BTF header or type/string area is structurally invalid. |
| `BPF-BTF-002` | warning | BTF contains a type kind not understood by this version. |
| `BPF-CORE-001` | error | BTF.ext CO-RE relocation metadata is malformed or out of bounds. |
| `BPF-REL-001` | warning | Relocation type is not in the standard BPF relocation set known to this version. |
| `BPF-REL-002` | warning | A local-call relocation target does not resolve to a defined function in an executable section. |
| `BPF-REL-003` | error | Instruction relocation is misaligned or points to the wrong instruction form. |
| `BPF-LIC-001` | warning | No readable license section exists. |
| `BPF-LIC-002` | note | License string is not one of the common GPL-compatible strings; helper eligibility remains target-dependent. |
| `BPF-SCOPE-001` | note | Static-analysis limits that apply to every report. |

Malformed ELF table layouts, invalid links, unsafe offsets, and truncated input stop analysis with an error message and exit code 2 instead of producing partial findings from untrusted ranges.

## Interpretation notes

- Instruction indexes count both halves of `ldimm64`, matching kernel instruction offsets.
- Helper names are a small convenience catalogue. Unknown helper IDs remain visible as `bpf_helper_id_N`.
- Map names come from ELF relocations that resolve to `.maps` symbols. This is not a complete semantic reconstruction of libbpf map declarations.
- CO-RE reporting counts well-formed records but does not apply relocations or check them against a target BTF database.
- Stack findings cover direct frame-pointer-relative load/store instructions. They are not a full data-flow or verifier analysis.
