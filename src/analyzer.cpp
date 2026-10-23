#include "rudy_bpf_atlas/analyzer.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace rudy::bpf_atlas {
namespace {

constexpr std::uint16_t kElfTypeRel = 1;
constexpr std::uint16_t kMachineBpf = 247;
constexpr std::uint32_t kSectionProgBits = 1;
constexpr std::uint32_t kSectionSymtab = 2;
constexpr std::uint32_t kSectionStrtab = 3;
constexpr std::uint32_t kSectionRela = 4;
constexpr std::uint32_t kSectionRel = 9;
constexpr std::uint64_t kFlagExec = 0x4;
constexpr std::uint8_t kBpfClassLdx = 0x01;
constexpr std::uint8_t kBpfClassSt = 0x02;
constexpr std::uint8_t kBpfClassStx = 0x03;
constexpr std::uint8_t kBpfClassJmp = 0x05;
constexpr std::uint8_t kBpfClassJmp32 = 0x06;
constexpr std::uint8_t kBpfModeMem = 0x60;
constexpr std::uint8_t kBpfOpCall = 0x80;
constexpr std::uint8_t kBpfOpExit = 0x90;
constexpr std::uint8_t kBpfSizeMask = 0x18;
constexpr std::uint8_t kBpfSizeB = 0x10;
constexpr std::uint8_t kBpfSizeH = 0x08;
constexpr std::uint8_t kBpfSizeW = 0x00;
constexpr std::uint8_t kBpfSizeDw = 0x18;

[[nodiscard]] bool range_ok(std::uint64_t offset, std::uint64_t length, std::uint64_t total) {
    return offset <= total && length <= total - offset;
}

[[nodiscard]] std::uint64_t checked_add(std::uint64_t a, std::uint64_t b, std::string_view what) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) throw std::runtime_error(std::string(what) + " overflows");
    return a + b;
}

[[nodiscard]] std::uint64_t checked_mul(std::uint64_t a, std::uint64_t b, std::string_view what) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) throw std::runtime_error(std::string(what) + " overflows");
    return a * b;
}

class Bytes {
public:
    explicit Bytes(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes)) {}
    [[nodiscard]] std::uint64_t size() const { return static_cast<std::uint64_t>(bytes_.size()); }
    [[nodiscard]] std::uint8_t u8(std::uint64_t at) const { require(at, 1); return bytes_[static_cast<std::size_t>(at)]; }
    [[nodiscard]] std::uint16_t u16(std::uint64_t at) const {
        require(at, 2);
        return static_cast<std::uint16_t>(u8(at)) | static_cast<std::uint16_t>(static_cast<std::uint16_t>(u8(at + 1)) << 8U);
    }
    [[nodiscard]] std::uint32_t u32(std::uint64_t at) const {
        require(at, 4);
        return static_cast<std::uint32_t>(u8(at)) | (static_cast<std::uint32_t>(u8(at + 1)) << 8U) |
               (static_cast<std::uint32_t>(u8(at + 2)) << 16U) | (static_cast<std::uint32_t>(u8(at + 3)) << 24U);
    }
    [[nodiscard]] std::uint64_t u64(std::uint64_t at) const {
        return static_cast<std::uint64_t>(u32(at)) | (static_cast<std::uint64_t>(u32(at + 4)) << 32U);
    }
    [[nodiscard]] std::string string(std::uint64_t at, std::uint64_t bound, std::string_view what) const {
        if (at >= bound || bound > size()) throw std::runtime_error(std::string(what) + " string offset is out of range");
        std::string out;
        for (auto i = at; i < bound; ++i) {
            const auto c = static_cast<char>(u8(i));
            if (c == '\0') return out;
            out.push_back(c);
        }
        throw std::runtime_error(std::string(what) + " string is not terminated");
    }
    [[nodiscard]] std::vector<std::uint8_t> slice(std::uint64_t at, std::uint64_t length) const {
        require(at, length);
        const auto first = bytes_.begin() + static_cast<std::ptrdiff_t>(at);
        const auto last = first + static_cast<std::ptrdiff_t>(length);
        return {first, last};
    }
private:
    void require(std::uint64_t at, std::uint64_t length) const {
        if (!range_ok(at, length, size())) throw std::runtime_error("truncated or out-of-range binary structure");
    }
    std::vector<std::uint8_t> bytes_;
};

struct Section {
    std::string name;
    std::uint32_t type{};
    std::uint64_t flags{};
    std::uint64_t offset{};
    std::uint64_t size{};
    std::uint32_t link{};
    std::uint32_t info{};
    std::uint64_t entry_size{};
};

struct Symbol { std::string name; std::uint16_t section{}; std::uint64_t value{}; std::uint8_t type{}; };

[[nodiscard]] std::string_view helper_name(std::int32_t id) {
    static const std::map<std::int32_t, std::string_view> names{
        {1,"bpf_map_lookup_elem"},{2,"bpf_map_update_elem"},{3,"bpf_map_delete_elem"},
        {4,"bpf_probe_read"},{5,"bpf_ktime_get_ns"},{6,"bpf_trace_printk"},
        {7,"bpf_get_prandom_u32"},{8,"bpf_get_smp_processor_id"},{9,"bpf_skb_store_bytes"},
        {10,"bpf_l3_csum_replace"},{11,"bpf_l4_csum_replace"},{12,"bpf_tail_call"},
        {14,"bpf_get_current_pid_tgid"},{15,"bpf_get_current_uid_gid"},{16,"bpf_get_current_comm"},
        {25,"bpf_perf_event_output"},{26,"bpf_skb_load_bytes"},{27,"bpf_get_stackid"},
        {36,"bpf_probe_write_user"},{58,"bpf_override_return"},{130,"bpf_probe_read_user"},
        {113,"bpf_probe_read_kernel"},{114,"bpf_probe_read_user_str"},{115,"bpf_probe_read_kernel_str"}
    };
    const auto it = names.find(id);
    return it == names.end() ? std::string_view{} : it->second;
}

[[nodiscard]] std::string classify_program(std::string_view name) {
    const auto slash = name.find('/');
    const auto stem = name.substr(0, slash);
    static constexpr std::array<std::string_view, 30> known{
        "xdp","xdp.frags","xdpgeneric","xdpdrv","xdp_cpumap","xdp_devmap","tc","classifier","action",
        "socket","sockops","sk_lookup","flow_dissector","perf_event","tracepoint","raw_tracepoint",
        "kprobe","kretprobe","fentry","fexit","fmod_ret","freplace","lsm","cgroup_skb","cgroup_sock",
        "cgroup_sock_addr","cgroup_sysctl","sk_skb","sk_msg","iter"
    };
    for (const auto prefix : known) if (stem == prefix) return std::string(stem);
    if (stem == "uprobe" || stem == "uretprobe" || stem == "struct_ops" || stem == "netfilter") return std::string(stem);
    return "unknown";
}

[[nodiscard]] std::uint64_t access_width(std::uint8_t code) {
    switch (code & kBpfSizeMask) {
        case kBpfSizeB: return 1;
        case kBpfSizeH: return 2;
        case kBpfSizeW: return 4;
        case kBpfSizeDw: return 8;
        default: return 0;
    }
}

[[nodiscard]] std::vector<std::uint8_t> load_file(const std::filesystem::path& path, std::uint64_t max_size) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("cannot open input file");
    const auto end = input.tellg();
    if (end < 0) throw std::runtime_error("cannot determine input size");
    const auto size = static_cast<std::uint64_t>(end);
    if (size > max_size) throw std::runtime_error("input exceeds configured maximum size");
    if (size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) throw std::runtime_error("input is too large for this platform");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    input.seekg(0);
    if (!bytes.empty() && !input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) throw std::runtime_error("failed to read input file");
    return bytes;
}

void add(Analysis& out, std::string id, Severity severity, std::string message, std::string section = {}, std::uint64_t instruction = 0) {
    out.findings.push_back({std::move(id), severity, std::move(message), std::move(section), instruction});
}

} // namespace

Analyzer::Analyzer(Options options) : options_(options) {
    if (options_.max_file_size == 0) throw std::invalid_argument("max_file_size must be positive");
}

std::string to_string(Severity severity) {
    switch (severity) {
        case Severity::info: return "note";
        case Severity::warning: return "warning";
        case Severity::error: return "error";
    }
    return "warning";
}

Analysis Analyzer::analyze(const std::filesystem::path& path) const {
    Bytes bytes(load_file(path, options_.max_file_size));
    Analysis out;
    out.input = path;
    out.file_size = bytes.size();
    if (bytes.size() < 64) throw std::runtime_error("file is too small to contain an ELF64 header");
    if (bytes.u8(0) != 0x7f || bytes.u8(1) != 'E' || bytes.u8(2) != 'L' || bytes.u8(3) != 'F') throw std::runtime_error("input is not an ELF file");
    if (bytes.u8(4) != 2) throw std::runtime_error("only ELF64 objects are supported");
    if (bytes.u8(5) != 1) throw std::runtime_error("only little-endian ELF objects are supported");
    if (bytes.u8(6) != 1 || bytes.u32(20) != 1) throw std::runtime_error("unsupported ELF version");
    if (bytes.u16(16) != kElfTypeRel) throw std::runtime_error("expected an ET_REL relocatable object");
    out.machine = bytes.u16(18);
    if (out.machine != kMachineBpf) throw std::runtime_error("ELF machine is not EM_BPF (247)");
    if (bytes.u16(52) < 64) throw std::runtime_error("ELF header declares an invalid header size");
    const auto shoff = bytes.u64(40);
    const auto shentsize = bytes.u16(58);
    auto shnum = static_cast<std::uint64_t>(bytes.u16(60));
    auto shstrndx = static_cast<std::uint64_t>(bytes.u16(62));
    if (shoff == 0 || shentsize < 64 || !range_ok(shoff, shentsize, bytes.size())) throw std::runtime_error("ELF section table is missing or malformed");
    const auto section_zero_size = bytes.u64(shoff + 32);
    if (shnum == 0) shnum = section_zero_size;
    if (shstrndx == 0xffffU) shstrndx = bytes.u32(shoff + 40);
    if (shnum == 0 || shnum > 65536) throw std::runtime_error("ELF section count is invalid or exceeds 65536");
    const auto table_size = checked_mul(shnum, shentsize, "section table size");
    if (!range_ok(shoff, table_size, bytes.size())) throw std::runtime_error("ELF section table exceeds file bounds");
    if (shstrndx >= shnum) throw std::runtime_error("section-name string table index is invalid");

    std::vector<Section> sections;
    sections.reserve(static_cast<std::size_t>(shnum));
    for (std::uint64_t i = 0; i < shnum; ++i) {
        const auto h = shoff + i * shentsize;
        Section s;
        const auto name_offset = bytes.u32(h);
        s.type = bytes.u32(h + 4);
        s.flags = bytes.u64(h + 8);
        s.offset = bytes.u64(h + 24);
        s.size = bytes.u64(h + 32);
        s.link = bytes.u32(h + 40);
        s.info = bytes.u32(h + 44);
        s.entry_size = bytes.u64(h + 56);
        if (s.type != 8 && !range_ok(s.offset, s.size, bytes.size())) throw std::runtime_error("section data exceeds file bounds");
        sections.push_back(std::move(s));
        (void)name_offset;
    }
    const auto& names = sections[static_cast<std::size_t>(shstrndx)];
    if (names.type != kSectionStrtab) throw std::runtime_error("section-name table is not a string table");
    const auto name_end = checked_add(names.offset, names.size, "section-name table end");
    for (std::uint64_t i = 0; i < shnum; ++i) {
        const auto h = shoff + i * shentsize;
        const auto name_offset = bytes.u32(h);
        sections[static_cast<std::size_t>(i)].name = name_offset == 0 ? "" : bytes.string(names.offset + name_offset, name_end, "section name");
    }
    out.section_count = shnum;

    std::unordered_map<std::uint32_t, std::vector<Symbol>> symbol_tables;
    for (std::uint32_t i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i];
        if (s.type != kSectionSymtab && s.type != 11) continue;
        if (s.link >= sections.size()) throw std::runtime_error("symbol table links to an invalid string table");
        const auto& strtab = sections[s.link];
        if (strtab.type != kSectionStrtab || s.entry_size < 24 || s.size % s.entry_size != 0) throw std::runtime_error("symbol table has an invalid layout");
        const auto count = s.size / s.entry_size;
        if (count > 1'000'000) throw std::runtime_error("symbol table exceeds safety limit");
        auto& symbols = symbol_tables[i];
        symbols.reserve(static_cast<std::size_t>(count));
        const auto str_end = strtab.offset + strtab.size;
        for (std::uint64_t j = 0; j < count; ++j) {
            const auto p = s.offset + j * s.entry_size;
            const auto name_off = bytes.u32(p);
            const auto shndx = bytes.u16(p + 6);
            symbols.push_back({name_off == 0 ? "" : bytes.string(strtab.offset + name_off, str_end, "symbol name"), shndx, bytes.u64(p + 8), static_cast<std::uint8_t>(bytes.u8(p + 4) & 0x0fU)});
        }
    }

    std::map<std::uint32_t, std::set<std::string>> maps_by_section;
    std::map<std::uint32_t, std::set<std::string>> calls_by_section;
    std::map<std::uint32_t, std::set<std::uint64_t>> call_relocations;
    std::map<std::uint32_t, std::set<std::string>> functions_by_section;
    for (const auto& [table_index, symbols] : symbol_tables) {
        (void)table_index;
        for (const auto& sym : symbols)
            if (sym.type == 2 && sym.section < sections.size() && !sym.name.empty()) functions_by_section[sym.section].insert(sym.name);
    }
    for (std::uint32_t i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i];
        if (s.name == "license" || s.name == ".license") {
            if (s.size > 0) out.license = bytes.string(s.offset, s.offset + s.size, "license");
        }
        if (s.type != kSectionRel && s.type != kSectionRela) continue;
        if (s.info >= sections.size()) throw std::runtime_error("relocation section has invalid target index");
        const auto sym_it = symbol_tables.find(s.link);
        if (sym_it == symbol_tables.end()) throw std::runtime_error("relocation section links to a missing symbol table");
        const auto minimum = s.type == kSectionRel ? 16ULL : 24ULL;
        if (s.entry_size < minimum || s.size % s.entry_size != 0) throw std::runtime_error("relocation table has an invalid layout");
        if (s.size / s.entry_size > 1'000'000) throw std::runtime_error("relocation table exceeds safety limit");
        const auto& target = sections[s.info];
        const auto& symbols = sym_it->second;
        for (std::uint64_t j = 0; j < s.size / s.entry_size; ++j) {
            const auto p = s.offset + j * s.entry_size;
            const auto r_offset = bytes.u64(p);
            const auto r_info = bytes.u64(p + 8);
            const auto symbol_index = r_info >> 32U;
            const auto relocation_type = static_cast<std::uint32_t>(r_info & 0xffffffffU);
            if (symbol_index >= symbols.size()) throw std::runtime_error("relocation references an invalid symbol");
            const auto& sym = symbols[static_cast<std::size_t>(symbol_index)];
            if (r_offset > target.size || target.size - r_offset < 4) throw std::runtime_error("relocation offset exceeds its target section");
            if ((relocation_type == 1 || relocation_type == 10) && target.size - r_offset < 8)
                throw std::runtime_error("instruction relocation does not fit in its target section");
            if (relocation_type != 0 && relocation_type != 1 && relocation_type != 2 && relocation_type != 3 && relocation_type != 4 && relocation_type != 10)
                add(out, "BPF-REL-001", Severity::warning, "unrecognized BPF relocation type " + std::to_string(relocation_type), target.name);
            if (relocation_type == 1 || relocation_type == 10) {
                if (r_offset % 8 != 0) add(out, "BPF-REL-003", Severity::error, "instruction relocation is not aligned to an 8-byte instruction boundary", target.name);
                if (target.type != kSectionProgBits || (target.flags & kFlagExec) == 0)
                    add(out, "BPF-REL-003", Severity::error, "instruction relocation targets a section that is not executable file content", target.name);
                else {
                    const auto opcode = bytes.u8(target.offset + r_offset);
                    if (relocation_type == 1 && opcode != 0x18) add(out, "BPF-REL-003", Severity::error, "R_BPF_64_64 relocation does not point to an ldimm64 instruction", target.name);
                    if (relocation_type == 10 && opcode != 0x85) add(out, "BPF-REL-003", Severity::error, "R_BPF_64_32 relocation does not point to a call instruction", target.name);
                }
            }
            if (relocation_type == 10) {
                call_relocations[s.info].insert(r_offset);
                if (sym.type == 2 && !sym.name.empty() && sym.section < sections.size() && (sections[sym.section].flags & kFlagExec) != 0)
                    calls_by_section[s.info].insert(sym.name);
                else add(out, "BPF-REL-002", Severity::warning, "local-call relocation target is not a defined function in an executable section", target.name);
            }
            if (sym.section < sections.size() && (sections[sym.section].name == ".maps" || sym.name.find("_map") != std::string::npos)) {
                maps_by_section[s.info].insert(sym.name.empty() ? sections[sym.section].name : sym.name);
            }
            if (sym.section < sections.size() && sections[sym.section].name == ".maps" && !sym.name.empty()) maps_by_section[s.info].insert(sym.name);
        }
    }

    // BTF is type metadata, not proof that the kernel verifier will accept an object.
    for (const auto& s : sections) {
        if (s.name != ".BTF") continue;
        if (s.size < 24) { add(out, "BPF-BTF-001", Severity::error, "BTF header is truncated", s.name); continue; }
        const auto magic = bytes.u16(s.offset);
        const auto version = bytes.u8(s.offset + 2);
        const auto hdr_len = bytes.u32(s.offset + 4);
        const auto type_off = bytes.u32(s.offset + 8);
        const auto type_len = bytes.u32(s.offset + 12);
        const auto str_off = bytes.u32(s.offset + 16);
        const auto str_len = bytes.u32(s.offset + 20);
        if (magic != 0xeb9f || version != 1 || hdr_len < 24 || hdr_len > s.size) { add(out, "BPF-BTF-001", Severity::error, "BTF header fields are invalid", s.name); continue; }
        const auto types_start = checked_add(hdr_len, type_off, "BTF type offset");
        const auto strings_start = checked_add(hdr_len, str_off, "BTF string offset");
        if (!range_ok(types_start, type_len, s.size) || !range_ok(strings_start, str_len, s.size)) { add(out, "BPF-BTF-001", Severity::error, "BTF type or string area exceeds section bounds", s.name); continue; }
        if (str_len == 0 || bytes.u8(s.offset + strings_start) != 0) { add(out, "BPF-BTF-001", Severity::error, "BTF string area is empty or does not start with a NUL byte", s.name); continue; }
        std::uint64_t cursor = types_start;
        const auto types_end = types_start + type_len;
        while (cursor < types_end) {
            if (!range_ok(cursor, 12, types_end)) throw std::runtime_error("truncated BTF type record");
            const auto name_off = bytes.u32(s.offset + cursor);
            const auto info = bytes.u32(s.offset + cursor + 4);
            const auto kind = (info >> 24U) & 0x1fU;
            const auto vlen = info & 0xffffU;
            const auto extra_at = cursor + 12;
            std::uint64_t extra = 0;
            switch (kind) {
                case 1: extra = 4; break; // INT
                case 3: extra = 12; break; // ARRAY
                case 4: case 5: extra = checked_mul(vlen, 12, "BTF member records"); break; // STRUCT, UNION
                case 6: extra = checked_mul(vlen, 8, "BTF enum records"); break;
                case 13: extra = checked_mul(vlen, 8, "BTF function prototype records"); break;
                case 14: extra = 4; break;
                case 15: extra = checked_mul(vlen, 12, "BTF data section records"); break;
                case 17: extra = 4; break;
                case 19: extra = checked_mul(vlen, 12, "BTF enum64 records"); break;
                case 2: case 7: case 8: case 9: case 10: case 11: case 12: case 16: case 18: break;
                default:
                    add(out, "BPF-BTF-002", Severity::warning, "BTF contains an unknown type kind " + std::to_string(kind) + "; remaining type records were not interpreted", s.name);
                    cursor = types_end;
                    continue;
            }
            if (!range_ok(extra_at, extra, types_end)) throw std::runtime_error("BTF type payload exceeds section bounds");
            if (name_off >= str_len && name_off != 0) throw std::runtime_error("BTF type name offset is invalid");
            if (name_off != 0) (void)bytes.string(s.offset + strings_start + name_off, s.offset + strings_start + str_len, "BTF type name");
            cursor = checked_add(extra_at, extra, "BTF cursor");
            ++out.btf_type_count;
        }
        if (cursor != types_end) throw std::runtime_error("BTF type area has trailing partial data");
    }

    for (const auto& s : sections) {
        if (s.name != ".BTF.ext") continue;
        if (s.size < 32 || bytes.u16(s.offset) != 0xeb9f || bytes.u8(s.offset + 2) != 1) { add(out, "BPF-CORE-001", Severity::error, "BTF.ext header is truncated or invalid", s.name); continue; }
        const auto hdr_len = bytes.u32(s.offset + 4);
        const auto relo_off = bytes.u32(s.offset + 24);
        const auto relo_len = bytes.u32(s.offset + 28);
        if (hdr_len < 32 || hdr_len > s.size || !range_ok(checked_add(hdr_len, relo_off, "CO-RE offset"), relo_len, s.size)) {
            add(out, "BPF-CORE-001", Severity::error, "CO-RE relocation area exceeds BTF.ext bounds", s.name); continue;
        }
        auto cursor = static_cast<std::uint64_t>(hdr_len) + relo_off;
        const auto end = cursor + relo_len;
        if (relo_len == 0) continue;
        if (!range_ok(cursor, 4, end)) throw std::runtime_error("truncated CO-RE record size");
        const auto rec_size = bytes.u32(s.offset + cursor);
        cursor += 4;
        if (rec_size < 16) throw std::runtime_error("CO-RE record size is smaller than the standard record");
        while (cursor < end) {
            if (!range_ok(cursor, 8, end)) throw std::runtime_error("truncated CO-RE section header");
            const auto section_name_off = bytes.u32(s.offset + cursor);
            const auto count = bytes.u32(s.offset + cursor + 4);
            cursor += 8;
            const auto payload = checked_mul(count, rec_size, "CO-RE records");
            if (!range_ok(cursor, payload, end)) throw std::runtime_error("CO-RE records exceed section bounds");
            out.core_relocation_count += count;
            cursor += payload;
            (void)section_name_off;
        }
    }

    std::uint64_t executable_sections = 0;
    for (std::uint32_t section_index = 0; section_index < sections.size(); ++section_index) {
        const auto& s = sections[section_index];
        if ((s.flags & kFlagExec) == 0 || s.name == ".text" || s.type != kSectionProgBits || s.size == 0) continue;
        ++executable_sections;
        if (s.size % 8 != 0) { add(out, "BPF-INSN-001", Severity::error, "executable BPF section size is not a multiple of 8 bytes", s.name); continue; }
        Program p;
        p.section = s.name;
        p.program_type = classify_program(s.name);
        const auto function_it = functions_by_section.find(section_index);
        if (function_it != functions_by_section.end()) p.function_symbols.assign(function_it->second.begin(), function_it->second.end());
        const auto calls_it = calls_by_section.find(section_index);
        if (calls_it != calls_by_section.end()) p.local_calls.assign(calls_it->second.begin(), calls_it->second.end());
        p.instruction_count = s.size / 8;
        if (p.program_type == "unknown") add(out, "BPF-PROG-001", Severity::warning, "executable section name does not match a recognized libbpf program section convention", s.name);
        const auto n = p.instruction_count;
        if (n > 2'000'000) throw std::runtime_error("BPF instruction section exceeds safety limit");
        std::set<std::uint64_t> continuation;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> branch_targets;
        std::set<std::string> helper_set;
        for (std::uint64_t pc = 0; pc < n; ++pc) {
            const auto at = s.offset + pc * 8;
            const auto code = bytes.u8(at);
            const auto regs = bytes.u8(at + 1);
            const auto dst = regs & 0x0fU;
            const auto src = regs >> 4U;
            const auto off = static_cast<std::int16_t>(bytes.u16(at + 2));
            const auto imm = static_cast<std::int32_t>(bytes.u32(at + 4));
            const auto cls = static_cast<std::uint8_t>(code & 0x07U);
            if (dst > 10 || src > 10) add(out, "BPF-INSN-002", Severity::error, "instruction references a register outside r0-r10", s.name, pc);
            if (code == 0x18) {
                if (pc + 1 >= n) { add(out, "BPF-INSN-003", Severity::error, "64-bit immediate instruction has no continuation slot", s.name, pc); continue; }
                const auto next = s.offset + (pc + 1) * 8;
                if (bytes.u8(next) != 0 || bytes.u8(next + 1) != 0 || bytes.u16(next + 2) != 0) add(out, "BPF-INSN-003", Severity::error, "64-bit immediate continuation slot has non-zero reserved fields", s.name, pc + 1);
                continuation.insert(pc + 1);
                ++pc;
                continue;
            }
            if ((cls == kBpfClassJmp || cls == kBpfClassJmp32) && (code & 0xf0U) != kBpfOpCall && (code & 0xf0U) != kBpfOpExit) {
                ++p.branch_count;
                const auto op = static_cast<std::uint8_t>(code & 0xf0U);
                const auto delta = cls == kBpfClassJmp32 && op == 0x00U ? static_cast<std::int64_t>(imm) : static_cast<std::int64_t>(off);
                const auto target_signed = static_cast<std::int64_t>(pc) + 1 + delta;
                if (target_signed < 0 || static_cast<std::uint64_t>(target_signed) >= n) add(out, "BPF-CFG-001", Severity::error, "branch target falls outside its executable section", s.name, pc);
                else {
                    const auto target = static_cast<std::uint64_t>(target_signed);
                    branch_targets.emplace_back(pc, target);
                    if (target <= pc) { ++p.backward_edges; add(out, "BPF-CFG-002", Severity::warning, "backward control-flow edge detected; this is not proof of an unbounded loop", s.name, pc); }
                }
            }
            if (cls == kBpfClassJmp && (code & 0xf0U) == kBpfOpCall && src == 1) {
                const auto relocated = call_relocations.find(section_index);
                if (relocated == call_relocations.end() || !relocated->second.contains(pc * 8)) {
                    ++p.branch_count;
                    const auto target_signed = static_cast<std::int64_t>(pc) + 1 + imm;
                    if (target_signed < 0 || static_cast<std::uint64_t>(target_signed) >= n) add(out, "BPF-CFG-001", Severity::error, "program-local call target falls outside its executable section", s.name, pc);
                    else branch_targets.emplace_back(pc, static_cast<std::uint64_t>(target_signed));
                }
            }
            if (cls == kBpfClassJmp && (code & 0xf0U) == kBpfOpCall && src == 0) {
                const auto name = helper_name(imm);
                helper_set.insert(name.empty() ? "bpf_helper_id_" + std::to_string(imm) : std::string(name));
                if (imm == 36) add(out, "BPF-HELPER-001", Severity::warning, "program calls bpf_probe_write_user; review whether user-memory writes are necessary and tightly constrained", s.name, pc);
                if (imm == 58) add(out, "BPF-HELPER-002", Severity::warning, "program calls bpf_override_return; review its attachment scope and intended effect", s.name, pc);
            }
            if ((cls == kBpfClassSt || cls == kBpfClassStx || cls == kBpfClassLdx) && (code & 0xe0U) == kBpfModeMem) {
                const auto base = cls == kBpfClassLdx ? src : dst;
                if (base == 10) {
                    ++p.stack_accesses;
                    const auto width = access_width(code);
                    const auto start = static_cast<std::int64_t>(off);
                    if (width == 0 || start >= 0 || start < -512 || start + static_cast<std::int64_t>(width) > 0)
                        add(out, "BPF-STACK-001", Severity::error, "direct frame-pointer stack access is outside the 512-byte BPF stack frame", s.name, pc);
                }
            }
        }
        for (const auto& [from, target] : branch_targets)
            if (continuation.contains(target)) add(out, "BPF-CFG-003", Severity::error, "control-flow edge targets the continuation half of a 64-bit immediate instruction", s.name, from);
        p.helpers.assign(helper_set.begin(), helper_set.end());
        const auto map_it = maps_by_section.find(section_index);
        if (map_it != maps_by_section.end()) p.map_symbols.assign(map_it->second.begin(), map_it->second.end());
        if (p.program_type != "unknown") out.programs.push_back(std::move(p));
    }
    if (executable_sections == 0) add(out, "BPF-PROG-002", Severity::error, "no executable BPF program sections were found");
    if (out.license.empty()) add(out, "BPF-LIC-001", Severity::warning, "object has no readable license section");
    else if (out.license != "GPL" && out.license != "Dual BSD/GPL" && out.license != "Dual MIT/GPL")
        add(out, "BPF-LIC-002", Severity::info, "license string is non-GPL; helper availability depends on the target kernel and program type");
    if (out.programs.empty() && executable_sections > 0) add(out, "BPF-PROG-003", Severity::warning, "executable sections were found but none use a recognized libbpf program section name");
    add(out, "BPF-SCOPE-001", Severity::info, "static inspection only: kernel verifier acceptance, target-kernel compatibility, runtime behavior, and attach permissions are not established");
    return out;
}

} // namespace rudy::bpf_atlas
