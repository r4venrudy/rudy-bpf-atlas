#include "rudy_bpf_atlas/analyzer.hpp"
#include "rudy_bpf_atlas/report.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;
int checks = 0;

void expect(bool value, const std::string& message) {
    ++checks;
    if (!value) throw std::runtime_error("check failed: " + message);
}

void put16(Bytes& b, std::size_t at, std::uint16_t v) {
    b.at(at) = static_cast<std::uint8_t>(v); b.at(at + 1) = static_cast<std::uint8_t>(v >> 8U);
}
void put32(Bytes& b, std::size_t at, std::uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b.at(at + i) = static_cast<std::uint8_t>(v >> (i * 8U));
}
void put64(Bytes& b, std::size_t at, std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) b.at(at + i) = static_cast<std::uint8_t>(v >> (i * 8U));
}

struct Sec {
    std::string name;
    std::uint32_t type{1};
    std::uint64_t flags{};
    Bytes data;
    std::uint32_t link{};
    std::uint32_t info{};
    std::uint64_t align{1};
    std::uint64_t entsize{};
    std::uint32_t name_offset{};
    std::uint64_t file_offset{};
};

Bytes make_btf() {
    Bytes b(45, 0);
    put16(b, 0, 0xeb9f); b[2] = 1; put32(b, 4, 24);
    put32(b, 8, 0); put32(b, 12, 16); put32(b, 16, 16); put32(b, 20, 5);
    put32(b, 24, 1); put32(b, 28, 1U << 24U); put32(b, 32, 4); put32(b, 36, 32U << 24U);
    b[40] = 0; b[41] = 'i'; b[42] = 'n'; b[43] = 't'; b[44] = 0;
    return b;
}

Bytes make_btf_ext() {
    Bytes b(60, 0);
    put16(b, 0, 0xeb9f); b[2] = 1; put32(b, 4, 32);
    put32(b, 24, 0); put32(b, 28, 28);
    put32(b, 32, 16); put32(b, 36, 1); put32(b, 40, 1);
    put32(b, 44, 0); put32(b, 48, 0); put32(b, 52, 0); put32(b, 56, 0);
    return b;
}

Bytes make_object(std::int16_t branch_offset = -1, bool include_exec = true) {
    std::vector<Sec> sections(1);
    sections.push_back({".shstrtab",3,0,{0},0,0,1});
    sections.push_back({".strtab",3,0,{0,'c','o','u','n','t','e','r','_','m','a','p',0,'s','u','b','p','r','o','g',0,'x','d','p','_','e','n','t','r','y',0},0,0,1});
    Bytes symtab(96, 0);
    put32(symtab, 24, 1); symtab[28] = 0x11; put16(symtab, 30, 4);
    put32(symtab, 48, 13); symtab[52] = 0x12; put16(symtab, 54, 5);
    put32(symtab, 72, 21); symtab[76] = 0x12; put16(symtab, 78, 6);
    sections.push_back({".symtab",2,0,std::move(symtab),2,1,8,24});
    sections.push_back({".maps",1,3,Bytes(16,0),0,0,8});
    Bytes subprogram(8, 0); subprogram[0] = 0x95;
    sections.push_back({".text",1,6,std::move(subprogram),0,0,8});
    Bytes instructions(56, 0);
    // ldimm64 r1, map reference; its continuation occupies the next slot.
    instructions[0] = 0x18; instructions[1] = 0x11;
    // JEQ r0, 0, branch_offset (used to exercise backwards and invalid edges).
    instructions[16] = 0x15; put16(instructions, 18, static_cast<std::uint16_t>(branch_offset));
    // call helper 36: bpf_probe_write_user
    instructions[24] = 0x85; put32(instructions, 28, 36);
    // STX DW [r10-520], r1: outside the permitted 512-byte stack frame.
    instructions[32] = 0x7b; instructions[33] = 0x1a; put16(instructions, 34, static_cast<std::uint16_t>(-520));
    instructions[40] = 0x85; instructions[41] = 0x10; // relocated BPF_PSEUDO_CALL to .text:subprog
    instructions[48] = 0x95;
    if (include_exec) sections.push_back({"xdp",1,6,std::move(instructions),0,0,8});
    else sections.push_back({"notes",1,0,{},0,0,1});
    Bytes rela(48, 0); put64(rela, 0, 0); put64(rela, 8, (1ULL << 32U) | 1ULL);
    put64(rela, 24, 40); put64(rela, 32, (2ULL << 32U) | 10ULL);
    sections.push_back({".relxdp",4,0,std::move(rela),3,6,8,24});
    sections.push_back({"license",1,0,Bytes{'G','P','L',0},0,0,1});
    sections.push_back({".BTF",1,0,make_btf(),0,0,4});
    sections.push_back({".BTF.ext",1,0,make_btf_ext(),0,0,4});

    std::string names(1, '\0');
    for (auto& s : sections) {
        if (s.name.empty()) continue;
        s.name_offset = static_cast<std::uint32_t>(names.size()); names += s.name; names.push_back('\0');
    }
    sections[1].data.assign(names.begin(), names.end());
    std::uint64_t offset = 64;
    for (std::size_t i = 1; i < sections.size(); ++i) {
        const auto alignment = std::max<std::uint64_t>(1, sections[i].align);
        offset = (offset + alignment - 1) & ~(alignment - 1);
        sections[i].file_offset = offset;
        offset += sections[i].data.size();
    }
    const auto shoff = (offset + 7) & ~std::uint64_t{7};
    Bytes file(static_cast<std::size_t>(shoff + sections.size() * 64), 0);
    file[0] = 0x7f; file[1] = 'E'; file[2] = 'L'; file[3] = 'F'; file[4] = 2; file[5] = 1; file[6] = 1;
    put16(file, 16, 1); put16(file, 18, 247); put32(file, 20, 1); put64(file, 40, shoff);
    put16(file, 52, 64); put16(file, 58, 64); put16(file, 60, static_cast<std::uint16_t>(sections.size())); put16(file, 62, 1);
    for (std::size_t i = 1; i < sections.size(); ++i) {
        std::copy(sections[i].data.begin(), sections[i].data.end(), file.begin() + static_cast<std::ptrdiff_t>(sections[i].file_offset));
        const auto h = static_cast<std::size_t>(shoff) + i * 64;
        put32(file, h, sections[i].name_offset); put32(file, h + 4, sections[i].type); put64(file, h + 8, sections[i].flags);
        put64(file, h + 24, sections[i].file_offset); put64(file, h + 32, sections[i].data.size());
        put32(file, h + 40, sections[i].link); put32(file, h + 44, sections[i].info); put64(file, h + 48, sections[i].align); put64(file, h + 56, sections[i].entsize);
    }
    return file;
}

std::filesystem::path write_temp(const Bytes& bytes, std::string_view suffix = ".o") {
    const auto path = std::filesystem::temp_directory_path() / ("rudy-bpf-atlas-test" + std::string(suffix));
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) throw std::runtime_error("could not create test fixture");
    return path;
}

void write_fixture(const std::filesystem::path& path) {
    const auto bytes = make_object();
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) throw std::runtime_error("could not write requested fixture");
}

bool has_rule(const rudy::bpf_atlas::Analysis& a, std::string_view id) {
    return std::any_of(a.findings.begin(), a.findings.end(), [id](const auto& f) { return f.rule_id == id; });
}

template<class F> void must_throw(F&& f, std::string_view message) {
    bool threw = false;
    try { f(); } catch (const std::exception&) { threw = true; }
    expect(threw, std::string(message));
}

}

int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string_view(argv[1]) == "--write-fixture") {
            write_fixture(argv[2]);
            return 0;
        }
        const auto valid = write_temp(make_object());
        const auto a = rudy::bpf_atlas::Analyzer{}.analyze(valid);
        expect(a.machine == 247, "EM_BPF is reported");
        expect(a.programs.size() == 1, "recognized XDP program is retained");
        expect(a.programs[0].program_type == "xdp", "XDP section is classified");
        expect(a.programs[0].instruction_count == 7, "ldimm64 continuation is counted as two slots");
        expect(a.programs[0].helpers.size() == 1 && a.programs[0].helpers[0] == "bpf_probe_write_user", "helper ID is resolved");
        expect(a.programs[0].map_symbols.size() == 1 && a.programs[0].map_symbols[0] == "counter_map", "map relocation is resolved");
        expect(a.programs[0].function_symbols.size() == 1 && a.programs[0].function_symbols[0] == "xdp_entry", "program function symbol is reported");
        expect(a.programs[0].local_calls.size() == 1 && a.programs[0].local_calls[0] == "subprog", "local call relocation is reported");
        expect(a.programs[0].backward_edges == 1 && has_rule(a, "BPF-CFG-002"), "back edge is reported without claiming it is unbounded");
        expect(has_rule(a, "BPF-HELPER-001"), "user-memory write helper gets a review finding");
        expect(has_rule(a, "BPF-STACK-001"), "out-of-frame stack access is reported");
        expect(a.btf_type_count == 1, "BTF type is parsed");
        expect(a.core_relocation_count == 1, "CO-RE relocation metadata is counted");
        expect(a.license == "GPL", "license section is parsed");

        const auto json = rudy::bpf_atlas::render_json(a);
        expect(json.find("\"format\":\"ELF64-LE-EM_BPF\"") != std::string::npos, "JSON includes explicit format");
        expect(json.find("bpf_probe_write_user") != std::string::npos, "JSON includes helper names");
        expect(json.find("\\u") == std::string::npos, "ordinary JSON strings do not get spurious unicode escapes");
        const auto sarif = rudy::bpf_atlas::render_sarif(a);
        expect(sarif.find("\"version\":\"2.1.0\"") != std::string::npos, "SARIF 2.1.0 is emitted");
        expect(sarif.find("BPF-STACK-001") != std::string::npos, "SARIF includes rule identifiers");
        expect(rudy::bpf_atlas::render_text(a).find("static inspection only") != std::string::npos, "text output preserves static-analysis limits");

        const auto to_continuation = write_temp(make_object(-2), "-continuation.o");
        const auto b = rudy::bpf_atlas::Analyzer{}.analyze(to_continuation);
        expect(has_rule(b, "BPF-CFG-003"), "branch into ldimm64 continuation is rejected");

        const auto invalid_branch = write_temp(make_object(100), "-branch.o");
        const auto c = rudy::bpf_atlas::Analyzer{}.analyze(invalid_branch);
        expect(has_rule(c, "BPF-CFG-001"), "out-of-range branch is rejected");

        auto elf32 = make_object(); elf32[4] = 1;
        const auto p32 = write_temp(elf32, "-32.o");
        must_throw([&] { (void)rudy::bpf_atlas::Analyzer{}.analyze(p32); }, "ELF32 is rejected explicitly");
        auto be = make_object(); be[5] = 2;
        const auto pbe = write_temp(be, "-be.o");
        must_throw([&] { (void)rudy::bpf_atlas::Analyzer{}.analyze(pbe); }, "big-endian ELF is rejected explicitly");
        auto wrong_machine = make_object(); put16(wrong_machine, 18, 62);
        const auto pm = write_temp(wrong_machine, "-machine.o");
        must_throw([&] { (void)rudy::bpf_atlas::Analyzer{}.analyze(pm); }, "non-BPF machine is rejected");
        auto truncated = make_object(); truncated.resize(70);
        const auto pt = write_temp(truncated, "-truncated.o");
        must_throw([&] { (void)rudy::bpf_atlas::Analyzer{}.analyze(pt); }, "truncated section table is rejected");
        const auto too_large = write_temp(make_object(), "-limit.o");
        must_throw([&] { (void)rudy::bpf_atlas::Analyzer{{32}}.analyze(too_large); }, "configured file-size limit is enforced");
        auto broken_btf = make_object();
        // Corrupt the BTF string-area offset inside the .BTF section.
        const std::array<std::uint8_t, 3> btf_marker{0x9f,0xeb,0x01};
        auto where = std::search(broken_btf.begin(), broken_btf.end(), btf_marker.begin(), btf_marker.end());
        expect(where != broken_btf.end(), "BTF fixture marker exists");
        if (where != broken_btf.end()) put32(broken_btf, static_cast<std::size_t>(where - broken_btf.begin()) + 16, 0xfffffff0U);
        const auto pb = write_temp(broken_btf, "-btf.o");
        const auto d = rudy::bpf_atlas::Analyzer{}.analyze(pb);
        expect(has_rule(d, "BPF-BTF-001"), "malformed BTF area produces a bounded finding");

        // Deterministic mutation smoke test: malformed headers and nested table offsets must fail closed.
        const auto mutation_path = std::filesystem::temp_directory_path() / "rudy-bpf-atlas-mutation.o";
        auto seed = make_object();
        std::uint32_t random = 0x5eed1234U;
        for (int i = 0; i < 256; ++i) {
            random ^= random << 13U; random ^= random >> 17U; random ^= random << 5U;
            auto mutated = seed;
            const auto index = static_cast<std::size_t>(random % static_cast<std::uint32_t>(mutated.size()));
            mutated[index] ^= static_cast<std::uint8_t>((random >> 24U) | 1U);
            {
                std::ofstream file(mutation_path, std::ios::binary | std::ios::trunc);
                file.write(reinterpret_cast<const char*>(mutated.data()), static_cast<std::streamsize>(mutated.size()));
            }
            try { (void)rudy::bpf_atlas::Analyzer{}.analyze(mutation_path); } catch (const std::exception&) { }
            ++checks;
        }

        for (const auto& path : {valid,to_continuation,invalid_branch,p32,pbe,pm,pt,too_large,pb,mutation_path}) std::filesystem::remove(path);
        std::cout << "PASS: " << checks << " assertions\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FAIL: " << ex.what() << '\n';
        return 1;
    }
}
