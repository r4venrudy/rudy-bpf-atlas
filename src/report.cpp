#include "rudy_bpf_atlas/report.hpp"

#include <algorithm>
#include <sstream>
#include <set>
#include <string_view>

namespace rudy::bpf_atlas {
namespace {

[[nodiscard]] std::string escape(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    constexpr char hex[] = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(hex[(c >> 4U) & 0xfU]);
                    out.push_back(hex[c & 0xfU]);
                } else if (c < 0x80) out.push_back(static_cast<char>(c));
                else {
                    std::size_t length = 0;
                    if ((c & 0xe0U) == 0xc0U) length = 2;
                    else if ((c & 0xf0U) == 0xe0U) length = 3;
                    else if ((c & 0xf8U) == 0xf0U) length = 4;
                    bool valid = length != 0 && i + length <= value.size();
                    for (std::size_t j = 1; valid && j < length; ++j)
                        valid = (static_cast<unsigned char>(value[i + j]) & 0xc0U) == 0x80U;
                    if (valid) {
                        const auto second = static_cast<unsigned char>(value[i + 1]);
                        valid = !((c <= 0xc1U) || (c == 0xe0U && second < 0xa0U) || (c == 0xedU && second >= 0xa0U) ||
                                  (c == 0xf0U && second < 0x90U) || (c == 0xf4U && second >= 0x90U) || c > 0xf4U);
                    }
                    if (valid) {
                        out.append(value.substr(i, length));
                        i += length - 1;
                    } else {
                        constexpr char hex[] = "0123456789abcdef";
                        out += "\\u00";
                        out.push_back(hex[(c >> 4U) & 0xfU]);
                        out.push_back(hex[c & 0xfU]);
                    }
                }
        }
    }
    return out;
}

void strings(std::ostringstream& out, const std::vector<std::string>& values) {
    out << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) out << ',';
        out << '"' << escape(values[i]) << '"';
    }
    out << ']';
}

} // namespace

int severity_rank(Severity severity) noexcept {
    switch (severity) {
        case Severity::info: return 0;
        case Severity::warning: return 1;
        case Severity::error: return 2;
    }
    return 0;
}

std::string render_text(const Analysis& a) {
    std::ostringstream out;
    out << "Rudy BPF Atlas 0.1.0 — static eBPF object inspection\n"
        << "Input: " << a.input.generic_string() << " (" << a.file_size << " bytes)\n"
        << "ELF: 64-bit little-endian relocatable EM_BPF; sections: " << a.section_count << "\n"
        << "License: " << (a.license.empty() ? "(missing)" : a.license) << "\n"
        << "BTF types: " << a.btf_type_count << " | CO-RE relocations: " << a.core_relocation_count << "\n";
    for (const auto& p : a.programs) {
        out << "\nProgram " << p.section << " [" << p.program_type << "]\n"
            << "  instructions: " << p.instruction_count << " | branches: " << p.branch_count
            << " | back-edges: " << p.backward_edges << " | direct stack accesses: " << p.stack_accesses << "\n";
        out << "  function symbols: ";
        if (p.function_symbols.empty()) out << "(none found)";
        else for (std::size_t i = 0; i < p.function_symbols.size(); ++i) out << (i ? ", " : "") << p.function_symbols[i];
        out << "\n  local calls: ";
        if (p.local_calls.empty()) out << "(none found)";
        else for (std::size_t i = 0; i < p.local_calls.size(); ++i) out << (i ? ", " : "") << p.local_calls[i];
        out << '\n';
        out << "  helpers: ";
        if (p.helpers.empty()) out << "(none recognized)";
        else for (std::size_t i = 0; i < p.helpers.size(); ++i) out << (i ? ", " : "") << p.helpers[i];
        out << "\n  map symbols: ";
        if (p.map_symbols.empty()) out << "(none found)";
        else for (std::size_t i = 0; i < p.map_symbols.size(); ++i) out << (i ? ", " : "") << p.map_symbols[i];
        out << '\n';
    }
    out << "\nFindings (" << a.findings.size() << ")\n";
    for (const auto& f : a.findings) {
        out << "  [" << to_string(f.severity) << "] " << f.rule_id;
        if (!f.section.empty()) out << " @ " << f.section;
        if (f.instruction != 0) out << ':' << f.instruction;
        out << " — " << f.message << '\n';
    }
    return out.str();
}

std::string render_json(const Analysis& a) {
    std::ostringstream out;
    out << "{\"schema\":\"https://rudy.systems/schemas/bpf-atlas/v1\",\"input\":\"" << escape(a.input.generic_string())
        << "\",\"file_size\":" << a.file_size << ",\"format\":\"ELF64-LE-EM_BPF\",\"machine\":" << a.machine
        << ",\"section_count\":" << a.section_count << ",\"license\":\"" << escape(a.license)
        << "\",\"btf_type_count\":" << a.btf_type_count << ",\"core_relocation_count\":" << a.core_relocation_count << ",\"programs\":[";
    for (std::size_t i = 0; i < a.programs.size(); ++i) {
        if (i) out << ',';
        const auto& p = a.programs[i];
        out << "{\"section\":\"" << escape(p.section) << "\",\"type\":\"" << escape(p.program_type)
            << "\",\"instructions\":" << p.instruction_count << ",\"branches\":" << p.branch_count
            << ",\"backward_edges\":" << p.backward_edges << ",\"stack_accesses\":" << p.stack_accesses << ",\"function_symbols\":";
        strings(out, p.function_symbols);
        out << ",\"local_calls\":";
        strings(out, p.local_calls);
        out << ",\"helpers\":";
        strings(out, p.helpers);
        out << ",\"map_symbols\":";
        strings(out, p.map_symbols);
        out << '}';
    }
    out << "],\"findings\":[";
    for (std::size_t i = 0; i < a.findings.size(); ++i) {
        if (i) out << ',';
        const auto& f = a.findings[i];
        out << "{\"rule_id\":\"" << escape(f.rule_id) << "\",\"severity\":\"" << to_string(f.severity)
            << "\",\"message\":\"" << escape(f.message) << "\",\"section\":\"" << escape(f.section)
            << "\",\"instruction\":" << f.instruction << '}';
    }
    out << "]}";
    return out.str();
}

std::string render_sarif(const Analysis& a) {
    std::set<std::string> rules;
    for (const auto& f : a.findings) rules.insert(f.rule_id);
    std::ostringstream out;
    out << "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Rudy BPF Atlas\",\"informationUri\":\"https://github.com/r4venrudy/rudy-bpf-atlas\",\"rules\":[";
    bool first = true;
    for (const auto& id : rules) {
        if (!first) out << ',';
        first = false;
        out << "{\"id\":\"" << escape(id) << "\"}";
    }
    out << "]}},\"artifacts\":[{\"location\":{\"uri\":\"" << escape(a.input.generic_string()) << "\"}}],\"results\":[";
    for (std::size_t i = 0; i < a.findings.size(); ++i) {
        if (i) out << ',';
        const auto& f = a.findings[i];
        const auto level = f.severity == Severity::error ? "error" : (f.severity == Severity::warning ? "warning" : "note");
        out << "{\"ruleId\":\"" << escape(f.rule_id) << "\",\"level\":\"" << level << "\",\"message\":{\"text\":\"" << escape(f.message) << "\"}";
        if (!f.section.empty()) out << ",\"properties\":{\"section\":\"" << escape(f.section) << "\",\"instruction\":" << f.instruction << '}';
        out << '}';
    }
    out << "]}]}";
    return out.str();
}

} // namespace rudy::bpf_atlas
