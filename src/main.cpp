#include "rudy_bpf_atlas/analyzer.hpp"
#include "rudy_bpf_atlas/report.hpp"

#include <charconv>
#include <iostream>
#include <string>
#include <string_view>
#include <stdexcept>

namespace {
void usage(std::ostream& out) {
    out << "Rudy BPF Atlas 0.1.0 — inspect eBPF ELF objects without loading them\n\n"
        << "Usage: rudy-bpf-atlas inspect <file.o> [--format text|json|sarif] [--fail-on note|warning|error] [--max-file-size bytes]\n"
        << "       rudy-bpf-atlas --help\n\n"
        << "Exit codes: 0 analysis completed; 1 severity gate matched; 2 input or usage error.\n";
}

int threshold(std::string_view value) {
    if (value == "note") return 0;
    if (value == "warning") return 1;
    if (value == "error") return 2;
    throw std::invalid_argument("--fail-on must be note, warning, or error");
}
}

int main(int argc, char** argv) {
    if (argc == 2 && (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h")) { usage(std::cout); return 0; }
    if (argc < 3 || std::string_view(argv[1]) != "inspect") { usage(std::cerr); return 2; }
    std::string format = "text";
    int fail_level = 3;
    rudy::bpf_atlas::Options options;
    try {
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg(argv[i]);
            if (arg == "--format" && i + 1 < argc) format = argv[++i];
            else if (arg == "--fail-on" && i + 1 < argc) fail_level = threshold(argv[++i]);
            else if (arg == "--max-file-size" && i + 1 < argc) {
                const std::string_view value(argv[++i]);
                const auto result = std::from_chars(value.data(), value.data() + value.size(), options.max_file_size);
                if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || options.max_file_size == 0)
                    throw std::invalid_argument("--max-file-size must be a positive integer byte count");
            }
            else throw std::invalid_argument("unknown or incomplete option: " + std::string(arg));
        }
        if (format != "text" && format != "json" && format != "sarif") throw std::invalid_argument("--format must be text, json, or sarif");
        const auto analysis = rudy::bpf_atlas::Analyzer{options}.analyze(argv[2]);
        if (format == "json") std::cout << rudy::bpf_atlas::render_json(analysis) << '\n';
        else if (format == "sarif") std::cout << rudy::bpf_atlas::render_sarif(analysis) << '\n';
        else std::cout << rudy::bpf_atlas::render_text(analysis);
        for (const auto& finding : analysis.findings)
            if (rudy::bpf_atlas::severity_rank(finding.severity) >= fail_level) return 1;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "rudy-bpf-atlas: " << ex.what() << '\n';
        return 2;
    }
}
