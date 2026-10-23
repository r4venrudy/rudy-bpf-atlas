#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rudy::bpf_atlas {

enum class Severity { info, warning, error };

struct Finding {
    std::string rule_id;
    Severity severity{Severity::info};
    std::string message;
    std::string section;
    std::uint64_t instruction{};
};

struct Program {
    std::string section;
    std::string program_type;
    std::vector<std::string> function_symbols;
    std::vector<std::string> local_calls;
    std::uint64_t instruction_count{};
    std::vector<std::string> helpers;
    std::vector<std::string> map_symbols;
    std::uint64_t branch_count{};
    std::uint64_t backward_edges{};
    std::uint64_t stack_accesses{};
};

struct Analysis {
    std::filesystem::path input;
    std::uint16_t machine{};
    std::uint64_t file_size{};
    std::uint64_t section_count{};
    std::string license;
    std::uint64_t btf_type_count{};
    std::uint64_t core_relocation_count{};
    std::vector<Program> programs;
    std::vector<Finding> findings;
};

struct Options {
    std::uint64_t max_file_size{256ULL * 1024ULL * 1024ULL};
};

class Analyzer {
public:
    explicit Analyzer(Options options = {});
    [[nodiscard]] Analysis analyze(const std::filesystem::path& path) const;

private:
    Options options_;
};

[[nodiscard]] std::string to_string(Severity severity);

} // namespace rudy::bpf_atlas
