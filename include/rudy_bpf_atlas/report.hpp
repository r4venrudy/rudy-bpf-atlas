#pragma once

#include "rudy_bpf_atlas/analyzer.hpp"

#include <string>

namespace rudy::bpf_atlas {

[[nodiscard]] std::string render_text(const Analysis& analysis);
[[nodiscard]] std::string render_json(const Analysis& analysis);
[[nodiscard]] std::string render_sarif(const Analysis& analysis);
[[nodiscard]] int severity_rank(Severity severity) noexcept;

} // namespace rudy::bpf_atlas
