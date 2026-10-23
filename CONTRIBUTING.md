# Contributing

Contributions should preserve offline behavior, deterministic output, bounded parsing, and the distinction between a static observation and a kernel-verifier/runtime conclusion.

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

Add parser fixtures for malformed as well as valid input. Do not include proprietary kernel objects or generated artifacts that contain sensitive data. New findings need a rule ID, severity rationale, a test, and a limitation note where the evidence is heuristic.
