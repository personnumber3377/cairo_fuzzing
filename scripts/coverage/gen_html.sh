llvm-cov show \
    ./cairo_stateful_fuzzer \
    -instr-profile=coverage.profdata \
    -format=html \
    -output-dir=coverage_html \
    -ignore-filename-regex="/usr/include" \
    -show-instantiations
