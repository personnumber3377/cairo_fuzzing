for f in corpus/*; do
    echo "$f"
    ./cairo_stateful_fuzzer_coverage < "$f"
done

