#!/usr/bin/env bash
set -euo pipefail

# Build + coverage generation for cairo + libFuzzer fuzzers
# Adjust these variables to your environment.

# Tools (must be clang/llvm toolchain)
CC=clang
CXX=clang++
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

# Paths (adjust)
SRC="$PWD"                              # root of your repo (where you run this)
WORK="$HOME/cair_fuzzers_work_coverage"          # intermediate object / profraw dir
OUT="$HOME/cairo_fuzzers_coverage"               # output binaries + coverage HTML
PREFIX="$HOME/cairo_build_coverage"              # install prefix for cairo build
CORPUS_DIR="$OUT/corpus"                # place your seed corpus here (one folder per fuzzer optional)
RUN_SECONDS=30                          # how many seconds to run each fuzzer to collect profiles

# Coverage flags (LLVM coverage)
# These lines instruct clang to produce profile data usable by llvm-cov.
COV_CFLAGS="-fprofile-instr-generate -fcoverage-mapping -O1 -g"
# If you want AddressSanitizer as well, add it. (optional)
SANITIZE_FLAGS="-fsanitize=address,undefined"

# Combined CFLAGS/CXXFLAGS
export CC CXX
export CFLAGS="${COV_CFLAGS} ${SANITIZE_FLAGS} -fno-omit-frame-pointer"
export CXXFLAGS="${COV_CFLAGS} ${SANITIZE_FLAGS} -fno-omit-frame-pointer"

# Make dirs
mkdir -p "$WORK"
mkdir -p "$OUT"
mkdir -p "$PREFIX"
mkdir -p "$CORPUS_DIR"
echo "Working: SRC=$SRC, OUT=$OUT, WORK=$WORK, PREFIX=$PREFIX, CORPUS_DIR=$CORPUS_DIR"

# 1) Build Cairo with coverage instrumentation using Meson/Ninja (adapted from your script)
echo "==> Configuring and building Cairo with coverage flags..."
pushd "$SRC" >/dev/null

# If you already used meson setup, remove previous build dir to ensure flags are used:
rm -rf _builddir
# Use meson to configure; pass CFLAGS/CXXFLAGS in env so meson picks them up
export CFLAGS CXXFLAGS
meson setup _builddir --prefix="$PREFIX" --libdir=lib --default-library=static --buildtype=debug
ninja -C _builddir -v
ninja -C _builddir install -v

popd >/dev/null
echo "Cairo built & installed into $PREFIX"

# 2) Compile fuzzers with same instrumentation and link them statically against the installed cairo
# You may need to adapt the pkg-config DEPS to your build. Make sure pkg-config picks $PREFIX/lib/pkgconfig first:
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"

DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 cairo cairo-gobject"
PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -pthread -lrt -lpthread"
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"

echo "BUILD_CFLAGS: $BUILD_CFLAGS"
echo "BUILD_LDFLAGS: $BUILD_LDFLAGS"

fuzzer_sources=$(find "$SRC/fuzz/" -maxdepth 1 -type f -name "*_fuzzer.c" -print)
if [ -z "$fuzzer_sources" ]; then
  echo "No fuzzers found in $SRC/fuzz. Aborting."
  exit 1
fi

for srcf in $fuzzer_sources; do
  fuzzer_name=$(basename "$srcf" .c)
  echo "==> Building fuzzer: $fuzzer_name"
  # compile .o
  $CC $BUILD_CFLAGS -c "$srcf" -o "$WORK/${fuzzer_name}.o"
  # Link an instrumented binary; for coverage we do NOT link libFuzzer engine (we will run the binary "normally"),
  # but if you want libFuzzer features, link with -fsanitize=fuzzer (optional).
  $CXX $CXXFLAGS \
    "$WORK/${fuzzer_name}.o" -o "$OUT/${fuzzer_name}" \
    $PREDEPS_LDFLAGS \
    $BUILD_LDFLAGS \
    -Wl,-Bdynamic

  chmod +x "$OUT/${fuzzer_name}"
done

echo "All fuzzers built. Binaries in $OUT"

# 3) Run each fuzzer for RUN_SECONDS with LLVM_PROFILE_FILE set to produce .profraw files
echo "==> Running fuzzers to collect profiles (each fuzzer will run for $RUN_SECONDS seconds)..."
pushd "$OUT" >/dev/null

# create unique profraw directory
PROFRAW_DIR="$WORK/profraw"
rm -rf "$PROFRAW_DIR"
mkdir -p "$PROFRAW_DIR"

# For each fuzzer binary, set LLVM_PROFILE_FILE to collect .profraw,
# and run it pointing at the CORPUS_DIR (if present) for a limited time.
for fbin in ./*_fuzzer*; do
  [ -x "$fbin" ] || continue
  fname=$(basename "$fbin")
  echo "-> Running $fname for $RUN_SECONDS s"
  # clean old profraws
  rm -f "$PROFRAW_DIR"/*.profraw

  # The environment variable format supports %p
  export LLVM_PROFILE_FILE="$PROFRAW_DIR/${fname}-%p.profraw"

  # Ensure we have at least one corpus subdir; if none, create a trivial corpus (optional)
  # If you want to use per-fuzzer corpus directories, create $CORPUS_DIR/$fname/
  if [ -d "$CORPUS_DIR/$fname" ]; then
    SEED_DIR="$CORPUS_DIR/$fname"
  else
    SEED_DIR="$CORPUS_DIR"
  fi

  # If there are no seed files, touch a trivial seed to get code exercised
  if [ -z "$(find "$SEED_DIR" -type f -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "No seeds in $SEED_DIR; creating a trivial seed"
    printf '\0' > "$WORK/trivial_seed"
    SEED_DIR="$WORK"
  fi

  # Run the fuzzer binary for RUN_SECONDS seconds against the seed directory.
  # We pass the seed dir as the first argument; libFuzzer-style fuzzers accept a seed corpus directory.
  # Use timeout to limit run time.
  timeout --preserve-status ${RUN_SECONDS}s "$fbin" "$SEED_DIR" || true

  # After run, copy profraws out so we don't lose them on next iteration
  mkdir -p "$WORK/profraw_collected"
  cp -av "$PROFRAW_DIR"/*.profraw "$WORK/profraw_collected/" 2>/dev/null || true
done

popd >/dev/null

# 4) Merge .profraw -> .profdata
echo "==> Merging profraw files..."
PROFRAW_COLLECT="$WORK/profraw_collected"
if [ -z "$(ls -A "$PROFRAW_COLLECT" 2>/dev/null)" ]; then
  echo "No profraw files found in $PROFRAW_COLLECT. Aborting."
  exit 1
fi

PROFDATA="$OUT/coverage.profdata"
rm -f "$PROFDATA"
$LLVM_PROFDATA merge -sparse "$PROFRAW_COLLECT"/*.profraw -o "$PROFDATA"
echo "Merged profdata written to $PROFDATA"

# 5) Generate coverage report (HTML) with llvm-cov
COV_HTML_DIR="$OUT/coverage_html"
rm -rf "$COV_HTML_DIR"
mkdir -p "$COV_HTML_DIR"

echo "==> Generating llvm-cov HTML reports..."
for fbin in "$OUT"/*_fuzzer*; do
  [ -x "$fbin" ] || continue
  fname=$(basename "$fbin")
  echo "Generating coverage for $fname"
  # llvm-cov show with -format=html renders per-source HTML. Output saved in COV_HTML_DIR/$fname
  mkdir -p "$COV_HTML_DIR/$fname"
  $LLVM_COV show "$fbin" \
    -instr-profile="$PROFDATA" \
    -format=html \
    -output-dir="$COV_HTML_DIR/$fname" \
    -Xdemangler=none \
    "$SRC"/src \
    || echo "llvm-cov show returned non-zero for $fname (continue)."
done

# also emit a quick summary text report using llvm-cov report
REPORT="$OUT/coverage_summary.txt"
echo "Coverage summary (llvm-cov report):" > "$REPORT"
for fbin in "$OUT"/*_fuzzer*; do
  [ -x "$fbin" ] || continue
  $LLVM_COV report "$fbin" -instr-profile="$PROFDATA" >> "$REPORT" 2>&1 || true
done

echo "Coverage HTML saved to: $COV_HTML_DIR"
echo "Coverage summary: $REPORT"
echo "Done."