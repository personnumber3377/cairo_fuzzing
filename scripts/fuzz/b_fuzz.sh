#!/bin/sh

# These next ones would be what oss-fuzz already does for us...

export CXX=clang++
export CC=clang
export CFLAGS="-fsanitize=undefined,address,fuzzer-no-link -O3 -g"
export CXXFLAGS="-fsanitize=undefined,address,fuzzer-no-link -O3 -g"
export SRC=$PWD # Just the current directory

export LIB_FUZZING_ENGINE="-fsanitize=address,undefined,fuzzer" # Here we link, so define "fuzzer"
export PREFIX=$HOME/cairo_build/ # The install directory...
export OUT=$HOME/cairo_fuzzers/

export WORK=$HOME/cair_fuzzers_work/
mkdir -p $WORK

mkdir -p $PREFIX # Create the directory...
mkdir -p $OUT

# Here we would normally push the directory, but since we run this from the root of cairo, there is no need...

# Build cairo
# pushd $SRC/cairo
CFLAGS="-DDEBUG_SVG_RENDER $CFLAGS" meson \
    setup \
    --prefix=$PREFIX \
    --libdir=lib \
    --default-library=static \
    _builddir
ninja -C _builddir
ninja -C _builddir install
# popd

# mv $SRC/{*.zip,*.dict} $OUT


PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -pthread -lrt -lpthread"
DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 cairo cairo-gobject"
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"

fuzzers=$(find $SRC/fuzz/ -name "*_fuzzer.c")
for f in $fuzzers ; do
  fuzzer_name=$(basename $f .c)
  $CC $CFLAGS $BUILD_CFLAGS \
    -c $f -o $WORK/${fuzzer_name}.o
  $CXX $CXXFLAGS \
    $WORK/${fuzzer_name}.o -o $OUT/${fuzzer_name} \
    $PREDEPS_LDFLAGS \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
  # cd $OUT; ln -sf cairo_seed_corpus.zip ${fuzzer_name}_seed_corpus.zip
  # cd $OUT; ln -sf cairo.dict ${fuzzer_name}.dict
done




