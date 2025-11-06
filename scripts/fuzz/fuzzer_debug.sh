#!/bin/sh

# These next ones would be what oss-fuzz already does for us...


# These next ones would be what oss-fuzz already does for us...
export CXX=clang++
export CC=clang

export WORK=$HOME/cair_fuzzers_work/
export PREFIX=$HOME/cairo_build   # <-- this is where 'make install' put files

# Tell pkg-config to use OUR cairo .pc files
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# Make sure compiler finds our headers/libraries FIRST
export CFLAGS="-fsanitize=undefined,address,fuzzer-no-link -O3 -g -I$PREFIX/include"
export CXXFLAGS="-fsanitize=undefined,address,fuzzer-no-link -O3 -g -I$PREFIX/include"

# Make linker prefer our libs
export LDFLAGS="-L$PREFIX/lib"

# So the loader finds lib during runtime
export LD_LIBRARY_PATH="$PREFIX/lib"

export LIB_FUZZING_ENGINE="-fsanitize=address,undefined,fuzzer"

export SRC=$PWD

mkdir -p $WORK



export OUT=$HOME/cairo_fuzzers/

# mkdir -p $PREFIX # Create the directory...
mkdir -p $OUT

# mkdir -p $PREFIX # Create the directory...

PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -pthread -lrt -lpthread"
DEPS="gmodule-2.0 glib-2.0 gobject-2.0 freetype2 cairo cairo-gobject" # Originally also had gio-2.0
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"

fuzzers=$(find $SRC/debug_fuzzer/ -name "*_fuzzer.c")
for f in $fuzzers ; do
  fuzzer_name=$(basename $f .c)
  $CC $CFLAGS $BUILD_CFLAGS -DFUZZ_DEBUG=1 \
    -c $f -o $WORK/${fuzzer_name}.o
  $CXX $CXXFLAGS \
    $WORK/${fuzzer_name}.o -o $OUT/maybe_final_debug \
    $PREDEPS_LDFLAGS \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
  # cd $OUT; ln -sf cairo_seed_corpus.zip ${fuzzer_name}_seed_corpus.zip
  # cd $OUT; ln -sf cairo.dict ${fuzzer_name}.dict
done
