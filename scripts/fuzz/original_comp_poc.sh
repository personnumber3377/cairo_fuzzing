#!/bin/sh

# These next ones would be what oss-fuzz already does for us...

export CXX=clang++
export CC=clang
export CFLAGS="-fsanitize=undefined,address,fuzzer-no-link -O3 -g"
export CXXFLAGS="-fsanitize=undefined,address,fuzzer-no-link -O3 -g"
export SRC=$PWD # Just the current directory

export LIB_FUZZING_ENGINE="-fsanitize=address,undefined,fuzzer" # Here we link, so define "fuzzer"
export PREFIX=$HOME/cairo_build/ # The install directory...

export WORK=$HOME/cair_fuzzers_work/
mkdir -p $WORK



export OUT=$HOME/cairo_fuzzers/

# mkdir -p $PREFIX # Create the directory...
mkdir -p $OUT

# mkdir -p $PREFIX # Create the directory...

PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -pthread -lrt -lpthread"
DEPS="gmodule-2.0 glib-2.0 gobject-2.0 freetype2 cairo cairo-gobject" # Originally also had gio-2.0
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
echo $BUILD_CFLAGS
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"
echo $BUILD_LDFLAGS


fuzzers=$(find $SRC/poc/ -name "*.c")
for f in $fuzzers ; do
  fuzzer_name=$(basename $f .c)
  $CC $CFLAGS $BUILD_CFLAGS \
    -c $f -o $WORK/${fuzzer_name}.o
  $CXX $CXXFLAGS \
    $WORK/${fuzzer_name}.o -o $OUT/poc_program \
    $PREDEPS_LDFLAGS \
    $BUILD_LDFLAGS \
    -Wl,-Bdynamic
  # cd $OUT; ln -sf cairo_seed_corpus.zip ${fuzzer_name}_seed_corpus.zip
  # cd $OUT; ln -sf cairo.dict ${fuzzer_name}.dict
done
