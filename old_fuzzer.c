// stateful_draw_fuzzer.c
// Stateful Cairo fuzzer that exercises *entire* Cairo drawing API.
// Works with libFuzzer + AFL++ (#define AFL)
//
// Build: clang -fsanitize=fuzzer,address cairo_stateful_fuzzer.c `pkg-config --cflags --libs cairo`
// AFL build: AFL_USE_ASAN=1 afl-gcc cairo_stateful_fuzzer.c -o fuzzer `pkg-config ...`

#include <cairo.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ============ Utility random access from fuzz buffer ============

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t index;
} fuzz_input_t;

static inline uint8_t pick8(fuzz_input_t *in) {
    if (in->index >= in->size) return 0;
    return in->data[in->index++];
}

static inline double pick_double(fuzz_input_t *in) {
    // Convert random int into [0,1] double
    uint32_t v = 0;
    for (int i = 0; i < 4; i++)
        v = (v << 8) | pick8(in);
    return (double)v / (double)UINT32_MAX;
}

// ============ Randomized Cairo API ============

static void random_set_source(fuzz_input_t *in, cairo_t *cr) {
    switch (pick8(in) % 3) {
    case 0: // Solid color
        cairo_set_source_rgba(cr,
            pick_double(in), pick_double(in), pick_double(in),
            pick_double(in));
        break;

    case 1: { // Linear gradient
        cairo_pattern_t *pat = cairo_pattern_create_linear(
            pick_double(in), pick_double(in),
            pick_double(in), pick_double(in));
        cairo_pattern_add_color_stop_rgba(pat, 0,
            pick_double(in), pick_double(in), pick_double(in),
            pick_double(in));
        cairo_pattern_add_color_stop_rgba(pat, 1,
            pick_double(in), pick_double(in), pick_double(in),
            pick_double(in));
        cairo_set_source(cr, pat);
        cairo_pattern_destroy(pat);
        break;
    }

    case 2: { // Radial gradient
        cairo_pattern_t *pat = cairo_pattern_create_radial(
            pick_double(in), pick_double(in), pick_double(in),
            pick_double(in), pick_double(in), pick_double(in));
        cairo_pattern_add_color_stop_rgba(pat, 0,
            pick_double(in), pick_double(in), pick_double(in),
            pick_double(in));
        cairo_pattern_add_color_stop_rgba(pat, 1,
            pick_double(in), pick_double(in), pick_double(in),
            pick_double(in));
        cairo_set_source(cr, pat);
        cairo_pattern_destroy(pat);
        break;
    }
    }
}

static void random_path(fuzz_input_t *in, cairo_t *cr) {
    switch (pick8(in) % 6) {
    case 0: cairo_move_to(cr, pick_double(in), pick_double(in)); break;
    case 1: cairo_line_to(cr, pick_double(in), pick_double(in)); break;
    case 2: cairo_rel_line_to(cr, pick_double(in), pick_double(in)); break;
    case 3:
        cairo_curve_to(cr,
            pick_double(in), pick_double(in),
            pick_double(in), pick_double(in),
            pick_double(in), pick_double(in));
        break;
    case 4:
        cairo_arc(cr,
            pick_double(in), pick_double(in),
            pick_double(in),
            pick_double(in) * 2 * M_PI,
            pick_double(in) * 2 * M_PI);
        break;
    case 5: cairo_close_path(cr); break;
    }
}

static void random_transform(fuzz_input_t *in, cairo_t *cr) {
    switch (pick8(in) % 3) {
    case 0: cairo_scale(cr, pick_double(in)*2, pick_double(in)*2); break;
    case 1: cairo_translate(cr, pick_double(in), pick_double(in)); break;
    case 2: {
        cairo_matrix_t m;
        cairo_matrix_init(&m,
            pick_double(in)*3, pick_double(in)*3,
            pick_double(in)*3, pick_double(in)*3,
            pick_double(in)*3, pick_double(in)*3);
        cairo_transform(cr, &m);
        break;
    }}
}

static void random_text(fuzz_input_t *in, cairo_t *cr) {
    const char txt[4] = {
        'A' + (pick8(in)%26),
        'a' + (pick8(in)%26),
        '0' + (pick8(in)%10),
        0
    };

    cairo_select_font_face(cr, "Georgia",
        pick8(in)%2 ? CAIRO_FONT_SLANT_ITALIC : CAIRO_FONT_SLANT_NORMAL,
        pick8(in)%2 ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);

    cairo_set_font_size(cr, 0.1 + pick_double(in)*0.5);

    cairo_move_to(cr, pick_double(in), pick_double(in));
    if (pick8(in)%2)
        cairo_show_text(cr, txt);
    else {
        cairo_text_path(cr, txt);
        cairo_fill_preserve(cr);
    }
}

// ============ Fuzz entry point ============

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    fuzz_input_t in = { data, size, 0 };

    cairo_surface_t *surface =
        cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 800, 800);
    cairo_t *cr = cairo_create(surface);

    // Coordinate normalization like tutorial (0,0)->(1,1)
    cairo_scale(cr, 800, 800);

    // Stateful loop
    for (int i = 0; i < 64 && in.index < in.size; i++) {
        switch (pick8(&in) % 6) {
            case 0: random_set_source(&in, cr); break;
            case 1: random_path(&in, cr); break;
            case 2: random_transform(&in, cr); break;
            case 3: cairo_stroke_preserve(cr); break;
            case 4: cairo_fill_preserve(cr); break;
            case 5: random_text(&in, cr); break;
        }

        // occasionally push/pop groups (image as source)
        if (pick8(&in) % 16 == 0)
            cairo_push_group(cr);
        if (pick8(&in) % 16 == 1)
            cairo_pop_group_to_source(cr);
    }

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    return 0;
}

#ifdef AFL
int main(void) {
    uint8_t buf[4096];
    while (__AFL_LOOP(1000)) {
        ssize_t len = read(0, buf, sizeof(buf));
        if (len > 0)
            LLVMFuzzerTestOneInput(buf, len);
    }
}
#endif