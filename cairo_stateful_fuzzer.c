// fuzz/cairo_stateful_fuzzer.c

#include <cairo.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>

static inline double pick_double(const uint8_t** in, size_t* remaining) {
    if (*remaining < 8) return 0.0;
    double val;
    memcpy(&val, *in, sizeof(double));
    *in += 8;
    *remaining -= 8;
    return val;
}

static inline double pick_double_extreme(const uint8_t** in, size_t* remaining) {
    double v = pick_double(in, remaining);

    switch ((int)fabs(fmod(v, 6.0))) {
        case 0: return NAN;
        case 1: return INFINITY;
        case 2: return -INFINITY;
        case 3: return v * 1e300;  // blow up huge
        case 4: return v / 1e300;  // tiny subnormal
        default: return v;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 40) return 0; // not enough bytes to be interesting

    const uint8_t* in = data;
    size_t remaining = size;

    cairo_surface_t* surface =
        cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 500, 500);
    cairo_t* cr = cairo_create(surface);

    // Paint white background so weird alpha blends show issues
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);

    while (remaining > 0) {
        uint8_t op = *in++ % 12;
        remaining--;

        switch (op) {

        case 0: { // move_to
            cairo_move_to(cr, pick_double_extreme(&in, &remaining),
                              pick_double_extreme(&in, &remaining));
            break;
        }

        case 1: { // line_to
            cairo_line_to(cr, pick_double_extreme(&in, &remaining),
                              pick_double_extreme(&in, &remaining));
            break;
        }

        case 2: { // curve_to
            cairo_curve_to(cr,
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining));
            break;
        }

        case 3: { // randomized dash pattern
            int dash_count = (abs((int)pick_double(&in, &remaining)) % 8) + 1;
            double dashes[8];

            for (int i = 0; i < dash_count; i++)
                dashes[i] = fabs(pick_double_extreme(&in, &remaining));

            double offset = pick_double_extreme(&in, &remaining);
            cairo_set_dash(cr, dashes, dash_count, offset);
            break;
        }

        case 4: { // arc
            /*
            cairo_arc(cr,
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                fabs(pick_double_extreme(&in, &remaining)), // radius must be ≥ 0
                pick_double(&in, &remaining) * 2 * M_PI,
                pick_double(&in, &remaining) * 2 * M_PI);
            */

            cairo_arc(cr,
                pick_double(&in, &remaining),
                pick_double(&in, &remaining),
                fabs(pick_double(&in, &remaining)), // radius must be ≥ 0
                pick_double(&in, &remaining) * 2 * M_PI,
                pick_double(&in, &remaining) * 2 * M_PI);
            
            break;
        }

        case 5: { // rectangle
            cairo_rectangle(cr,
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining));
            break;
        }

        case 6: { // fill or stroke randomly
            if (op & 1) cairo_fill(cr);
            else        cairo_stroke(cr);
            break;
        }

        case 7: { // change line width
            double lw = fabs(pick_double_extreme(&in, &remaining));
            cairo_set_line_width(cr, lw);
            break;
        }

        case 8: { // change line cap
            cairo_set_line_cap(cr,
                (int)fabs(pick_double(&in, &remaining)) % 3);
            break;
        }

        case 9: { // change line join
            cairo_set_line_join(cr,
                (int)fabs(pick_double(&in, &remaining)) % 3);
            break;
        }

        case 10: { // change miter limit
            cairo_set_miter_limit(cr, fabs(pick_double_extreme(&in, &remaining)));
            break;
        }

        case 11: { // random transform (scale/rotate/translate)
            int r = ((int)pick_double(&in, &remaining)) % 3;
            switch (r) {
                case 0: cairo_scale(cr,
                           pick_double_extreme(&in, &remaining),
                           pick_double_extreme(&in, &remaining)); break;
                case 1: cairo_rotate(cr,
                           pick_double_extreme(&in, &remaining)); break;
                case 2: cairo_translate(cr,
                           pick_double_extreme(&in, &remaining),
                           pick_double_extreme(&in, &remaining)); break;
            }
            break;
        }
        }
    }

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    return 0;
}