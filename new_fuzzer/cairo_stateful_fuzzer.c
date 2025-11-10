// fuzz/cairo_stateful_fuzzer.c
#define _GNU_SOURCE
#include <cairo.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
static sigjmp_buf escape;

static void alarm_handler(int sig) {
    siglongjmp(escape, 1);
}

#ifdef COVERAGE_BUILD
char* current_file = NULL; // Global pointer to the current file being processed
#endif

// Fuzz parameters...

#define MAX_PATCHES 1000
#define MIN_PATCHES 5

#define MIN_CURVES 10
#define MAX_CURVES 1000

// CAIRO_OPERATOR_HSL_LUMINOSITY is the last one in the enum...
#define MAX_CAIRO_OPERATOR 28

static inline double clamp_dim(double v) {
    if (!isfinite(v)) return 500.0;
    if (v < 1.0) return 1.0;
    if (v > 20000.0) return 20000.0;
    return v;
}

static inline double clamp_pos(double v, double def) {
    if (!isfinite(v) || v <= 0.0) return def;
    if (v > 1e6) return 1e6;
    return v;
}

static inline double pick_double(const uint8_t **in, size_t *remaining) {
    if (*remaining < 8) return 0.0;
    double val;
    memcpy(&val, *in, sizeof(double));
    *in += 8;
    *remaining -= 8;
    return val;
}

static inline double pick_double_extreme(const uint8_t **in, size_t *remaining) {
    double v = pick_double(in, remaining);
    switch ((int)fabs(fmod(v, 6.0))) {
        case 0: return NAN;
        case 1: return INFINITY;
        case 2: return -INFINITY;
        case 3: return v * 1e300;
        case 4: return v / 1e300;
        default: return v;
    }
}

static inline int pick_int(const uint8_t **in, size_t *remaining) {
    if (*remaining < 4) return 0;
    int x;
    memcpy(&x, *in, 4);
    *in += 4;
    *remaining -= 4;
    return x;
}

static inline char* pick_string(const uint8_t **in, size_t *remaining) {
    if (*remaining == 0) return strdup("");

    size_t len = (*remaining % 64) + 1;
    if (len > *remaining) len = *remaining;
    char *s = malloc(len + 1);
    if (!s) return strdup("");
    memcpy(s, *in, len);
    for (size_t i = 0; i < len; i++)
        if (s[i] < 32 || s[i] > 126) s[i] = 'A' + (s[i] % 26);
    s[len] = '\0';
    *in += len;
    *remaining -= len;
    return s;
}

static inline void safe_set_source(cairo_t *cr, cairo_pattern_t *p) {
    if (!p) return;
    if (cairo_pattern_status(p) == CAIRO_STATUS_SUCCESS) {
        cairo_set_source(cr, p);
    }
    cairo_pattern_destroy(p);
}

static cairo_matrix_t rand_matrix(const uint8_t **in, size_t *remaining) {
    cairo_matrix_t m;
    double a = pick_double_extreme(in, remaining);
    double b = pick_double_extreme(in, remaining);
    double c = pick_double_extreme(in, remaining);
    double d = pick_double_extreme(in, remaining);
    double tx = pick_double_extreme(in, remaining);
    double ty = pick_double_extreme(in, remaining);
    /* clamp to reasonable numbers to avoid insane matrices */
    if (!isfinite(a) || fabs(a) > 1e6) a = 1.0;
    if (!isfinite(b) || fabs(b) > 1e6) b = 0.0;
    if (!isfinite(c) || fabs(c) > 1e6) c = 0.0;
    if (!isfinite(d) || fabs(d) > 1e6) d = 1.0;
    if (!isfinite(tx) || fabs(tx) > 1e6) tx = 0.0;
    if (!isfinite(ty) || fabs(ty) > 1e6) ty = 0.0;
    cairo_matrix_init(&m, a, b, c, d, tx, ty);
    return m;
}

static cairo_surface_t* make_small_image_surface(void) {
    /* small 8x8 ARGB surface used for surface-pattern tests */
    cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 8, 8);
    if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
        if (s) cairo_surface_destroy(s);
        return NULL;
    }
    cairo_t *cr = cairo_create(s);
    if (cr) {
        cairo_set_source_rgb(cr, 0.2, 0.3, 0.4);
        cairo_paint(cr);
        cairo_destroy(cr);
    }
    return s;
}

/* put near your helpers (no new headers required) */
static inline void fill_image_with_fuzz(cairo_surface_t *img,
                                       const uint8_t **in, size_t *remaining) {
    if (!img) return;
    if (cairo_surface_status(img) != CAIRO_STATUS_SUCCESS) return;
    unsigned char *data = cairo_image_surface_get_data(img);
    if (!data) return;
    int width = cairo_image_surface_get_width(img);
    int height = cairo_image_surface_get_height(img);
    int stride = cairo_image_surface_get_stride(img);
    /* total bytes we can write */
    size_t capacity = (size_t)stride * (size_t)height;
    /* don't read more than remaining */
    size_t to_write = (*remaining < capacity) ? *remaining : capacity;
    if (to_write == 0) return;

    /* copy at most capacity bytes; fill the rest with a pattern so the rasterizer
       sees varied content */
    memcpy(data, *in, to_write);
    if (to_write < capacity) {
        /* optional deterministic fill for the leftover */
        for (size_t i = to_write; i < capacity; i++) data[i] = (unsigned char)(i & 0xFF);
    }

    /* mark dirty so Cairo knows */
    cairo_surface_mark_dirty(img);

    /* consume input bytes */
    *in += to_write;
    *remaining -= to_write;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;

    const uint8_t *in = data;
    size_t remaining = size;

    double w = 500.0, h = 500.0;
    cairo_rectangle_t ext = {0, 0, w, h};
    cairo_surface_t *surface =
        cairo_recording_surface_create(CAIRO_CONTENT_COLOR_ALPHA, &ext);

    if (!surface) return 0;
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surface);
        return 0;
    }

    cairo_t *cr = cairo_create(surface);
    if (!cr || cairo_status(cr) != CAIRO_STATUS_SUCCESS) {
        if (cr) cairo_destroy(cr);
        cairo_surface_destroy(surface);
        return 0;
    }

    cairo_save(cr);
    cairo_set_source_rgb(cr, 1,1,1);
    cairo_paint(cr);
    cairo_restore(cr);

    size_t max_ops = 2000;
    size_t ops = 0;

    while (remaining > 0 && ops++ < max_ops) {
        //uint8_t op = *in++ % 20;      // expanded 0..19
        uint8_t op = *in++ % 51;
        remaining--;

#ifdef COVERAGE_BUILD
        fprintf(stderr, "Current operation: %d\n", op);
#endif

        switch (op) {
        case 0:
            cairo_move_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            break;
        case 1:
            cairo_line_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            break;
        case 2:
            cairo_curve_to(cr,
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            break;
        case 3: {
            int dash_count = (abs(pick_int(&in,&remaining)) % 8) + 1;
            double dashes[8];
            for (int i=0;i<dash_count;i++) dashes[i] = fabs(pick_double_extreme(&in,&remaining));
            cairo_set_dash(cr, dashes, dash_count, pick_double_extreme(&in,&remaining));
            break;
        }
        case 4:
            cairo_arc(cr,
                pick_double(&in,&remaining), pick_double(&in,&remaining),
                clamp_pos(pick_double_extreme(&in,&remaining), 1.0),
                pick_double(&in,&remaining)*2*M_PI, pick_double(&in,&remaining)*2*M_PI);
            break;
        case 5:
            cairo_rectangle(cr,
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            break;
        case 6:
            (pick_int(&in,&remaining)&1) ? cairo_fill(cr) : cairo_stroke(cr);
            break;
        case 7:
            cairo_set_line_width(cr, clamp_pos(fabs(pick_double_extreme(&in,&remaining)), .5));
            break;
        case 8:
            cairo_set_line_cap(cr, abs(pick_int(&in,&remaining)) % 3);
            break;
        case 9:
            cairo_set_line_join(cr, abs(pick_int(&in,&remaining)) % 3);
            break;
        case 10:
            cairo_set_miter_limit(cr, clamp_pos(fabs(pick_double_extreme(&in,&remaining)),1.0));
            break;
        case 11: {
            switch (abs(pick_int(&in,&remaining)) % 3) {
                case 0: cairo_scale(cr,pick_double_extreme(&in,&remaining),pick_double_extreme(&in,&remaining)); break;
                case 1: cairo_rotate(cr, pick_double_extreme(&in,&remaining)); break;
                case 2: cairo_translate(cr,pick_double_extreme(&in,&remaining),pick_double_extreme(&in,&remaining)); break;
            }
            break;
        }
        case 12: {
            int t = abs(pick_int(&in,&remaining)) % 3;
            if (t == 0) {
                cairo_set_source_rgba(cr,
                    fabs(pick_double(&in,&remaining)),
                    fabs(pick_double(&in,&remaining)),
                    fabs(pick_double(&in,&remaining)),
                    fabs(pick_double(&in,&remaining)));
            } else if (t == 1) {
                cairo_pattern_t *p = cairo_pattern_create_linear(
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
                if (p) {
                    cairo_pattern_add_color_stop_rgba(p,0,1,0,0,1);
                    cairo_pattern_add_color_stop_rgba(p,1,0,1,0,1);
                }
                safe_set_source(cr, p);
            } else {
                cairo_pattern_t *p = cairo_pattern_create_radial(
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                    clamp_pos(pick_double_extreme(&in,&remaining),1.0),
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                    clamp_pos(pick_double_extreme(&in,&remaining),2.0));
                if (p) {
                    cairo_pattern_add_color_stop_rgba(p,0,0,1,0,1);
                    cairo_pattern_add_color_stop_rgba(p,1,1,1,0,1);
                }
                safe_set_source(cr, p);
            }
            break;
        }
        case 13: {
            cairo_save(cr);
            cairo_rectangle(cr,
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            cairo_clip(cr);
            if ((ops % 7) == 0) cairo_reset_clip(cr);
            cairo_restore(cr);
            break;
        }
        case 14: {
            char *s = pick_string(&in,&remaining);
            cairo_select_font_face(cr,
                s,
                abs(pick_int(&in,&remaining)) % 3,
                abs(pick_int(&in,&remaining)) % 2);
            cairo_set_font_size(cr,
                clamp_pos(fabs(pick_double_extreme(&in,&remaining)) * 50.0, 1.0));
            cairo_move_to(cr,
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining));
            if (pick_int(&in,&remaining) & 1)
                cairo_show_text(cr, s);
            else {
                cairo_text_path(cr, s);
                cairo_fill(cr);
            }
            free(s);
            break;
        }
        case 15: {
            cairo_font_options_t *opts = cairo_font_options_create();
            cairo_font_options_set_hint_style   (opts, abs(pick_int(&in,&remaining)) % 5);
            cairo_font_options_set_hint_metrics (opts, abs(pick_int(&in,&remaining)) % 3);
            cairo_set_font_options(cr, opts);
            cairo_font_options_destroy(opts);
            break;
        }

        /* ---------- Pattern API focused ops ---------- */
        case 16: { /* create and query various pattern types, then destroy */
            int ptype = abs(pick_int(&in,&remaining)) % 5;
            cairo_pattern_t *p = NULL;
            switch (ptype) {
                case 0: p = cairo_pattern_create_rgb(fabs(pick_double(&in,&remaining)),
                                                   fabs(pick_double(&in,&remaining)),
                                                   fabs(pick_double(&in,&remaining))); break;
                case 1: p = cairo_pattern_create_rgba(fabs(pick_double(&in,&remaining)),
                                                    fabs(pick_double(&in,&remaining)),
                                                    fabs(pick_double(&in,&remaining)),
                                                    fabs(pick_double(&in,&remaining))); break;
                case 2: {
                    p = cairo_pattern_create_linear(
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining));
                    if (p) {
                        int stops = (abs(pick_int(&in,&remaining)) % 3) + 1;
                        for (int i=0;i<stops;i++)
                            cairo_pattern_add_color_stop_rgba(p, (double)i/(stops-1 + 1e-9),
                                fabs(pick_double(&in,&remaining)),
                                fabs(pick_double(&in,&remaining)),
                                fabs(pick_double(&in,&remaining)),
                                fabs(pick_double(&in,&remaining)));
                    }
                    break;
                }
                case 3: {
                    p = cairo_pattern_create_radial(
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                        clamp_pos(pick_double_extreme(&in,&remaining),1.0),
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                        clamp_pos(pick_double_extreme(&in,&remaining),1.0));
                    if (p) {
                        int stops = (abs(pick_int(&in,&remaining)) % 3) + 1;
                        for (int i=0;i<stops;i++)
                            cairo_pattern_add_color_stop_rgba(p, (double)i/(stops-1 + 1e-9),
                                fabs(pick_double(&in,&remaining)),
                                fabs(pick_double(&in,&remaining)),
                                fabs(pick_double(&in,&remaining)),
                                fabs(pick_double(&in,&remaining)));
                    }
                    break;
                }
                case 4: {
                    cairo_surface_t *img = make_small_image_surface();
                    p = cairo_pattern_create_for_surface(img);
                    if (img) cairo_surface_destroy(img);
                    break;
                }
            } /* switch ptype */

            if (p) {
                cairo_pattern_status(p); /* quick touch */
                cairo_pattern_t *pref = cairo_pattern_reference(p);
                /* try getters where applicable */
                cairo_pattern_type_t t = cairo_pattern_get_type(pref);
                /* color-stop getters (only makes sense for linear/radial/solid) */
                int cnt;
                if (cairo_pattern_get_color_stop_count(pref, &cnt) != CAIRO_STATUS_SUCCESS) {
                    break;
                }
                for (int i=0;i<cnt && i<8;i++) {
                    double offset, r,g,b,a;
                    cairo_pattern_get_color_stop_rgba(pref, i, &offset, &r, &g, &b, &a);
                }
                /* try matrix get/set */
                cairo_matrix_t m = rand_matrix(&in,&remaining);
                cairo_pattern_set_matrix(pref, &m);
                cairo_matrix_t m2;
                // cairo_status_t st = cairo_pattern_get_matrix(pref, &m2);
                // (void)st;
                cairo_pattern_get_matrix(pref, &m2);
                /* extend, filter */
                cairo_pattern_set_extend(pref, (cairo_extend_t)(abs(pick_int(&in,&remaining)) % 4));
                cairo_pattern_get_extend(pref);
                cairo_pattern_set_filter(pref, (cairo_filter_t)(abs(pick_int(&in,&remaining)) % 4));
                cairo_pattern_get_filter(pref);
                /* dither if available */
                #ifdef CAIRO_HAS_DITHER
                cairo_pattern_set_dither(pref, (cairo_dither_t)(abs(pick_int(&in,&remaining)) % 3));
                cairo_pattern_get_dither(pref);
                #endif
                /* try set/get surface/rgba where applicable */
                if (t == CAIRO_PATTERN_TYPE_SOLID) {
                    double rr,gg,bb,aa;
                    if (cairo_pattern_get_rgba(pref, &rr, &gg, &bb, &aa) == CAIRO_STATUS_SUCCESS) {
                        /* noop */
                        (void)rr;
                    }
                } else if (t == CAIRO_PATTERN_TYPE_SURFACE) {
                    cairo_surface_t *s = NULL;
                    if (cairo_pattern_get_surface(pref, &s) == CAIRO_STATUS_SUCCESS) {
                        if (s) cairo_surface_destroy(s); /* ref was returned (if any) */
                    }
                }
                cairo_pattern_destroy(pref);
            } /* if p */

            break;
        }

        case 17: { /* FULL MESH RASTER TEST */
            cairo_pattern_t *mesh = cairo_pattern_create_mesh();
            if (!mesh) break;

            // int patches = (abs(pick_int(&in,&remaining)) % 25) + 5;  // 5–30 patches

            int patches = (abs(pick_int(&in,&remaining)) % (MAX_PATCHES + 1)) + MIN_PATCHES;

            for (int p = 0; p < patches && remaining > 0; p++) {
                cairo_mesh_pattern_begin_patch(mesh);

                /* Starting point */
                cairo_mesh_pattern_move_to(mesh,
                    pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining));

                /* Add 0–6 curves (0 = degenerate --> triggers weird raster paths) */
                int curves = abs(pick_int(&in,&remaining)) % (MAX_CURVES + 1);
                for (int i=0; i < curves; i++)
                    cairo_mesh_pattern_curve_to(mesh,
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining));

                /* corner colors */
                for (int corner = 0; corner < 4; corner++)
                    cairo_mesh_pattern_set_corner_color_rgba(mesh,
                        corner,
                        fabs(pick_double(&in,&remaining)),
                        fabs(pick_double(&in,&remaining)),
                        fabs(pick_double(&in,&remaining)),
                        fabs(pick_double(&in,&remaining)));

                cairo_mesh_pattern_end_patch(mesh);
            }

            /* ---- FORCE RASTERIZATION ---- */
            cairo_surface_t *img = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 64, 64);
            cairo_t *tmp = cairo_create(img);

            cairo_set_operator(tmp, (cairo_operator_t)(abs(pick_int(&in,&remaining)) % (MAX_CAIRO_OPERATOR + 1)));
            cairo_set_source(tmp, mesh);

            /* triggers rasterizer */
            cairo_paint_with_alpha(tmp, fabs(pick_double(&in,&remaining)));

            cairo_destroy(tmp);
            cairo_surface_destroy(img);

            cairo_pattern_destroy(mesh);
            break;
        }

        case 18: { /* reference / re-use source pattern via groups */
            /* create a small linear pattern, set matrix/extend, use as source & destroy */
            cairo_pattern_t *p = cairo_pattern_create_linear(0,0,10,10);
            if (p) {
                cairo_pattern_add_color_stop_rgba(p, 0, 0.1, 0.2, 0.3, 1.0);
                cairo_pattern_add_color_stop_rgba(p, 1, 0.9, 0.8, 0.7, 1.0);
                cairo_pattern_set_extend(p, CAIRO_EXTEND_REPEAT);
                cairo_matrix_t mm = rand_matrix(&in,&remaining);
                cairo_pattern_set_matrix(p, &mm);
                safe_set_source(cr, cairo_pattern_reference(p));
                cairo_pattern_destroy(p);
            }
            break;
        }

        case 19: { /* try pattern getters (get_rgba/get_surface) on many created patterns */
            cairo_pattern_t *p = cairo_pattern_create_rgba(
                fabs(pick_double(&in,&remaining)),
                fabs(pick_double(&in,&remaining)),
                fabs(pick_double(&in,&remaining)),
                fabs(pick_double(&in,&remaining)));
            if (p) {
                double r,g,b,a;
                cairo_pattern_get_rgba(p, &r, &g, &b, &a);
                cairo_pattern_destroy(p);
            }

            cairo_surface_t *img = make_small_image_surface();
            if (img) {
                cairo_pattern_t *ps = cairo_pattern_create_for_surface(img);
                if (ps) {
                    cairo_pattern_get_surface(ps, &img); /* try getter; careful with refcount */
                    cairo_pattern_destroy(ps);
                }
                cairo_surface_destroy(img);
            }
            break;
        }

        /* ------------------------------------------------------------------ */
        case 20: /* rel_move_to */
            cairo_rel_move_to(cr,
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining));
            break;

        case 21: /* rel_line_to LOOP — stress tessellators */
        {
            int reps = (abs(pick_int(&in,&remaining)) % 100) + 50;
            for (int i = 0; i < reps && remaining > 0; i++)
                cairo_rel_line_to(cr,
                    pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining));
            break;
        }

        case 22: /* rel_curve_to LOOP — high complexity strokes */
        {
            int reps = (abs(pick_int(&in,&remaining)) % 50) + 10;
            for (int i = 0; i < reps && remaining > 0; i++)
                cairo_rel_curve_to(cr,
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            break;
        }

        case 23: /* path close + random stroke/fill */
            cairo_close_path(cr);
            if (pick_int(&in,&remaining) & 1)
                cairo_fill_preserve(cr);
            cairo_stroke(cr);
            break;

        case 24: /* push_group → random drawing → pop_group_to_source */
            cairo_push_group(cr);
            for (int i = 0; i < (abs(pick_int(&in,&remaining)) % 20)+5; i++) {
                cairo_line_to(cr, pick_double_extreme(&in,&remaining),
                                   pick_double_extreme(&in,&remaining));
            }
            cairo_pop_group_to_source(cr);
            cairo_paint_with_alpha(cr, fabs(pick_double(&in,&remaining)));
            break;

        case 25: /* mask surface */
        {
            cairo_surface_t *img = make_small_image_surface();
            if (img) {
                cairo_mask_surface(cr, img,
                    pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining));
                cairo_surface_destroy(img);
            }
            break;
        }

        case 26: /* set/hit/get fill rule */
            cairo_set_fill_rule(cr, abs(pick_int(&in,&remaining)) % 2);
            cairo_fill_preserve(cr);
            break;

        case 27: /* add insane clip + stroke */
            cairo_arc(cr,
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining),
                clamp_pos(pick_double_extreme(&in,&remaining), 3.0),
                0, 2 * M_PI);
            cairo_clip_preserve(cr);
            cairo_stroke(cr);
            break;

        case 28: /* path copy → replay */
        {
            cairo_path_t *p = cairo_copy_path(cr);
            if (p) {
                cairo_new_path(cr);
                cairo_append_path(cr, p);
                cairo_path_destroy(p);
            }
            break;
        }

        case 29: /* heavy operator stress */
            cairo_set_operator(cr,
                (cairo_operator_t)(abs(pick_int(&in,&remaining)) % (MAX_CAIRO_OPERATOR))); // uses *all* blend modes
            break;

        case 30: { /* region fuzzing -> hits cairo-boxes-intersect.c */
            cairo_region_t *r1 = cairo_region_create();
            cairo_region_t *r2 = cairo_region_create();

            for (int i = 0; i < 8 && remaining > 0; i++) {
                cairo_rectangle_int_t rect = {
                    pick_int(&in,&remaining) % 500,
                    pick_int(&in,&remaining) % 500,
                    (pick_int(&in,&remaining) % 200) + 1,
                    (pick_int(&in,&remaining) % 200) + 1
                };
                cairo_region_union_rectangle(r1, &rect);
                cairo_region_union_rectangle(r2, &rect);
            }

            switch (abs(pick_int(&in,&remaining)) % 4) {
                case 0: cairo_region_intersect(r1, r2); break;
                case 1: cairo_region_xor(r1, r2); break;
                case 2: cairo_region_subtract(r1, r2); break;
                default: cairo_region_union(r1, r2); break;
            }

            cairo_region_destroy(r1);
            cairo_region_destroy(r2);
            break;
        }

        case 31: /* ATOMIC: push_group only (no drawing here) */
            cairo_push_group(cr);
            break;

        case 32: /* ATOMIC: pop_group_to_source only */
            cairo_pop_group_to_source(cr);
            cairo_paint_with_alpha(cr, fabs(pick_double(&in,&remaining)));
            break;

        case 33: /* ATOMIC: set_antialias */
            cairo_set_antialias(cr, (cairo_antialias_t)(abs(pick_int(&in,&remaining)) % 5));
            break;

        case 34: /* ATOMIC: set operator (standalone) */
            cairo_set_operator(cr, (cairo_operator_t)(abs(pick_int(&in,&remaining)) % (MAX_CAIRO_OPERATOR+1)));
            break;

        case 35: /* CLIP + RESET CLIP explicitly */
            cairo_rectangle(cr,
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining));
            cairo_clip(cr);
            if (pick_int(&in,&remaining) & 1)
                cairo_reset_clip(cr);
            break;

        case 36: /* HARD CODED TEXT PATTERN — always uses valid font */
        {
            cairo_select_font_face(cr,
                "Sans",                                // reliable font
                CAIRO_FONT_SLANT_NORMAL,
                CAIRO_FONT_WEIGHT_BOLD);

            cairo_set_font_size(cr, (fabs(pick_double_extreme(&in,&remaining)) + 1.0) * 12.0);

            cairo_move_to(cr,
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining));

            static const char *words[] = {
                "cairo", "SVG", "RGBA", "mesh", "recording"
            };
            cairo_show_text(cr, words[abs(pick_int(&in,&remaining)) % 5]);
            break;
        }

        case 37: /* ATOMIC: stroke_preserve + fill */
            cairo_stroke_preserve(cr);
            cairo_fill(cr);
            break;

        case 38: /* ATOMIC: mask with randomly constructed pattern */
        {
            cairo_surface_t *img = make_small_image_surface();
            if (img) {
                cairo_pattern_t *p = cairo_pattern_create_for_surface(img);
                cairo_mask(cr, p);
                cairo_pattern_destroy(p);
                cairo_surface_destroy(img);
            }
            break;
        }

        case 39: /* set matrix directly (CTM fuzz) */
        {
            cairo_matrix_t m = rand_matrix(&in, &remaining);
            cairo_set_matrix(cr, &m);
            break;
        }

        case 40: /* get matrix + invert it */
        {
            cairo_matrix_t m;
            cairo_get_matrix(cr, &m);
            cairo_matrix_invert(&m);  // sometimes returns failure but Cairo doesn't care
            cairo_set_matrix(cr, &m);
            break;
        }

        case 41: /* new_path only */
            cairo_new_path(cr);
            break;

        case 42: /* new_sub_path */
            cairo_new_sub_path(cr);
            break;

        case 43: /* fill_extents (does not modify state - great coverage) */
        {
            double x1,y1,x2,y2;
            cairo_fill_extents(cr, &x1,&y1,&x2,&y2);
            break;
        }

        case 44: /* stroke_extents */
        {
            double x1,y1,x2,y2;
            cairo_stroke_extents(cr, &x1,&y1,&x2,&y2);
            break;
        }

        case 45: /* ATOMIC: set tolerance (affects flattening/tessellation) */
            cairo_set_tolerance(cr, fabs(pick_double_extreme(&in,&remaining)) + 1e-6);
            break;

        case 46: /* ATOMIC: cairo_paint() */
            cairo_paint(cr);
            break;

        case 47: /* CAIRO HINTING COMBO (inspired by bug #61592) */
        {
            cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
            cairo_move_to(cr, pick_double(&in,&remaining), pick_double(&in,&remaining));
            cairo_line_to(cr, pick_double(&in,&remaining), pick_double(&in,&remaining));
            cairo_clip(cr);

            cairo_set_antialias(cr, CAIRO_ANTIALIAS_DEFAULT);
            cairo_move_to(cr, pick_double(&in,&remaining), pick_double(&in,&remaining));
            cairo_line_to(cr, pick_double(&in,&remaining), pick_double(&in,&remaining));
            cairo_clip(cr);
            break;
        }

        case 48: /* CAIRO FONT EXTENTS (touches font code paths without drawing) */
        {
            cairo_font_extents_t fe;
            cairo_font_extents(cr, &fe);
            break;
        }

        case 49: /* CAIRO TEXT EXTENTS */
        {
            cairo_text_extents_t te;
            cairo_text_extents(cr, "cairo", &te);
            break;
        }


        case 50: { /* HEAVY: Fuzz image surfaces / raster-like code paths (map data -> pattern -> paint) */
            /* pick a small-ish but variable size; keep it reasonable to avoid OOM */
            int w = (abs(pick_int(&in,&remaining)) % 256) + 1;   /* 1..256 */
            int h = (abs(pick_int(&in,&remaining)) % 256) + 1;   /* 1..256 */

            /* try different formats */
            int fmt_sel = abs(pick_int(&in,&remaining)) % 3;
            cairo_format_t fmt = CAIRO_FORMAT_ARGB32;
            if (fmt_sel == 1) fmt = CAIRO_FORMAT_RGB24;
            else if (fmt_sel == 2) fmt = CAIRO_FORMAT_A8;

            /* create image surface */
            cairo_surface_t *img = cairo_image_surface_create(fmt, w, h);
            if (img && cairo_surface_status(img) == CAIRO_STATUS_SUCCESS) {
                /* fill the pixels with fuzz bytes (safe: respects stride/height) */
                fill_image_with_fuzz(img, &in, &remaining);

                /* create a similar surface (exercises create_similar_image) */
                cairo_surface_t *sim = cairo_surface_create_similar_image(img, fmt,
                                                                          (w > 16 ? w/2 : w),
                                                                          (h > 16 ? h/2 : h/2));
                if (sim && cairo_surface_status(sim) == CAIRO_STATUS_SUCCESS) {
                    fill_image_with_fuzz(sim, &in, &remaining);
                    cairo_surface_destroy(sim);
                }

                /* create pattern for the surface and try various pattern ops */
                cairo_pattern_t *ps = cairo_pattern_create_for_surface(img);
                if (ps) {
                    /* random matrix + extend + filter to exercise getters/setters */
                    cairo_matrix_t mm = rand_matrix(&in, &remaining);
                    cairo_pattern_set_matrix(ps, &mm);
                    cairo_pattern_set_extend(ps, (cairo_extend_t)(abs(pick_int(&in,&remaining)) % 4));
                    cairo_pattern_set_filter(ps, (cairo_filter_t)(abs(pick_int(&in,&remaining)) % 4));
                    cairo_pattern_get_filter(ps);
                    cairo_pattern_get_extend(ps);

                    /* set as source directly and draw */
                    safe_set_source(cr, cairo_pattern_reference(ps));
                    cairo_paint_with_alpha(cr, fabs(pick_double(&in,&remaining)));

                    /* try set_source_surface as well */
                    cairo_set_source_surface(cr, img,
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining));
                    cairo_paint_with_alpha(cr, fabs(pick_double(&in,&remaining)));

                    cairo_pattern_destroy(ps);
                }

                /* sometimes map the surface -> call APIs that read/write raw data */
                if (pick_int(&in,&remaining) & 1) {
                    /* retrieving data/pointers again is harmless even if already done */
                    unsigned char *d = cairo_image_surface_get_data(img);
                    (void)d;
                    /* mark dirty rectangle randomly */
                    /*
                    cairo_surface_mark_dirty_rectangle(img,
                        pick_int(&in,&remaining) % (w>0?w:1),
                        pick_int(&in,&remaining) % (h>0?h:1),
                        (abs(pick_int(&in,&remaining)) % (w>0?w:1)) + 1,
                        (abs(pick_int(&in,&remaining)) % (h>0?h:1)) + 1);
                    */

                }

                cairo_surface_destroy(img);
            } else {
                if (img) cairo_surface_destroy(img);
            }
            break;
        }






        }
        /* switch op */

        /*
        if ((ops % 11) == 0) cairo_new_path(cr);
        if ((ops % 17) == 0) { cairo_save(cr); cairo_restore(cr); }
        if ((ops % 29) == 0) cairo_identity_matrix(cr);
        */

        /*
        if (cairo_status(cr) != CAIRO_STATUS_SUCCESS)
            break;
        */
        
    }


#ifdef COVERAGE_BUILD

    fprintf(stderr, "Trying this file here: %s\n", current_file);
    {
        /* use the same logical extents you constructed earlier (w/h) */
        int iw = (int)ceil(w);
        int ih = (int)ceil(h);

        /* create an image surface to rasterize the recording surface onto */
        cairo_surface_t *img = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, iw, ih);
        if (img && cairo_surface_status(img) == CAIRO_STATUS_SUCCESS) {
            cairo_t *out = cairo_create(img);
            if (out && cairo_status(out) == CAIRO_STATUS_SUCCESS) {
                /* paint the recording surface onto the image */
                cairo_set_source_surface(out, surface, 0.0, 0.0);
                cairo_paint(out);

                /* flush & write to a reasonably-unique filename */
                cairo_surface_flush(img);
                char fname[256];
                snprintf(fname, sizeof(fname),
                         "cairo_out/cairo_fuzz_out_%d_%ld.png",
                         (int)getpid(), (long)rand());
                /* ignore return value but you can check it if you want */
                cairo_surface_write_to_png(img, fname);

                /* clean up */
                cairo_destroy(out);
            } else {
                if (out) cairo_destroy(out);
            }
            cairo_surface_destroy(img);
        } else {
            if (img) cairo_surface_destroy(img);
        }
    }

#endif

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    return 0;
}


/* Coverage runner below — unchanged from your version */

#ifdef COVERAGE_BUILD
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

void save_input(char* buffer, int len) {
    // Do the stuff...
    FILE* fp;
    fp = fopen("cur_input.bin", "wb");
    fwrite(buffer, 1, len, fp);
    fclose(fp);
    return;
}

static int process_file(const char *path) {

    // Install a timeout (2 seconds for coverage scans)
    signal(SIGALRM, alarm_handler);
    alarm(2);           // <-- adjust time if needed

    if (sigsetjmp(escape, 1)) {
        fprintf(stderr, "[!] Timeout on file %s — skipping\n", path);
        alarm(0);
        return 0;
    }


    current_file = path; // Set the pointer thing...
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -1; }
    if (!S_ISREG(st.st_mode)) { close(fd); return 0; }

    if ((unsigned long long)st.st_size > (1ULL << 31)) {
        fprintf(stderr, "skip huge: %s (%lld)\n", path, (long long)st.st_size);
        close(fd); return 0;
    }

    size_t size = (size_t)st.st_size;
    uint8_t *buf = (uint8_t*)malloc(size ? size : 1);
    if (!buf) { perror("malloc"); close(fd); return -1; }

    ssize_t off = 0;
    while (off < (ssize_t)size) {
        ssize_t r = read(fd, buf + off, size - (size_t)off);
        if (r < 0) { if (errno == EINTR) continue; perror("read"); free(buf); close(fd); return -1; }
        if (r == 0) break;
        off += r;
    }
    save_input(buf, off); // Do the stuff...
    LLVMFuzzerTestOneInput(buf, (size_t)off);
    free(buf); close(fd);
    alarm(0);
    return 0;
}

static int process_directory(const char *dirpath) {
    DIR *d = opendir(dirpath);
    if (!d) { perror("opendir"); return -1; }
    struct dirent *ent;
    char full[PATH_MAX];
    while ((ent = readdir(d)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        if (snprintf(full, sizeof(full), "%s/%s", dirpath, ent->d_name) >= (int)sizeof(full))
            continue;
        struct stat st;
        if (stat(full, &st) < 0) continue;
        if (S_ISREG(st.st_mode)) process_file(full);
    }
    closedir(d);
    return 0;
}

int main(int argc, char **argv) {
    srand(time(NULL));
    if (argc < 2) {
        uint8_t buf[60000];
        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len > 0) LLVMFuzzerTestOneInput(buf, (size_t)len);
        return 0;
    }
    struct stat st;
    if (stat(argv[1], &st) < 0) return 1;
    if (S_ISDIR(st.st_mode)) return process_directory(argv[1]);
    if (S_ISREG(st.st_mode)) return process_file(argv[1]);
    return 1;
}
#endif