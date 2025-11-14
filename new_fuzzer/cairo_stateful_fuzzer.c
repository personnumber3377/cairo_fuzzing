// fuzz/cairo_stateful_fuzzer.c
#define _GNU_SOURCE
#include <cairo.h>
#include <cairo-pdf.h>   // ✅ added
#include <cairo-svg.h>   // ✅ added
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <cairo.h>
#include <cairo-svg.h>
#include <cairo-pdf.h>
#include <cairo-ps.h>

#define WIDTH 256
#define HEIGHT 256
#define MAX_CAIRO_OPERATOR 28
#define MAX_PATCHES 5
#define MIN_PATCHES 1
#define MAX_CURVES 4

typedef enum {
    BE_RECORDING = 0,
    BE_IMAGE     = 1,
    BE_PDF       = 2,
    BE_SVG       = 3
} backend_e;

// Debug macro
#ifdef COVERAGE_BUILD
#define DEBUG_OP(OP, FMT, ...) \
    fprintf(stderr, "Op %d: " FMT "\n", (OP), ##__VA_ARGS__)
#else
#define DEBUG_OP(OP, FMT, ...) do {} while(0)
#endif


// Function prototypes

// Helper extraction
static double pick_double(const uint8_t **data, size_t *len);
static double pick_double_unit(const uint8_t **data, size_t *len);
static int pick_int(const uint8_t **data, size_t *len);
static double pick_double_extreme(const uint8_t **data, size_t *len);
static double pick_double_scale(const uint8_t **data, size_t *len);

// Source + image helpers
static cairo_surface_t* make_small_image_surface(void);
static void fill_image_with_fuzz(cairo_surface_t *surf, const uint8_t **data, size_t *len);
static cairo_matrix_t rand_matrix(const uint8_t **data, size_t *len);
static void safe_set_source(cairo_t *cr, cairo_pattern_t *p);

// Backend selection helper
static cairo_surface_t* choose_backend_surface_B(const uint8_t **data, size_t *len,
                                                 double w, double h, backend_e *out);

// Glyph + text helpers
static cairo_glyph_t* make_glyphs(const uint8_t *data, size_t size, size_t pos, int *out_count);
static cairo_text_cluster_t* make_clusters(const uint8_t *data, size_t size, size_t pos, int *out_count);
static cairo_font_face_t* make_font_face(const uint8_t *data, size_t size, size_t pos);
static char* read_string_at(const uint8_t *data, size_t size, size_t *off, size_t max);
static void read_matrix_from_bytes(cairo_matrix_t *out,
                                   const uint8_t *data, size_t size, size_t pos);
static double clamp_pos(double v, double minv);




static sigjmp_buf escape;

static void alarm_handler(int sig) {
    siglongjmp(escape, 1);
}

#ifdef COVERAGE_BUILD
char* current_file = NULL;
#endif

#ifdef DEBUG_OPS
#  define DEBUG(op, fmt, ...) fprintf(stderr, "[OP %02d] " fmt "\n", (op), ##__VA_ARGS__)
#else
#  define DEBUG(op, fmt, ...) do{}while(0)
#endif

#define WIDTH 500.0
#define HEIGHT 500.0

#define MAX_PATCHES 1000
#define MIN_PATCHES 5
#define MIN_CURVES 10
#define MAX_CURVES 1000
#define MAX_CAIRO_OPERATOR 28





// Some of the missing helpers

// -------- basic extraction --------
static int pick_int(const uint8_t **data, size_t *len) {
    if (*len < 4) return 0;
    int v = *((int*)(*data));
    *data += 4;
    *len -= 4;
    return v;
}

static double pick_double(const uint8_t **data, size_t *len) {
    if (*len < sizeof(double)) return 0.0;
    double v;
    memcpy(&v, *data, sizeof(double));
    *data += sizeof(double);
    *len -= sizeof(double);
    return v;
}

static double pick_double_unit(const uint8_t **data, size_t *len) {
    return fabs(pick_double(data, len));
}

static double pick_double_scale(const uint8_t **data, size_t *len) {
    return pick_double(data, len) * 5.0;
}

static inline double clamp_pos(double v, double def) {
    if (!isfinite(v)) return def;
    if (v < 0.0) return 0.0;
    if (v > 20000.0) return 20000.0;
    return v;
}

// ✅ NEW DISTRIBUTION
static inline double pick_double_extreme(const uint8_t **in, size_t *remaining) {
    double v = pick_double(in, remaining);
    int mode = abs((int)fmod(v, 7.0));

    switch (mode) {
        case 0: return NAN;
        case 1: return INFINITY;
        case 2: return -INFINITY;
        case 3: // tightly inside 500x500 fuzz canvas
            return (((double)rand() / RAND_MAX) * (WIDTH * 2.0)) - (WIDTH);
        case 4: // tiny jitter [-1, 1]
            return (((double)rand() / RAND_MAX) * 2.0) - 1.0;
        case 5: // "moderate" values
            return (v / (double)INT64_MAX) * 1000.0;
        default:
            return v;
    }
}

/*
static inline int pick_int(const uint8_t **in, size_t *remaining) {
    if (*remaining < 4) return 0;
    int v;
    memcpy(&v, *in, 4);
    *in += 4;
    *remaining -= 4;
    return v;
}
*/

static inline char* pick_string(const uint8_t **in, size_t *remaining) {
    if (*remaining == 0) return strdup("");
    size_t len = (*remaining % 64) + 1;
    if (len > *remaining) len = *remaining;
    char *s = malloc(len + 1);
    memcpy(s, *in, len);
    for (size_t i = 0; i < len; i++)
        if (s[i] < 32 || s[i] > 126) s[i] = 'A' + (s[i] % 26);
    s[len] = '\0';
    *in += len;
    *remaining -= len;
    return s;
}

/* ---------- extra byte readers used by helpers ---------- */
static inline double read_double_at(const uint8_t *data, size_t size, size_t *pos) {
    if (*pos + sizeof(uint64_t) > size) return 0.0;
    uint64_t bits;
    memcpy(&bits, data + *pos, sizeof(bits));
    *pos += sizeof(bits);
    return (double)((int64_t)bits) / (double)INT64_MAX;
}

static inline float read_float_at(const uint8_t *data, size_t size, size_t *pos) {
    if (*pos + sizeof(uint32_t) > size) return 0.0f;
    uint32_t bits;
    memcpy(&bits, data + *pos, sizeof(bits));
    *pos += sizeof(bits);
    return (float)((int32_t)bits) / (float)INT32_MAX;
}

/* ---------- misc helpers ---------- */
static inline void safe_set_source(cairo_t *cr, cairo_pattern_t *p) {
    if (!p) return;
    if (cairo_pattern_status(p) == CAIRO_STATUS_SUCCESS)
        cairo_set_source(cr, p);
    cairo_pattern_destroy(p);
}

static cairo_matrix_t rand_matrix(const uint8_t **in, size_t *remaining) {
    cairo_matrix_t m;
    double a  = pick_double_extreme(in, remaining);
    double b  = pick_double_extreme(in, remaining);
    double c  = pick_double_extreme(in, remaining);
    double d  = pick_double_extreme(in, remaining);
    double tx = pick_double_extreme(in, remaining);
    double ty = pick_double_extreme(in, remaining);

    /* clamp for sanity */
    if (!isfinite(a)  || fabs(a)  > 1e6) a  = 1.0;
    if (!isfinite(b)  || fabs(b)  > 1e6) b  = 0.0;
    if (!isfinite(c)  || fabs(c)  > 1e6) c  = 0.0;
    if (!isfinite(d)  || fabs(d)  > 1e6) d  = 1.0;
    if (!isfinite(tx) || fabs(tx) > 1e6) tx = 0.0;
    if (!isfinite(ty) || fabs(ty) > 1e6) ty = 0.0;

    cairo_matrix_init(&m, a, b, c, d, tx, ty);
    return m;
}

static cairo_surface_t* make_small_image_surface(void) {
    cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 8, 8);
    if (!s || cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
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

static inline void fill_image_with_fuzz(cairo_surface_t *img,
                                        const uint8_t **in, size_t *remaining) {
    if (!img) return;
    if (cairo_surface_status(img) != CAIRO_STATUS_SUCCESS) return;
    unsigned char *data = cairo_image_surface_get_data(img);
    if (!data) return;
    int width  = cairo_image_surface_get_width(img);
    int height = cairo_image_surface_get_height(img);
    int stride = cairo_image_surface_get_stride(img);
    (void)width; (void)height;

    size_t capacity = (size_t)stride * (size_t)height;
    size_t to_write = (*remaining < capacity) ? *remaining : capacity;
    if (to_write == 0) return;

    memcpy(data, *in, to_write);
    if (to_write < capacity) {
        for (size_t i = to_write; i < capacity; i++)
            data[i] = (unsigned char)(i & 0xFF);
    }
    cairo_surface_mark_dirty(img);
    *in += to_write;
    *remaining -= to_write;
}

/* ---------- glyph / cluster / matrix / font helpers ---------- */
static cairo_glyph_t *make_glyphs(const uint8_t *data, size_t size, size_t seed_pos, int *num_glyphs) {
    size_t p = seed_pos;
    *num_glyphs = (p < size) ? (data[p++] % 10) : 0;  // up to 10 glyphs
    cairo_glyph_t *glyphs = (cairo_glyph_t*)calloc(*num_glyphs, sizeof(cairo_glyph_t));
    if (!glyphs) { *num_glyphs = 0; return NULL; }

    for (int i = 0; i < *num_glyphs; i++) {
        glyphs[i].index = (p < size) ? data[p++] : 0;
        double x = read_double_at(data, size, &p) * WIDTH;   /* bias into canvas */
        double y = read_double_at(data, size, &p) * HEIGHT;
        glyphs[i].x = x;
        glyphs[i].y = y;
    }
    return glyphs;
}

static cairo_text_cluster_t *make_clusters(const uint8_t *data, size_t size, size_t seed_pos, int *num_clusters) {
    size_t p = seed_pos;
    *num_clusters = (p < size) ? (data[p++] % 4) : 0;
    cairo_text_cluster_t *clusters = (cairo_text_cluster_t*)calloc(*num_clusters, sizeof(cairo_text_cluster_t));
    if (!clusters) { *num_clusters = 0; return NULL; }

    for (int i = 0; i < *num_clusters; i++) {
        clusters[i].num_bytes  = (p < size) ? ((data[p++] % 4) + 1) : 1;
        clusters[i].num_glyphs = (p < size) ? ((data[p++] % 4) + 1) : 1;
    }
    return clusters;
}

static void read_matrix_from_bytes(cairo_matrix_t *m, const uint8_t *data, size_t size, size_t seed_pos) {
    size_t p = seed_pos;
    m->xx = read_double_at(data, size, &p) * 2.0;
    m->xy = read_double_at(data, size, &p) * 2.0;
    m->yx = read_double_at(data, size, &p) * 2.0;
    m->yy = read_double_at(data, size, &p) * 2.0;
    m->x0 = read_double_at(data, size, &p) * WIDTH;
    m->y0 = read_double_at(data, size, &p) * HEIGHT;
}

static cairo_font_face_t *make_font_face(const uint8_t *data, size_t size, size_t seed_pos) {
    static const char *families[] = {"Sans", "Serif", "Monospace"};
    size_t p = seed_pos;
    const char *family = families[(p < size) ? data[p++] % 3 : 0];
    cairo_font_slant_t slant  = (p < size) ? (data[p++] % 3) : CAIRO_FONT_SLANT_NORMAL;
    cairo_font_weight_t weight = (p < size) ? (data[p++] % 2) : CAIRO_FONT_WEIGHT_NORMAL;
    return cairo_toy_font_face_create(family, slant, weight);
}

/* ---------- backend selection (B: Recording, Image, PDF, SVG) ---------- */
static cairo_status_t null_write(void *closure, const unsigned char *data, unsigned int length) {
    (void)closure; (void)data; (void)length;
    return CAIRO_STATUS_SUCCESS;
}

static cairo_surface_t *create_pdf_surface_stream(double w, double h) {
#ifdef COVERAGE_BUILD
    /* Write to file for coverage builds */
    char path[256];
    snprintf(path, sizeof(path), "cairo_out/out_%d_%ld.pdf", (int)getpid(), (long)rand());
    return cairo_pdf_surface_create(path, w, h);
#else
    /* Stream that discards bytes */
    return cairo_pdf_surface_create_for_stream(null_write, NULL, w, h);
#endif
}

static cairo_surface_t *create_svg_surface_stream(double w, double h) {
#ifdef COVERAGE_BUILD
    char path[256];
    snprintf(path, sizeof(path), "cairo_out/out_%d_%ld.svg", (int)getpid(), (long)rand());
    return cairo_svg_surface_create(path, w, h);
#else
    return cairo_svg_surface_create_for_stream(null_write, NULL, w, h);
#endif
}

static cairo_surface_t *choose_backend_surface_B(const uint8_t **in, size_t *remaining,
                                                 double w, double h, backend_e *chosen) {
    /* derive selection from the first byte available */
    int sel = 0;
    if (*remaining > 0) {
        sel = (**in) % 4;
        *in += 1;
        *remaining -= 1;
    }
    if (chosen) *chosen = (backend_e)sel;

    switch (sel) {
        case BE_IMAGE:
            return cairo_image_surface_create(CAIRO_FORMAT_ARGB32, (int)w, (int)h);
        case BE_PDF:
            return create_pdf_surface_stream(w, h);
        case BE_SVG:
            return create_svg_surface_stream(w, h);
        case BE_RECORDING:
        default: {
            cairo_rectangle_t ext = {0, 0, w, h};
            return cairo_recording_surface_create(CAIRO_CONTENT_COLOR_ALPHA, &ext);
        }
    }
}

static char* read_string_at(const uint8_t *data, size_t size, size_t *off, size_t max) {
    size_t avail = size - *off;
    if (avail == 0) return strdup("X");
    if (max > avail) max = avail;
    char *s = malloc(max + 1);
    memcpy(s, data + *off, max);
    s[max] = 0;
    *off += max;
    return s;
}

/* ====================== LLVMFuzzerTestOneInput ====================== */

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || !data) return 0;

    const uint8_t *in = data;
    size_t remaining  = size;

    double w = WIDTH, h = HEIGHT;
    backend_e be = BE_RECORDING;
    cairo_surface_t *surface = choose_backend_surface_B(&in, &remaining, w, h, &be);
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

    /* neutral background */
    cairo_save(cr);
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_paint(cr);
    cairo_restore(cr);

    size_t max_ops = 2000;
    size_t ops = 0;
    size_t pos_seed = 0;

    while (remaining > 0 && ops++ < max_ops) {
        uint8_t op = *in++ % 61;
        remaining--;
#ifdef COVERAGE_BUILD
        fprintf(stderr, "Current operation: %u\n", op);
#endif

        switch (op) {
        case 0: {
            double x = pick_double_extreme(&in, &remaining);
            double y = pick_double_extreme(&in, &remaining);
            DEBUG_OP(op, "move_to(%.2f, %.2f)", x, y);
            cairo_move_to(cr, x, y);
            break;
        }
        case 1: {
            double x = pick_double_extreme(&in, &remaining);
            double y = pick_double_extreme(&in, &remaining);
            DEBUG_OP(op, "line_to(%.2f, %.2f)", x, y);
            cairo_line_to(cr, x, y);
            break;
        }
        case 2: {
            double x1 = pick_double_extreme(&in,&remaining);
            double y1 = pick_double_extreme(&in,&remaining);
            double x2 = pick_double_extreme(&in,&remaining);
            double y2 = pick_double_extreme(&in,&remaining);
            double x3 = pick_double_extreme(&in,&remaining);
            double y3 = pick_double_extreme(&in,&remaining);
            DEBUG_OP(op, "curve_to((%.2f,%.2f),(%.2f,%.2f),(%.2f,%.2f))", x1,y1,x2,y2,x3,y3);
            cairo_curve_to(cr, x1,y1,x2,y2,x3,y3);
            break;
        }
        case 3: {
            int dash_count = (abs(pick_int(&in,&remaining)) % 8) + 1;
            double dashes[8];
            for (int i = 0; i < dash_count; i++)
                dashes[i] = fabs(pick_double_unit(&in,&remaining)) * 20.0 + 0.1;
            double off = fabs(pick_double_unit(&in,&remaining)) * 10.0;
            DEBUG_OP(op, "set_dash(count=%d, off=%.2f)", dash_count, off);
            cairo_set_dash(cr, dashes, dash_count, off);
            break;
        }
        case 4: {
            double cx = pick_double_extreme(&in,&remaining);
            double cy = pick_double_extreme(&in,&remaining);
            double r  = clamp_pos(fabs(pick_double_unit(&in,&remaining)) * (WIDTH*0.5), 1.0);
            double a1 = pick_double(&in,&remaining) * 2 * M_PI;
            double a2 = pick_double(&in,&remaining) * 2 * M_PI;
            DEBUG_OP(op, "arc((%.2f,%.2f), r=%.2f, a1=%.2f, a2=%.2f)", cx,cy,r,a1,a2);
            cairo_arc(cr, cx, cy, r, a1, a2);
            break;
        }
        case 5: {
            double rx = pick_double_extreme(&in,&remaining);
            double ry = pick_double_extreme(&in,&remaining);
            double rw = fabs(pick_double_unit(&in,&remaining)) * WIDTH;
            double rh = fabs(pick_double_unit(&in,&remaining)) * HEIGHT;
            DEBUG_OP(op, "rectangle(%.2f,%.2f, %.2f×%.2f)", rx,ry,rw,rh);
            cairo_rectangle(cr, rx, ry, rw, rh);
            break;
        }
        case 6: {
            int which = pick_int(&in,&remaining) & 1;
            // DEBUG_OP(op, which ? "fill()" : "stroke()");
            if (which) cairo_fill(cr); else cairo_stroke(cr);
            break;
        }
        case 7: {
            double lw = fabs(pick_double_unit(&in,&remaining)) * 20.0 + 0.1;
            DEBUG_OP(op, "set_line_width(%.3f)", lw);
            cairo_set_line_width(cr, lw);
            break;
        }
        case 8: {
            int cap = abs(pick_int(&in,&remaining)) % 3;
            DEBUG_OP(op, "set_line_cap(%d)", cap);
            cairo_set_line_cap(cr, (cairo_line_cap_t)cap);
            break;
        }
        case 9: {
            int j = abs(pick_int(&in,&remaining)) % 3;
            DEBUG_OP(op, "set_line_join(%d)", j);
            cairo_set_line_join(cr, (cairo_line_join_t)j);
            break;
        }
        case 10: {
            double ml = fabs(pick_double_unit(&in,&remaining)) * 20.0 + 1.0;
            DEBUG_OP(op, "set_miter_limit(%.3f)", ml);
            cairo_set_miter_limit(cr, ml);
            break;
        }
        case 11: {
            int which = abs(pick_int(&in,&remaining)) % 3;
            if (which == 0) {
                double sx = pick_double_scale(&in,&remaining);
                double sy = pick_double_scale(&in,&remaining);
                DEBUG_OP(op, "scale(%.3f, %.3f)", sx, sy);
                cairo_scale(cr, sx, sy);
            } else if (which == 1) {
                double ang = pick_double(&in,&remaining);
                DEBUG_OP(op, "rotate(%.3f)", ang);
                cairo_rotate(cr, ang);
            } else {
                double tx = pick_double_extreme(&in,&remaining);
                double ty = pick_double_extreme(&in,&remaining);
                DEBUG_OP(op, "translate(%.2f, %.2f)", tx, ty);
                cairo_translate(cr, tx, ty);
            }
            break;
        }
        case 12: {
            int t = abs(pick_int(&in,&remaining)) % 3;
            if (t == 0) {
                double r = fabs(pick_double_unit(&in,&remaining));
                double g = fabs(pick_double_unit(&in,&remaining));
                double b = fabs(pick_double_unit(&in,&remaining));
                double a = fabs(pick_double_unit(&in,&remaining));
                DEBUG_OP(op, "set_source_rgba(%.2f,%.2f,%.2f,%.2f)", r,g,b,a);
                cairo_set_source_rgba(cr, r,g,b,a);
            } else if (t == 1) {
                double x0 = pick_double_extreme(&in,&remaining);
                double y0 = pick_double_extreme(&in,&remaining);
                double x1 = pick_double_extreme(&in,&remaining);
                double y1 = pick_double_extreme(&in,&remaining);
                cairo_pattern_t *p = cairo_pattern_create_linear(x0,y0,x1,y1);
                if (p) {
                    cairo_pattern_add_color_stop_rgba(p, 0, 1,0,0,1);
                    cairo_pattern_add_color_stop_rgba(p, 1, 0,1,0,1);
                }
                DEBUG_OP(op, "linear src ((%.1f,%.1f)->(%.1f,%.1f))", x0,y0,x1,y1);
                safe_set_source(cr, p);
            } else {
                double cx0 = pick_double_extreme(&in,&remaining);
                double cy0 = pick_double_extreme(&in,&remaining);
                double r0  = fabs(pick_double_unit(&in,&remaining)) * WIDTH * .25 + 1.0;
                double cx1 = pick_double_extreme(&in,&remaining);
                double cy1 = pick_double_extreme(&in,&remaining);
                double r1  = r0 + fabs(pick_double_unit(&in,&remaining)) * WIDTH * .25;
                cairo_pattern_t *p = cairo_pattern_create_radial(cx0,cy0,r0,cx1,cy1,r1);
                if (p) {
                    cairo_pattern_add_color_stop_rgba(p, 0, 0,1,0,1);
                    cairo_pattern_add_color_stop_rgba(p, 1, 1,1,0,1);
                }
                DEBUG_OP(op, "radial src c0=(%.1f,%.1f,r=%.1f) c1=(%.1f,%.1f,r=%.1f)", cx0,cy0,r0,cx1,cy1,r1);
                safe_set_source(cr, p);
            }
            break;
        }
        case 13: {
            double rx = pick_double_extreme(&in,&remaining);
            double ry = pick_double_extreme(&in,&remaining);
            double rw = fabs(pick_double_unit(&in,&remaining)) * WIDTH;
            double rh = fabs(pick_double_unit(&in,&remaining)) * HEIGHT;
            DEBUG_OP(op, "clip rect (%.1f,%.1f, %.1f×%.1f)", rx,ry,rw,rh);
            cairo_save(cr);
            cairo_rectangle(cr, rx, ry, rw, rh);
            cairo_clip(cr);
            if ((ops % 7) == 0) cairo_reset_clip(cr);
            cairo_restore(cr);
            break;
        }
        case 14: {
            char *s = pick_string(&in,&remaining);
            int slant  = abs(pick_int(&in,&remaining)) % 3;
            int weight = abs(pick_int(&in,&remaining)) % 2;
            double sizev = fabs(pick_double_unit(&in,&remaining)) * 80.0 + 1.0;
            double x = pick_double_extreme(&in,&remaining);
            double y = pick_double_extreme(&in,&remaining);
            DEBUG_OP(op, "text '%s' size=%.1f slant=%d weight=%d at (%.1f,%.1f)", s,sizev,slant,weight,x,y);
            cairo_select_font_face(cr, s, (cairo_font_slant_t)slant, (cairo_font_weight_t)weight);
            cairo_set_font_size(cr, sizev);
            cairo_move_to(cr, x, y);
            if (pick_int(&in,&remaining) & 1) cairo_show_text(cr, s);
            else { cairo_text_path(cr, s); cairo_fill(cr); }
            free(s);
            break;
        }
        case 15: {
            cairo_font_options_t *opts = cairo_font_options_create();
            cairo_font_options_set_hint_style  (opts, abs(pick_int(&in,&remaining)) % 5);
            cairo_font_options_set_hint_metrics(opts, abs(pick_int(&in,&remaining)) % 3);
            DEBUG_OP(op, "font_options set");
            cairo_set_font_options(cr, opts);
            cairo_font_options_destroy(opts);
            break;
        }
        case 16: {
            int ptype = abs(pick_int(&in,&remaining)) % 5;
            cairo_pattern_t *p = NULL;
            if (ptype == 0) {
                p = cairo_pattern_create_rgb(fabs(pick_double_unit(&in,&remaining)),
                                             fabs(pick_double_unit(&in,&remaining)),
                                             fabs(pick_double_unit(&in,&remaining)));
            } else if (ptype == 1) {
                p = cairo_pattern_create_rgba(fabs(pick_double_unit(&in,&remaining)),
                                              fabs(pick_double_unit(&in,&remaining)),
                                              fabs(pick_double_unit(&in,&remaining)),
                                              fabs(pick_double_unit(&in,&remaining)));
            } else if (ptype == 2) {
                double x0 = pick_double_extreme(&in,&remaining);
                double y0 = pick_double_extreme(&in,&remaining);
                double x1 = pick_double_extreme(&in,&remaining);
                double y1 = pick_double_extreme(&in,&remaining);
                p = cairo_pattern_create_linear(x0,y0,x1,y1);
                if (p) {
                    int stops = (abs(pick_int(&in,&remaining)) % 3) + 1;
                    for (int i = 0; i < stops; i++) {
                        double t = (stops > 1) ? ((double)i/(stops-1)) : 0.0;
                        cairo_pattern_add_color_stop_rgba(p, t,
                            fabs(pick_double_unit(&in,&remaining)),
                            fabs(pick_double_unit(&in,&remaining)),
                            fabs(pick_double_unit(&in,&remaining)),
                            fabs(pick_double_unit(&in,&remaining)));
                    }
                }
            } else if (ptype == 3) {
                double cx0 = pick_double_extreme(&in,&remaining);
                double cy0 = pick_double_extreme(&in,&remaining);
                double r0  = fabs(pick_double_unit(&in,&remaining)) * (WIDTH*.25) + 1.0;
                double cx1 = pick_double_extreme(&in,&remaining);
                double cy1 = pick_double_extreme(&in,&remaining);
                double r1  = r0 + fabs(pick_double_unit(&in,&remaining)) * (WIDTH*.25);
                p = cairo_pattern_create_radial(cx0,cy0,r0,cx1,cy1,r1);
                if (p) {
                    int stops = (abs(pick_int(&in,&remaining)) % 3) + 1;
                    for (int i = 0; i < stops; i++) {
                        double t = (stops > 1) ? ((double)i/(stops-1)) : 0.0;
                        cairo_pattern_add_color_stop_rgba(p, t,
                            fabs(pick_double_unit(&in,&remaining)),
                            fabs(pick_double_unit(&in,&remaining)),
                            fabs(pick_double_unit(&in,&remaining)),
                            fabs(pick_double_unit(&in,&remaining)));
                    }
                }
            } else {
                cairo_surface_t *img = make_small_image_surface();
                if (img) {
                    p = cairo_pattern_create_for_surface(img);
                    cairo_surface_destroy(img);
                }
            }

            if (p) {
                cairo_matrix_t m = rand_matrix(&in,&remaining);
                cairo_pattern_set_matrix(p, &m);
                cairo_pattern_set_extend(p, (cairo_extend_t)(abs(pick_int(&in,&remaining)) % 4));
                cairo_pattern_set_filter(p, (cairo_filter_t)(abs(pick_int(&in,&remaining)) % 5));
                DEBUG_OP(op, "pattern created type=%d", ptype);
                cairo_pattern_destroy(p);
            }
            break;
        }
        case 17: {
            cairo_pattern_t *mesh = cairo_pattern_create_mesh();
            if (!mesh) break;
            int patches = (abs(pick_int(&in,&remaining)) % (MAX_PATCHES+1)) + MIN_PATCHES;
            for (int p = 0; p < patches && remaining > 0; p++) {
                cairo_mesh_pattern_begin_patch(mesh);
                cairo_mesh_pattern_move_to(mesh,
                    pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining));
                int curves = abs(pick_int(&in,&remaining)) % (MAX_CURVES+1);
                for (int i = 0; i < curves; i++) {
                    cairo_mesh_pattern_curve_to(mesh,
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
                }
                for (int c = 0; c < 4; c++) {
                    cairo_mesh_pattern_set_corner_color_rgba(mesh, c,
                        fabs(pick_double_unit(&in,&remaining)),
                        fabs(pick_double_unit(&in,&remaining)),
                        fabs(pick_double_unit(&in,&remaining)),
                        fabs(pick_double_unit(&in,&remaining)));
                }
                cairo_mesh_pattern_end_patch(mesh);
            }

            cairo_surface_t *img = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 64, 64);
            cairo_t *tmp = cairo_create(img);
            cairo_set_operator(tmp, (cairo_operator_t)(abs(pick_int(&in,&remaining)) % (MAX_CAIRO_OPERATOR+1)));
            cairo_set_source(tmp, mesh);
            cairo_paint_with_alpha(tmp, fabs(pick_double_unit(&in,&remaining)));
            cairo_destroy(tmp);
            cairo_surface_destroy(img);
            cairo_pattern_destroy(mesh);
            DEBUG_OP(op, "mesh pattern drawn");
            break;
        }
        case 18: {
            cairo_pattern_t *p = cairo_pattern_create_linear(0,0,10,10);
            if (p) {
                cairo_pattern_add_color_stop_rgba(p, 0, .1,.2,.3,1);
                cairo_pattern_add_color_stop_rgba(p, 1, .9,.8,.7,1);
                cairo_matrix_t mm = rand_matrix(&in,&remaining);
                cairo_pattern_set_matrix(p, &mm);
                cairo_pattern_set_extend(p, CAIRO_EXTEND_REPEAT);
                safe_set_source(cr, cairo_pattern_reference(p));
                cairo_pattern_destroy(p);
            }
            break;
        }
        case 19: {
            cairo_pattern_t *p = cairo_pattern_create_rgba(
                fabs(pick_double_unit(&in,&remaining)),
                fabs(pick_double_unit(&in,&remaining)),
                fabs(pick_double_unit(&in,&remaining)),
                fabs(pick_double_unit(&in,&remaining)));
            if (p) {
                double r,g,b,a;
                cairo_pattern_get_rgba(p, &r,&g,&b,&a);
                cairo_pattern_destroy(p);
            }
            cairo_surface_t *img = make_small_image_surface();
            if (img) {
                cairo_pattern_t *ps = cairo_pattern_create_for_surface(img);
                int destroyed = 0;
                if (ps) {
                    cairo_surface_t *out = NULL;
                    cairo_pattern_get_surface(ps, &out);
                    if (out) {
                        destroyed = 1;
                        cairo_surface_destroy(out);
                    }
                    cairo_pattern_destroy(ps);
                }
                if (!destroyed) {
                    cairo_surface_destroy(img);
                }
                // Originally this was here, but this caused UAF
                // cairo_surface_destroy(img);
            }
            break;
        }
        case 20: {
            double dx = pick_double_extreme(&in,&remaining);
            double dy = pick_double_extreme(&in,&remaining);
            DEBUG_OP(op, "rel_move_to(%.2f, %.2f)", dx, dy);
            cairo_rel_move_to(cr, dx, dy);
            break;
        }
        case 21: {
            int reps = (abs(pick_int(&in,&remaining)) % 100) + 50;
            DEBUG_OP(op, "rel_line_to reps=%d", reps);
            for (int i = 0; i < reps && remaining > 0; i++) {
                cairo_rel_line_to(cr,
                    pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining));
            }
            break;
        }
        case 22: {
            int reps = (abs(pick_int(&in,&remaining)) % 50) + 10;
            DEBUG_OP(op, "rel_curve_to reps=%d", reps);
            for (int i = 0; i < reps && remaining > 0; i++) {
                cairo_rel_curve_to(cr,
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            }
            break;
        }
        case 23:
            DEBUG_OP(op, "close_path + (fill_preserve?) + stroke");
            cairo_close_path(cr);
            if (pick_int(&in,&remaining) & 1) cairo_fill_preserve(cr);
            cairo_stroke(cr);
            break;
        case 24: {
            cairo_push_group(cr);
            int n = (abs(pick_int(&in,&remaining)) % 20) + 5;
            for (int i = 0; i < n; i++) {
                cairo_line_to(cr,
                    pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining));
            }
            cairo_pop_group_to_source(cr);
            cairo_paint_with_alpha(cr, fabs(pick_double_unit(&in,&remaining)));
            break;
        }
        case 25: {
            cairo_surface_t *img = make_small_image_surface();
            if (img) {
                double x = pick_double_extreme(&in,&remaining);
                double y = pick_double_extreme(&in,&remaining);
                DEBUG_OP(op, "mask_surface at (%.1f,%.1f)", x,y);
                cairo_mask_surface(cr, img, x, y);
                cairo_surface_destroy(img);
            }
            break;
        }
        case 26:
            cairo_set_fill_rule(cr, (cairo_fill_rule_t)(abs(pick_int(&in,&remaining)) % 2));
            cairo_fill_preserve(cr);
            break;
        case 27: {
            double cx = pick_double_extreme(&in,&remaining);
            double cy = pick_double_extreme(&in,&remaining);
            double r  = fabs(pick_double_unit(&in,&remaining)) * 30.0 + 3.0;
            cairo_arc(cr, cx, cy, r, 0, 2*M_PI);
            cairo_clip_preserve(cr);
            cairo_stroke(cr);
            break;
        }
        case 28: {
            cairo_path_t *p = cairo_copy_path(cr);
            if (p) {
                cairo_new_path(cr);
                cairo_append_path(cr, p);
                cairo_path_destroy(p);
            }
            break;
        }
        case 29:
            cairo_set_operator(cr, (cairo_operator_t)(abs(pick_int(&in,&remaining)) % (MAX_CAIRO_OPERATOR+1)));
            break;
        case 30: {
            cairo_region_t *r1 = cairo_region_create();
            cairo_region_t *r2 = cairo_region_create();
            for (int i = 0; i < 8 && remaining > 0; i++) {
                cairo_rectangle_int_t rect = {
                    abs(pick_int(&in,&remaining)) % 500,
                    abs(pick_int(&in,&remaining)) % 500,
                    (abs(pick_int(&in,&remaining)) % 200) + 1,
                    (abs(pick_int(&in,&remaining)) % 200) + 1
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
        case 31:
            cairo_push_group(cr);
            break;
        case 32:
            cairo_pop_group_to_source(cr);
            cairo_paint_with_alpha(cr, fabs(pick_double_unit(&in,&remaining)));
            break;
        case 33:
            cairo_set_antialias(cr, (cairo_antialias_t)(abs(pick_int(&in,&remaining)) % 5));
            break;
        case 34:
            cairo_set_operator(cr, (cairo_operator_t)(abs(pick_int(&in,&remaining)) % (MAX_CAIRO_OPERATOR+1)));
            break;
        case 35: {
            double x = pick_double_extreme(&in,&remaining);
            double y = pick_double_extreme(&in,&remaining);
            double rw = fabs(pick_double_unit(&in,&remaining)) * WIDTH;
            double rh = fabs(pick_double_unit(&in,&remaining)) * HEIGHT;
            cairo_rectangle(cr, x,y,rw,rh);
            cairo_clip(cr);
            if (pick_int(&in,&remaining) & 1) cairo_reset_clip(cr);
            break;
        }
        case 36: {
            cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
            cairo_set_font_size(cr, (fabs(pick_double_unit(&in,&remaining))+1.0)*12.0);
            cairo_move_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            static const char *words[] = {"cairo","SVG","RGBA","mesh","recording"};
            cairo_show_text(cr, words[abs(pick_int(&in,&remaining)) % 5]);
            break;
        }
        case 37:
            cairo_stroke_preserve(cr);
            cairo_fill(cr);
            break;
        case 38: {
            cairo_surface_t *img = make_small_image_surface();
            if (img) {
                cairo_pattern_t *p = cairo_pattern_create_for_surface(img);
                cairo_mask(cr, p);
                cairo_pattern_destroy(p);
                cairo_surface_destroy(img);
            }
            break;
        }
        case 39: {
            cairo_matrix_t m = rand_matrix(&in,&remaining);
            cairo_set_matrix(cr, &m);
            break;
        }
        case 40: {
            cairo_matrix_t m;
            cairo_get_matrix(cr, &m);
            cairo_matrix_invert(&m);
            cairo_set_matrix(cr, &m);
            break;
        }
        case 41:
            cairo_new_path(cr);
            break;
        case 42:
            cairo_new_sub_path(cr);
            break;
        case 43: {
            double x1,y1,x2,y2;
            cairo_fill_extents(cr, &x1,&y1,&x2,&y2);
            (void)x1;(void)y1;(void)x2;(void)y2;
            break;
        }
        case 44: {
            double x1,y1,x2,y2;
            cairo_stroke_extents(cr, &x1,&y1,&x2,&y2);
            (void)x1;(void)y1;(void)x2;(void)y2;
            break;
        }
        case 45:
            cairo_set_tolerance(cr, fabs(pick_double_unit(&in,&remaining)) * 10.0 + 1e-6);
            break;
        case 46:
            cairo_paint(cr);
            break;
        case 47: {
            cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
            cairo_move_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            cairo_line_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            cairo_clip(cr);
            cairo_set_antialias(cr, CAIRO_ANTIALIAS_DEFAULT);
            cairo_move_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            cairo_line_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
            cairo_clip(cr);
            break;
        }
        case 48: {
            cairo_font_extents_t fe;
            cairo_font_extents(cr, &fe);
            break;
        }
        case 49: {
            cairo_text_extents_t te;
            cairo_text_extents(cr, "cairo", &te);
            break;
        }
        case 50: {
            int iw = (abs(pick_int(&in,&remaining)) % 256) + 1;
            int ih = (abs(pick_int(&in,&remaining)) % 256) + 1;
            int fmt_sel = abs(pick_int(&in,&remaining)) % 3;
            cairo_format_t fmt = (fmt_sel==1) ? CAIRO_FORMAT_RGB24
                               : (fmt_sel==2) ? CAIRO_FORMAT_A8
                                              : CAIRO_FORMAT_ARGB32;
            cairo_surface_t *img = cairo_image_surface_create(fmt, iw, ih);
            if (img && cairo_surface_status(img) == CAIRO_STATUS_SUCCESS) {
                fill_image_with_fuzz(img, &in, &remaining);
                cairo_surface_t *sim = cairo_surface_create_similar_image(img, fmt,
                                            iw > 16 ? iw/2 : iw,
                                            ih > 16 ? ih/2 : ih);
                if (sim && cairo_surface_status(sim) == CAIRO_STATUS_SUCCESS) {
                    fill_image_with_fuzz(sim, &in, &remaining);
                    cairo_surface_destroy(sim);
                }
                cairo_pattern_t *ps = cairo_pattern_create_for_surface(img);
                if (ps) {
                    cairo_matrix_t mm = rand_matrix(&in,&remaining);
                    cairo_pattern_set_matrix(ps, &mm);
                    cairo_pattern_set_extend(ps, (cairo_extend_t)(abs(pick_int(&in,&remaining)) % 4));
                    cairo_pattern_set_filter(ps, (cairo_filter_t)(abs(pick_int(&in,&remaining)) % 5));
                    safe_set_source(cr, cairo_pattern_reference(ps));
                    cairo_paint_with_alpha(cr, fabs(pick_double_unit(&in,&remaining)));
                    cairo_set_source_surface(cr, img,
                        pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining));
                    cairo_paint_with_alpha(cr, fabs(pick_double_unit(&in,&remaining)));
                    cairo_pattern_destroy(ps);
                }
                if (pick_int(&in,&remaining) & 1) {
                    (void)cairo_image_surface_get_data(img);
                }
                cairo_surface_destroy(img);
            } else if (img) {
                cairo_surface_destroy(img);
            }
            break;
        }

        /* --- newly added cairo text & tag APIs and clip queries --- */
        case 51: { /* cairo_set_font_matrix */
            cairo_matrix_t M;
            read_matrix_from_bytes(&M, data, size, size - remaining);
            DEBUG_OP(op, "set_font_matrix([%.2f %.2f; %.2f %.2f | %.2f %.2f])",
                     M.xx, M.xy, M.yx, M.yy, M.x0, M.y0);
            cairo_set_font_matrix(cr, &M);
            break;
        }
        case 52: { /* cairo_set_font_face */
            cairo_font_face_t *face = make_font_face(data, size, size - remaining);
            DEBUG_OP(op, "set_font_face()");
            cairo_set_font_face(cr, face);
            cairo_font_face_destroy(face);
            break;
        }
        case 53: { /* cairo_glyph_path */
            int n = 0;
            cairo_glyph_t *glyphs = make_glyphs(data, size, size - remaining, &n);
            DEBUG_OP(op, "glyph_path n=%d", n);
            cairo_glyph_path(cr, glyphs, n);
            free(glyphs);
            break;
        }
        case 54: { /* cairo_glyph_extents */
            cairo_text_extents_t extents;
            int n = 0;
            cairo_glyph_t *glyphs = make_glyphs(data, size, size - remaining, &n);
            DEBUG_OP(op, "glyph_extents n=%d", n);
            cairo_glyph_extents(cr, glyphs, n, &extents);
            free(glyphs);
            break;
        }
        case 55: { /* cairo_show_text_glyphs */
            int num_glyphs = 0, num_clusters = 0;
            cairo_glyph_t *glyphs = make_glyphs(data, size, size - remaining, &num_glyphs);
            cairo_text_cluster_t *clusters = make_clusters(data, size, size - remaining, &num_clusters);
            size_t tmp = size - remaining;
            char *utf8 = read_string_at(data, size, &tmp, 32);
            cairo_text_cluster_flags_t flags = (data[(size - remaining) % size] & 1)
                                                ? CAIRO_TEXT_CLUSTER_FLAG_BACKWARD
                                                : 0;
            DEBUG_OP(op, "show_text_glyphs ng=%d nc=%d str='%s' flags=%d",
                     num_glyphs, num_clusters, utf8, (int)flags);
            cairo_show_text_glyphs(cr,
                                   utf8, (int)strlen(utf8),
                                   glyphs, num_glyphs,
                                   clusters, num_clusters,
                                   flags);
            free(utf8);
            free(glyphs);
            free(clusters);
            break;
        }
        case 56: { /* cairo_tag_begin */
            size_t p = size - remaining;
            char *tag   = read_string_at(data, size, &p, 16);
            char *attrs = read_string_at(data, size, &p, 64);
            DEBUG_OP(op, "tag_begin '%s' attrs='%s'", tag, attrs);
            cairo_tag_begin(cr, tag, attrs);
            free(tag);
            free(attrs);
            break;
        }
        case 57: { /* cairo_tag_end */
            size_t p = size - remaining;
            char *tag = read_string_at(data, size, &p, 16);
            DEBUG_OP(op, "tag_end '%s'", tag);
            cairo_tag_end(cr, tag);
            free(tag);
            break;
        }
        case 58: { /* cairo_clip_extents */
            double x1=0,y1=0,x2=0,y2=0;
            cairo_clip_extents(cr, &x1,&y1,&x2,&y2);
            DEBUG_OP(op, "clip_extents => [%.1f %.1f %.1f %.1f]", x1,y1,x2,y2);
            break;
        }
        case 59: { /* cairo_in_clip */
            double x = pick_double_extreme(&in,&remaining);
            double y = pick_double_extreme(&in,&remaining);
            cairo_bool_t inside = cairo_in_clip(cr, x, y);
            DEBUG_OP(op, "in_clip(%.1f,%.1f) => %d", x, y, (int)inside);
            break;
        }
        case 60: { /* cairo_copy_clip_rectangle_list */
            cairo_rectangle_list_t *list = cairo_copy_clip_rectangle_list(cr);
            DEBUG_OP(op, "copy_clip_rectangle_list n=%d status=%d",
                     list ? list->num_rectangles : -1,
                     list ? list->status : -1);
            cairo_rectangle_list_destroy(list);
            break;
        }

        default:
            /* no-op */
            break;
        } /* switch */
        pos_seed++;
    } /* while ops */

#ifdef COVERAGE_BUILD
    /* For recording surface, rasterize to PNG to visualize. */
    if (be == BE_RECORDING) {
        fprintf(stderr, "Trying this file here: %s\n", current_file);
        int iw = (int)ceil(w), ih = (int)ceil(h);
        cairo_surface_t *img = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, iw, ih);
        if (img && cairo_surface_status(img) == CAIRO_STATUS_SUCCESS) {
            cairo_t *out = cairo_create(img);
            if (out && cairo_status(out) == CAIRO_STATUS_SUCCESS) {
                cairo_set_source_surface(out, surface, 0.0, 0.0);
                cairo_paint(out);
                cairo_surface_flush(img);
                char fname[256];
                snprintf(fname, sizeof(fname),
                         "cairo_out/cairo_fuzz_out_%d_%ld.png",
                         (int)getpid(), (long)rand());
                cairo_surface_write_to_png(img, fname);
                cairo_destroy(out);
            } else if (out) {
                cairo_destroy(out);
            }
            cairo_surface_destroy(img);
        }
    }
#endif

    /* finish vector surfaces to flush objects */
    if (be == BE_PDF || be == BE_SVG) {
        cairo_show_page(cr);
        cairo_surface_flush(surface);
        cairo_surface_finish(surface);
    }

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