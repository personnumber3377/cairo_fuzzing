// fuzz/cairo_stateful_fuzzer.c
#define _GNU_SOURCE
#include <cairo.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <stdio.h>

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
        case 3: return v * 1e300;   // huge
        case 4: return v / 1e300;   // tiny/subnormal
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

static inline void safe_set_source(cairo_t *cr, cairo_pattern_t *p) {
    if (!p) return;
    cairo_status_t ps = cairo_pattern_status(p);
    if (ps == CAIRO_STATUS_SUCCESS) {
        cairo_set_source(cr, p);
    }
    cairo_pattern_destroy(p);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;

    const uint8_t *in = data;
    size_t remaining = size;

    // Dimensions from input (optional) so recording bounds (when later replayed)
    // are reasonable; otherwise NULL extents = unbounded recording.
    double w = 500.0, h = 500.0;
    /*
    if (remaining >= 16) {
        union { uint64_t u; double d; } u1 = {0}, u2 = {0};
        memcpy(&u1.u, in, 8); in += 8; remaining -= 8;
        memcpy(&u2.u, in, 8); in += 8; remaining -= 8;
        w = clamp_dim(u1.d);
        h = clamp_dim(u2.d);
    }
    */

    // Use a recording surface to avoid backend runtime deps.
    cairo_rectangle_t ext = {0, 0, w, h};
    cairo_surface_t *surface =
        cairo_recording_surface_create(CAIRO_CONTENT_COLOR_ALPHA, &ext);

    if (!surface) return 0;

    /*
    // Guard against Cairo's error-surface trick (tiny fake pointers)
    if (cairo_surface_get_type(surface) == CAIRO_SURFACE_TYPE_NULL) {
        cairo_surface_destroy(surface);
        return 0;
    }
    */

    cairo_status_t ss = cairo_surface_status(surface);
    if (ss != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surface);
        return 0;
    }

    cairo_t *cr = cairo_create(surface);
    if (!cr) {
        cairo_surface_destroy(surface);
        return 0;
    }
    cairo_status_t cs = cairo_status(cr);
    if (cs != CAIRO_STATUS_SUCCESS) {
        cairo_destroy(cr);
        cairo_surface_destroy(surface);
        return 0;
    }

    // Start with white background (recording surface will record ops)
    cairo_save(cr);
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);
    cairo_restore(cr);

    // Bound total ops so one huge input can't hang forever.
    size_t max_ops = 2000;
    size_t ops = 0;

    while (remaining > 0 && ops++ < max_ops) {
        uint8_t op = *in++ % 15; // 0..14
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
        case 3: { // dashed stroke
            int dash_count = (abs(pick_int(&in, &remaining)) % 8) + 1;
            double dashes[8];
            for (int i = 0; i < dash_count; i++) {
                // Cairo allows zero/negatives but we bias positive for coverage
                dashes[i] = fabs(pick_double_extreme(&in, &remaining));
            }
            double offset = pick_double_extreme(&in, &remaining);
            cairo_set_dash(cr, dashes, dash_count, offset);
            break;
        }
        case 4: { // arc
            double cx = pick_double(&in, &remaining);
            double cy = pick_double(&in, &remaining);
            double r  = clamp_pos(pick_double_extreme(&in, &remaining), 1.0);
            double a1 = pick_double(&in, &remaining) * 2 * M_PI;
            double a2 = pick_double(&in, &remaining) * 2 * M_PI;
            cairo_arc(cr, cx, cy, r, a1, a2);
            break;
        }
        case 5: { // rectangle
            double x = pick_double_extreme(&in, &remaining);
            double y = pick_double_extreme(&in, &remaining);
            double rw = pick_double_extreme(&in, &remaining);
            double rh = pick_double_extreme(&in, &remaining);
            // Cairo allows negative width/height to draw “nothing” – keep it for variety
            cairo_rectangle(cr, x, y, rw, rh);
            break;
        }
        case 6: { // fill or stroke
            if (pick_int(&in, &remaining) & 1) cairo_fill(cr);
            else                                cairo_stroke(cr);
            break;
        }
        case 7: { // line width
            double lw = clamp_pos(fabs(pick_double_extreme(&in, &remaining)), 0.5);
            cairo_set_line_width(cr, lw);
            break;
        }
        case 8: { // line cap
            cairo_set_line_cap(cr, abs(pick_int(&in, &remaining)) % 3);
            break;
        }
        case 9: { // line join
            cairo_set_line_join(cr, abs(pick_int(&in, &remaining)) % 3);
            break;
        }
        case 10: { // miter limit
            double ml = clamp_pos(fabs(pick_double_extreme(&in, &remaining)), 1.0);
            cairo_set_miter_limit(cr, ml);
            break;
        }
        case 11: { // random transform
            int r = abs(pick_int(&in, &remaining)) % 3;
            switch (r) {
                case 0: cairo_scale(cr,
                           pick_double_extreme(&in, &remaining),
                           pick_double_extreme(&in, &remaining)); break;
                case 1: cairo_rotate(cr, pick_double_extreme(&in, &remaining)); break;
                case 2: cairo_translate(cr,
                           pick_double_extreme(&in, &remaining),
                           pick_double_extreme(&in, &remaining)); break;
            }
            break;
        }
        case 12: { // solid or gradient source
            int t = abs(pick_int(&in, &remaining)) % 3;
            if (t == 0) {
                cairo_set_source_rgba(cr,
                    fabs(pick_double(&in, &remaining)),
                    fabs(pick_double(&in, &remaining)),
                    fabs(pick_double(&in, &remaining)),
                    fabs(pick_double(&in, &remaining)));
            } else if (t == 1) {
                cairo_pattern_t *p = cairo_pattern_create_linear(
                    pick_double_extreme(&in, &remaining), pick_double_extreme(&in, &remaining),
                    pick_double_extreme(&in, &remaining), pick_double_extreme(&in, &remaining));
                if (p) {
                    cairo_pattern_add_color_stop_rgba(p, 0, 1, 0, 0, 1);
                    cairo_pattern_add_color_stop_rgba(p, 1, 0, 0, 1, 1);
                }
                safe_set_source(cr, p);
            } else {
                double x0 = pick_double_extreme(&in, &remaining);
                double y0 = pick_double_extreme(&in, &remaining);
                double r0 = clamp_pos(pick_double_extreme(&in, &remaining), 1.0);
                double x1 = pick_double_extreme(&in, &remaining);
                double y1 = pick_double_extreme(&in, &remaining);
                double r1 = clamp_pos(pick_double_extreme(&in, &remaining), 2.0);
                cairo_pattern_t *p = cairo_pattern_create_radial(x0, y0, r0, x1, y1, r1);
                if (p) {
                    cairo_pattern_add_color_stop_rgba(p, 0, 0, 1, 0, 1);
                    cairo_pattern_add_color_stop_rgba(p, 1, 1, 1, 0, 1);
                }
                safe_set_source(cr, p);
            }
            break;
        }
        case 13: { // clipping
            cairo_save(cr);
            cairo_rectangle(cr,
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining));
            cairo_clip(cr);
            // keep clip for a bit then maybe reset
            if ((ops % 7) == 0) cairo_reset_clip(cr);
            cairo_restore(cr);
            break;
        }
        case 14: { // text rendering
            cairo_select_font_face(cr, "Sans",
                CAIRO_FONT_SLANT_NORMAL,
                CAIRO_FONT_WEIGHT_BOLD);
            double sz = clamp_pos(fabs(pick_double_extreme(&in, &remaining)) * 50.0, 1.0);
            cairo_set_font_size(cr, sz);
            cairo_move_to(cr,
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining));
            cairo_show_text(cr, "FUZZ");
            break;
        }
        } // switch

        // Light hygiene to avoid pathological states accumulating forever
        if ((ops % 11) == 0) cairo_new_path(cr);
        if ((ops % 17) == 0) { cairo_save(cr); cairo_restore(cr); }
        if ((ops % 29) == 0) cairo_identity_matrix(cr);

        // Optional: early-out if context goes bad (keeps fuzzer moving)
        cairo_status_t cur = cairo_status(cr);
        if (cur != CAIRO_STATUS_SUCCESS) break;
    }

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    return 0;
}

/* ----------------- coverage runner (unchanged idea) ----------------- */
#ifdef COVERAGE_BUILD
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

static int process_file(const char *path) {
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
    LLVMFuzzerTestOneInput(buf, (size_t)off);
    free(buf); close(fd); return 0;
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
    if (argc < 2) {
        uint8_t buf[4096];
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