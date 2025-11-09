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

    size_t len = (*remaining % 64); // + 1; // originally had + 1 but that caused an off-by-one crash...
    // fprintf(stderr, "len: %d\n", len);
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
    if (cairo_pattern_status(p) == CAIRO_STATUS_SUCCESS)
        cairo_set_source(cr, p);
    cairo_pattern_destroy(p);
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
        uint8_t op = *in++ % 16;      // now 0..15
        // fprintf(stderr, "op: %d\n", op);
        remaining--;

        switch (op) {
        case 0: cairo_move_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining)); break;
        case 1: cairo_line_to(cr, pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining)); break;
        case 2: cairo_curve_to(cr,
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining)); break;

        case 3: {
            int dash_count = (abs(pick_int(&in,&remaining)) % 8) + 1;
            double dashes[8];
            for (int i=0;i<dash_count;i++) dashes[i] = fabs(pick_double_extreme(&in,&remaining));
            cairo_set_dash(cr, dashes, dash_count, pick_double_extreme(&in,&remaining));
            break;
        }

        case 4: cairo_arc(cr,
                pick_double(&in,&remaining), pick_double(&in,&remaining),
                clamp_pos(pick_double_extreme(&in,&remaining), 1.0),
                pick_double(&in,&remaining)*2*M_PI, pick_double(&in,&remaining)*2*M_PI); break;

        case 5: cairo_rectangle(cr,
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining)); break;

        case 6: (pick_int(&in,&remaining)&1) ? cairo_fill(cr) : cairo_stroke(cr); break;

        case 7: cairo_set_line_width(cr, clamp_pos(fabs(pick_double_extreme(&in,&remaining)), .5)); break;
        case 8: cairo_set_line_cap(cr, abs(pick_int(&in,&remaining)) % 3); break;
        case 9: cairo_set_line_join(cr, abs(pick_int(&in,&remaining)) % 3); break;
        case 10: cairo_set_miter_limit(cr, clamp_pos(fabs(pick_double_extreme(&in,&remaining)),1.0)); break;

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
            cairo_rectangle(cr,pick_double_extreme(&in,&remaining),pick_double_extreme(&in,&remaining),
                                 pick_double_extreme(&in,&remaining),pick_double_extreme(&in,&remaining));
            cairo_clip(cr);
            if ((ops % 7) == 0) cairo_reset_clip(cr);
            cairo_restore(cr);
            break;
        }

        /* ✨ New: font / text + cairo_text_path fuzzing */
        case 14: {
            char *s = pick_string(&in,&remaining);

            cairo_select_font_face(cr,
                s,                                   // fuzz font face name
                abs(pick_int(&in,&remaining)) % 3,   // slant
                abs(pick_int(&in,&remaining)) % 2);  // weight

            cairo_set_font_size(cr,
                clamp_pos(fabs(pick_double_extreme(&in,&remaining)) * 50.0, 1.0));

            cairo_move_to(cr,
                pick_double_extreme(&in,&remaining),
                pick_double_extreme(&in,&remaining));

            if (pick_int(&in,&remaining) & 1)
                cairo_show_text(cr, s);  // normal text
            else {
                cairo_text_path(cr, s);  // path-based
                cairo_fill(cr);
            }

            free(s);
            break;
        }

        /* ✨ New: fuzz cairo_font_options like the official test */
        case 15: {
            cairo_font_options_t *opts = cairo_font_options_create();
            cairo_font_options_set_hint_style   (opts, abs(pick_int(&in,&remaining)) % 5);
            cairo_font_options_set_hint_metrics (opts, abs(pick_int(&in,&remaining)) % 3);
            cairo_set_font_options(cr, opts);
            cairo_font_options_destroy(opts);
            break;
        }

        } // switch

        if ((ops % 11) == 0) cairo_new_path(cr);
        if ((ops % 17) == 0) { cairo_save(cr); cairo_restore(cr); }
        if ((ops % 29) == 0) cairo_identity_matrix(cr);

        if (cairo_status(cr) != CAIRO_STATUS_SUCCESS)
            break;
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