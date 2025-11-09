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
        uint8_t op = *in++ % 30;
        remaining--;

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

        case 17: {
            cairo_pattern_t *mesh = cairo_pattern_create_mesh();
            if (!mesh) break;

            int patches = (abs(pick_int(&in,&remaining)) % 3) + 1;   // 1-3 patches

            for (int p = 0; p < patches && remaining > 0; p++) {

                cairo_mesh_pattern_begin_patch(mesh);

                // random starting point
                cairo_mesh_pattern_move_to(mesh,
                    pick_double_extreme(&in,&remaining),
                    pick_double_extreme(&in,&remaining));

                // add 3–6 curve segments
                int curves = (abs(pick_int(&in,&remaining)) % 4) + 3;
                for (int i=0; i < curves; i++) {
                    cairo_mesh_pattern_curve_to(mesh,
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining),
                        pick_double_extreme(&in,&remaining), pick_double_extreme(&in,&remaining));
                }

                // set corner colors
                for (int corner=0; corner < 4; corner++) {
                    if (pick_int(&in,&remaining) & 1)
                        cairo_mesh_pattern_set_corner_color_rgb(mesh,
                            corner,
                            fabs(pick_double(&in,&remaining)),
                            fabs(pick_double(&in,&remaining)),
                            fabs(pick_double(&in,&remaining)));
                    else
                        cairo_mesh_pattern_set_corner_color_rgba(mesh,
                            corner,
                            fabs(pick_double(&in,&remaining)),
                            fabs(pick_double(&in,&remaining)),
                            fabs(pick_double(&in,&remaining)),
                            fabs(pick_double(&in,&remaining)));
                }

                cairo_mesh_pattern_end_patch(mesh);
            }

            // optionally set as source and draw
            if (cairo_pattern_status(mesh) == CAIRO_STATUS_SUCCESS &&
                (pick_int(&in,&remaining) & 1))
            {
                cairo_set_source(cr, mesh);
                cairo_paint(cr);
            }

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
                (cairo_operator_t)(abs(pick_int(&in,&remaining)) % 18)); // uses *all* blend modes
            break;

        } /* switch op */

        if ((ops % 11) == 0) cairo_new_path(cr);
        if ((ops % 17) == 0) { cairo_save(cr); cairo_restore(cr); }
        if ((ops % 29) == 0) cairo_identity_matrix(cr);
        /*
        if (cairo_status(cr) != CAIRO_STATUS_SUCCESS)
            break;
        */
        
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