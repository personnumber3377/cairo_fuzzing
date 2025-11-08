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
        uint8_t op = *in++ % 15; // 12;
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

        case 12: { // solid color or gradient pattern
            int t = abs((int)pick_double(&in, &remaining)) % 3;
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
                cairo_pattern_add_color_stop_rgba(p, 0, 1, 0, 0, 1);
                cairo_pattern_add_color_stop_rgba(p, 1, 0, 0, 1, 1);
                cairo_set_source(cr, p);
                cairo_pattern_destroy(p);
            } else {
                cairo_pattern_t *p = cairo_pattern_create_radial(
                    pick_double_extreme(&in, &remaining), pick_double_extreme(&in, &remaining), 10,
                    pick_double_extreme(&in, &remaining), pick_double_extreme(&in, &remaining), 200);
                cairo_pattern_add_color_stop_rgba(p, 0, 0, 1, 0, 1);
                cairo_pattern_add_color_stop_rgba(p, 1, 1, 1, 0, 1);
                cairo_set_source(cr, p);
                cairo_pattern_destroy(p);
            }
            break;
        }

        case 13: { // text rendering
            cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
            cairo_set_font_size(cr, fabs(pick_double_extreme(&in, &remaining)) * 50);
            cairo_move_to(cr, pick_double_extreme(&in, &remaining), pick_double_extreme(&in, &remaining));
            cairo_show_text(cr, "FUZZ");
            break;
        }

        case 14: { // clipping
            cairo_rectangle(cr,
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining),
                pick_double_extreme(&in, &remaining));
            cairo_clip(cr);
            break;
        }
        
        }
    }

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    return 0;
}

#ifdef COVERAGE_BUILD

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>


/* read the whole file at 'path' into a malloc'd buffer and call the fuzzer. */
static int process_file(const char *path) {
    fprintf(stderr, "Processing file: %s\n", path);
    int fd = -1;
    struct stat st;
    uint8_t *buf = NULL;
    ssize_t total = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "fstat(%s): %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    /* refuse insanely large files to avoid malloc overflow */
    if (!S_ISREG(st.st_mode)) {
        /* not a regular file */
        close(fd);
        return 0;
    }

    if ((unsigned long long)st.st_size > (unsigned long long) (1ULL << 31)) {
        fprintf(stderr, "skipping very large file %s (size=%lld)\n", path, (long long)st.st_size);
        close(fd);
        return 0;
    }

    size_t size = (size_t)st.st_size;
    buf = malloc(size ? size : 1); /* malloc(1) if zero-length file so pointer is non-NULL */
    if (!buf) {
        fprintf(stderr, "malloc(%zu) failed for %s\n", size, path);
        close(fd);
        return -1;
    }

    /* read full file */
    while (total < (ssize_t)size) {
        ssize_t r = read(fd, buf + total, size - (size_t)total);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "read(%s) error: %s\n", path, strerror(errno));
            free(buf);
            close(fd);
            return -1;
        } else if (r == 0) {
            break; /* EOF */
        } else {
            total += r;
        }
    }

    /* Call the fuzz target */
    LLVMFuzzerTestOneInput(buf, (size_t)total);

    free(buf);
    close(fd);
    return 0;
}

/* iterate non-recursively through directory 'dirpath' */
static int process_directory(const char *dirpath) {
    DIR *d = opendir(dirpath);
    struct dirent *ent;
    if (!d) {
        fprintf(stderr, "opendir(%s): %s\n", dirpath, strerror(errno));
        return -1;
    }

    char fullpath[PATH_MAX];
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        /* build full path */
        if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, ent->d_name) >= (int)sizeof(fullpath)) {
            fprintf(stderr, "path too long: %s/%s, skipping\n", dirpath, ent->d_name);
            continue;
        }

        struct stat st;
        if (stat(fullpath, &st) < 0) {
            fprintf(stderr, "stat(%s): %s\n", fullpath, strerror(errno));
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            if (process_file(fullpath) != 0) {
                fprintf(stderr, "processing file failed: %s\n", fullpath);
            }
        } else {
            /* skip non-regular files (symlinks, dirs, etc.) */
        }
    }

    closedir(d);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        /* read from stdin (original behaviour) */
        uint8_t buf[4096];
        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len > 0) {
            LLVMFuzzerTestOneInput(buf, (size_t)len);
        } else {
            fprintf(stderr, "no stdin input\n");
        }
        return 0;
    }

    /* If first arg is -r, interpret next arg as dir and recurse (not implemented).
       For now we support directory (non-recursive) or single file. */
    const char *path = argv[1];
    struct stat st;
    if (stat(path, &st) < 0) {
        fprintf(stderr, "stat(%s): %s\n", path, strerror(errno));
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        return process_directory(path);
    } else if (S_ISREG(st.st_mode)) {
        return process_file(path);
    } else {
        fprintf(stderr, "%s is not a regular file or directory\n", path);
        return 1;
    }
}

#endif