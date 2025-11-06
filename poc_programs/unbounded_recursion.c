#include <cairo.h>
#include <math.h>
#include <stdint.h>
int main() {
    cairo_surface_t* surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 500, 500);
    cairo_t* cr = cairo_create(surface);
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);

    cairo_arc(cr, 4.18773154961833e-294, -3.988094816959602e-16, fabs(1.5314697853761904e-231), 9422236867459448.0 * 2 * M_PI, 1.7576384591071336e-295 * 2 * M_PI);

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
}