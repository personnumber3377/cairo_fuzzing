#include <cairo.h>
#include <math.h>
#include <stdint.h>
int main(){
    cairo_surface_t* surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 500, 500);
    cairo_t* cr = cairo_create(surface);
    cairo_set_source_rgb(cr,1,1,1);
    cairo_paint(cr);
    cairo_curve_to(cr, ((union{ uint64_t u; double d; }){ .u = 0x0001fffd00020000ULL }).d, ((union{ uint64_t u; double d; }){ .u = 0x00023b001401ffffULL }).d, ((union{ uint64_t u; double d; }){ .u = 0xfffff80000fff624ULL }).d, ((union{ uint64_t u; double d; }){ .u = 0xfffe01023b001401ULL }).d, ((union{ uint64_t u; double d; }){ .u = 0xd8ff01056d02bafaULL }).d, ((union{ uint64_t u; double d; }){ .u = 0x0000000000000000ULL }).d);
    cairo_set_miter_limit(cr, ((union{ uint64_t u; double d; }){ .u = 0x0000000000000000ULL }).d);
    cairo_stroke(cr);
}
