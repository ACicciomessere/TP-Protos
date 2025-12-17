// Plot stress_results.csv without Python/matplotlib.
//
// Reads a CSV with header: conns,throughput_MBps
// Produces a simple SVG chart (stress_results.svg) and prints a table.

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int conns;
    double thr;
} point_t;

static int parse_line(const char *line, int *conns_out, double *thr_out) {
    // Expected: <int>,<double>
    char *end = NULL;
    long c = strtol(line, &end, 10);
    if (end == line || (*end != ',' && *end != ';')) return -1;
    end++;
    double t = strtod(end, &end);
    if (end == NULL) return -1;
    *conns_out = (int)c;
    *thr_out = t;
    return 0;
}

static void write_svg(const char *path, const point_t *pts, size_t n) {
    const int W = 900;
    const int H = 500;
    const int L = 70;
    const int R = 20;
    const int T = 20;
    const int B = 60;

    int minC = pts[0].conns, maxC = pts[0].conns;
    double minT = pts[0].thr, maxT = pts[0].thr;
    for (size_t i = 1; i < n; i++) {
        if (pts[i].conns < minC) minC = pts[i].conns;
        if (pts[i].conns > maxC) maxC = pts[i].conns;
        if (pts[i].thr < minT) minT = pts[i].thr;
        if (pts[i].thr > maxT) maxT = pts[i].thr;
    }
    if (minC == maxC) { maxC = minC + 1; }
    if (minT == maxT) { maxT = minT + 1.0; }

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "[plot_stress] cannot write %s: %s\n", path, strerror(errno));
        return;
    }

    fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(f, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\">\n", W, H);
    fprintf(f, "<rect x=\"0\" y=\"0\" width=\"%d\" height=\"%d\" fill=\"white\"/>\n", W, H);

    // Axes
    const int x0 = L;
    const int y0 = H - B;
    const int x1 = W - R;
    const int y1 = T;
    fprintf(f, "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"black\"/>\n", x0, y0, x1, y0);
    fprintf(f, "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"black\"/>\n", x0, y0, x0, y1);

    // Labels
    fprintf(f, "<text x=\"%d\" y=\"%d\" font-family=\"sans-serif\" font-size=\"16\">Throughput vs Conexiones</text>\n", x0, 18);
    fprintf(f, "<text x=\"%d\" y=\"%d\" font-family=\"sans-serif\" font-size=\"12\">Conexiones (c)</text>\n", (x0 + x1)/2 - 40, H - 20);
    fprintf(f, "<text x=\"15\" y=\"%d\" font-family=\"sans-serif\" font-size=\"12\" transform=\"rotate(-90 15,%d)\">Throughput (MB/s)</text>\n", (y0 + y1)/2 + 40, (y0 + y1)/2 + 40);

    // Polyline
    fprintf(f, "<polyline fill=\"none\" stroke=\"#1f77b4\" stroke-width=\"2\" points=\"");
    for (size_t i = 0; i < n; i++) {
        double xc = (double)(pts[i].conns - minC) / (double)(maxC - minC);
        double yt = (double)(pts[i].thr - minT) / (double)(maxT - minT);
        int x = x0 + (int)(xc * (double)(x1 - x0));
        int y = y0 - (int)(yt * (double)(y0 - y1));
        fprintf(f, "%d,%d ", x, y);
    }
    fprintf(f, "\"/>\n");

    // Points
    for (size_t i = 0; i < n; i++) {
        double xc = (double)(pts[i].conns - minC) / (double)(maxC - minC);
        double yt = (double)(pts[i].thr - minT) / (double)(maxT - minT);
        int x = x0 + (int)(xc * (double)(x1 - x0));
        int y = y0 - (int)(yt * (double)(y0 - y1));
        fprintf(f, "<circle cx=\"%d\" cy=\"%d\" r=\"4\" fill=\"#1f77b4\"/>\n", x, y);
        fprintf(f, "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" font-size=\"10\">%d</text>\n", x - 10, y - 8, pts[i].conns);
    }

    fprintf(f, "</svg>\n");
    fclose(f);
}

int main(int argc, char **argv) {
    const char *csv_path = (argc >= 2) ? argv[1] : "stress_results.csv";
    const char *svg_path = (argc >= 3) ? argv[2] : "stress_results.svg";

    FILE *f = fopen(csv_path, "r");
    if (!f) {
        fprintf(stderr, "[plot_stress] cannot open %s: %s\n", csv_path, strerror(errno));
        return 1;
    }

    char line[4096];
    // Skip header
    if (!fgets(line, sizeof(line), f)) {
        fprintf(stderr, "[plot_stress] empty file: %s\n", csv_path);
        fclose(f);
        return 1;
    }

    point_t *pts = NULL;
    size_t n = 0, cap = 0;
    while (fgets(line, sizeof(line), f)) {
        // trim
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (len == 0) continue;

        int c = 0;
        double t = 0;
        if (parse_line(line, &c, &t) != 0) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            point_t *tmp = realloc(pts, cap * sizeof(*pts));
            if (!tmp) {
                fprintf(stderr, "[plot_stress] out of memory\n");
                free(pts);
                fclose(f);
                return 1;
            }
            pts = tmp;
        }
        pts[n++] = (point_t){ .conns = c, .thr = t };
    }
    fclose(f);

    if (n == 0) {
        fprintf(stderr, "[plot_stress] no data rows found in %s\n", csv_path);
        free(pts);
        return 1;
    }

    printf("conns,throughput_MBps\n");
    for (size_t i = 0; i < n; i++) {
        printf("%d,%.3f\n", pts[i].conns, pts[i].thr);
    }

    write_svg(svg_path, pts, n);
    fprintf(stderr, "[plot_stress] wrote %s\n", svg_path);
    free(pts);
    return 0;
}
