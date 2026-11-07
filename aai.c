/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 sekid. See the LICENSE file. */

/*
 * AAI - Assembly Architecture Installer (package manager for PAE)
 *
 *   aai set LINK                 set the repo (a web page that lists .so files)
 *   aai update                   refresh the package list from the repo
 *   aai install ARCH             download ARCH into $PAE32I / $PAE64I
 *   aai upgrade [ARCH]           re-download ARCH (no ARCH: every installed package)
 *   aai remove ARCH              delete ARCH
 *   aai search [TEXT]            list packages that match TEXT
 *   aai info ARCH                show what a package says about itself
 *
 *   --bitness 64|32              64 = pae64, 32 = pae32 (default: this build's pointer size)
 *   --version                    print the version
 *
 * Folders: $PAE64I = $PREFIX/share/pae/pae64, $PAE32I = $PREFIX/share/pae/pae32
 * Repo:    <LINK>/pae64/ or <LINK>/pae32/ is fetched and every link ending in .so is a package.
 * Trust:   the repo link must be https:// (file:// is allowed for a local folder). Redirects
 *          must stay on https. Every package needs a SHA-512: the repo folder must hold a
 *          SHA512SUMS file (what `sha512sum *.so > SHA512SUMS` writes). A package with no
 *          line in it is skipped, and a download whose SHA-512 differs is thrown away.
 * Names:   letters, numbers, & _ - and spaces only. A name used twice, or equal to a
 *          built-in architecture, is refused.
 * Build:   cc aai.c -o aai -ldl        (needs curl at run time:  apt install -y curl)
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>

#define AAI_VERSION "1.0.0"
#define MAX_ENT  512
#define PAGE_MAX (1 << 20)

typedef struct { char name[72]; char url[400]; char sha[129]; } Ent;

static Ent  ents[MAX_ENT];
static int  nent;
static int  bits = (int)(sizeof(void *) * 8);
static char root[480], dir[512];

static const char *const BUILTIN[] = {
    "arm64", "aarch64", "x64", "x86-64", "x86_64", "amd64", "mips64", "mips",
    "arm32", "arm", "x86", "i386", "mips32", NULL
};

/* ── names and paths ─────────────────────────────────────────────────────── */

static int is_alnum(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* letters, numbers, & _ - and spaces; nothing else */
static int name_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 64 || s[0] == ' ' || s[0] == '-' || s[n - 1] == ' ') return 0;
    for (; *s; s++)
        if (!is_alnum((unsigned char)*s) && *s != '&' && *s != ' ' && *s != '_' && *s != '-')
            return 0;
    return 1;
}

static int is_builtin(const char *name) {
    for (const char *const *b = BUILTIN; *b; b++)
        if (!strcasecmp(name, *b)) return 1;
    return 0;
}

static void mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++)
        if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
    mkdir(tmp, 0755);
}

static void set_paths(void) {
    const char *env = getenv(bits == 64 ? "PAE64I" : "PAE32I");
    const char *pre = getenv("PREFIX");
    if (!pre || !*pre) pre = "/usr";
    snprintf(root, sizeof root, "%s/share/pae", pre);
    if (env && *env) {
        snprintf(dir, sizeof dir, "%s", env);
        /* the repo setting lives next to the package folder: its parent */
        size_t l = strlen(dir);
        while (l > 1 && dir[l - 1] == '/') dir[--l] = 0;
        const char *slash = strrchr(dir, '/');
        if (slash && slash != dir) snprintf(root, sizeof root, "%.*s", (int)(slash - dir), dir);
    } else {
        snprintf(dir, sizeof dir, "%s/pae%d", root, bits);
    }
}

/* dir/name.so; an empty string when it would not fit (every later use then fails cleanly) */
static void pkg_path(char *out, size_t n, const char *name) {
    size_t a = strlen(dir), b = strlen(name);
    if (a + b + 5 > n) { out[0] = 0; return; }
    memcpy(out, dir, a);
    out[a] = '/';
    memcpy(out + a + 1, name, b);
    memcpy(out + a + 1 + b, ".so", 4);
}

/* ── files ───────────────────────────────────────────────────────────────── */

static char *read_all(const char *path, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(cap + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, cap, f);
    buf[n] = 0;
    fclose(f);
    return buf;
}

static int is_elf(const char *path) {
    unsigned char m[4];
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int ok = fread(m, 1, 4, f) == 4 && m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F';
    fclose(f);
    return ok;
}

static int same_file(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    int same = fa && fb;
    while (same) {
        char x[4096], y[4096];
        size_t nx = fread(x, 1, sizeof x, fa), ny = fread(y, 1, sizeof y, fb);
        if (nx != ny || memcmp(x, y, nx)) same = 0;
        else if (nx == 0) break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return same;
}


/* ── SHA-512 (FIPS 180-4) ────────────────────────────────────────────────── */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};
static const uint64_t H512_INIT[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

typedef struct { uint64_t h[8]; uint8_t buf[128]; uint64_t len; size_t fill; } Sha512;

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_block(Sha512 *c, const uint8_t *p) {
    uint64_t w[80], v[8];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | p[i * 8 + j];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(v, c->h, sizeof v);
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ROR64(v[4], 14) ^ ROR64(v[4], 18) ^ ROR64(v[4], 41);
        uint64_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint64_t t1 = v[7] + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ROR64(v[0], 28) ^ ROR64(v[0], 34) ^ ROR64(v[0], 39);
        uint64_t mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        uint64_t t2 = S0 + mj;
        v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = v[3] + t1;
        v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) c->h[i] += v[i];
}

static void sha512_init(Sha512 *c) {
    memcpy(c->h, H512_INIT, sizeof c->h);
    c->len = 0;
    c->fill = 0;
}

static void sha512_update(Sha512 *c, const void *data, size_t n) {
    const uint8_t *p = data;
    c->len += n;
    while (n) {
        size_t k = 128 - c->fill;
        if (k > n) k = n;
        memcpy(c->buf + c->fill, p, k);
        c->fill += k; p += k; n -= k;
        if (c->fill == 128) { sha512_block(c, c->buf); c->fill = 0; }
    }
}

static void sha512_hex(Sha512 *c, char out[129]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha512_update(c, &pad, 1);
    pad = 0;
    while (c->fill != 112) sha512_update(c, &pad, 1);
    for (int i = 0; i < 8; i++) sha512_update(c, &pad, 1);          /* high half of the length */
    for (int i = 7; i >= 0; i--) { uint8_t b = (uint8_t)(bits >> (i * 8)); sha512_update(c, &b, 1); }
    for (int i = 0; i < 8; i++) snprintf(out + i * 16, 17, "%016llx", (unsigned long long)c->h[i]);
}

/* SHA-512 of a file as 128 hex digits; 0 = ok */
static int sha512_file(const char *path, char out[129]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    Sha512 c;
    sha512_init(&c);
    unsigned char b[8192];
    size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) sha512_update(&c, b, n);
    int bad = ferror(f);
    fclose(f);
    if (bad) return -1;
    sha512_hex(&c, out);
    return 0;
}

static int is_sha512_hex(const char *s) {
    if (strlen(s) != 128) return 0;
    for (; *s; s++)
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F'))) return 0;
    return 1;
}

/* SHA512SUMS: lines of "<128 hex>  <file>" (or " *<file>"); finds the hash for file */
static int find_sum(const char *sums, const char *file, char out[129]) {
    size_t fl = strlen(file);
    for (const char *l = sums; *l; ) {
        const char *e = strchr(l, '\n');
        size_t len = e ? (size_t)(e - l) : strlen(l);
        if (len > 130 && len < 400) {
            char hex[129];
            memcpy(hex, l, 128);
            hex[128] = 0;
            const char *p = l + 128;
            const char *end = l + len;
            while (end > p && end[-1] == '\r') end--;
            if (is_sha512_hex(hex) && (*p == ' ' || *p == '\t')) {
                while (p < end && (*p == ' ' || *p == '\t')) p++;
                if (p < end && *p == '*') p++;
                if ((size_t)(end - p) == fl && !memcmp(p, file, fl)) {
                    for (int i = 0; i < 128; i++) out[i] = (char)((hex[i] >= 'A' && hex[i] <= 'F') ? hex[i] + 32 : hex[i]);
                    out[128] = 0;
                    return 1;
                }
            }
        }
        if (!e) break;
        l = e + 1;
    }
    return 0;
}

/* ── network (curl, no shell) ────────────────────────────────────────────── */

/* https:// for anything on the network; file:// only for a local folder */
static int scheme_ok(const char *u) {
    return !strncmp(u, "https://", 8) || !strncmp(u, "file://", 7);
}

static int fetch(const char *url, const char *out) {
    if (!scheme_ok(url)) return -1;
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        if (!strncmp(url, "https://", 8))      /* https only, redirects included */
            execlp("curl", "curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                   "--tlsv1.2", "--max-time", "120", "-o", out, url, (char *)NULL);
        else
            execlp("curl", "curl", "-fsSL", "--proto", "=file", "--max-time", "120",
                   "-o", out, url, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    if (waitpid(p, &st, 0) < 0) return -1;
    if (WIFEXITED(st) && WEXITSTATUS(st) == 127)
        fputs("aai: curl not found (apt install -y curl)\n", stderr);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

/* ── repo setting ────────────────────────────────────────────────────────── */

static int repo_get(char *out, size_t n) {
    char path[560];
    snprintf(path, sizeof path, "%s/aai_repo", root);
    char *s = read_all(path, 399);
    if (!s) return 0;
    s[strcspn(s, "\r\n")] = 0;
    snprintf(out, n, "%s", s);
    free(s);
    if (!scheme_ok(out)) {
        fputs("aai: the saved repo isn't https:// -- set a new one (aai set LINK)\n", stderr);
        out[0] = 0;
        return 0;
    }
    return 1;
}

static void index_url(char *out, size_t n, const char *repo) {
    size_t l = strlen(repo);
    snprintf(out, n, "%s%spae%d/", repo, (l && repo[l - 1] == '/') ? "" : "/", bits);
}

static int join(char *out, size_t n, const char *a, size_t alen, const char *b) {
    size_t blen = strlen(b);
    if (alen + blen >= n) return -1;
    memcpy(out, a, alen);
    memcpy(out + alen, b, blen + 1);
    return 0;
}

/* turn a link found on the page into a full URL; -1 when it is too long */
static int resolve(char *out, size_t n, const char *base, const char *tok) {
    int rc;
    const char *want = !strncmp(base, "https://", 8) ? "https://" : "file://";
    if (!strncmp(tok, want, strlen(want))) {
        rc = join(out, n, "", 0, tok);
    } else if (strstr(tok, "://")) {
        return -1;                          /* http://, file:// from a web page, ftp://, ... */
    } else if (tok[0] == '/') {
        const char *h = strstr(base, "://");
        const char *e = h ? strchr(h + 3, '/') : NULL;
        rc = join(out, n, base, e ? (size_t)(e - base) : strlen(base), tok);
    } else {
        if (!strncmp(tok, "./", 2)) tok += 2;
        rc = join(out, n, base, strlen(base), tok);
    }
    if (rc) return rc;
    /* a GitHub "blob" page link becomes the raw download link */
    char *g = strstr(out, "github.com/");
    char *bl = g ? strstr(g, "/blob/") : NULL;
    if (bl) memmove(bl + 4, bl + 5, strlen(bl + 5) + 1), memcpy(bl, "/raw", 4);
    return 0;
}

/* ── package list ────────────────────────────────────────────────────────── */

static int find_ent(const char *name) {
    for (int i = 0; i < nent; i++)
        if (!strcasecmp(ents[i].name, name)) return i;
    return -1;
}

static void add_ent(const char *name, const char *url, const char *sha) {
    if (is_builtin(name)) { fprintf(stderr, "aai: skipping '%s' (same name as a built-in)\n", name); return; }
    int d = find_ent(name);
    if (d >= 0) {
        if (strcmp(ents[d].url, url))
            fprintf(stderr, "aai: skipping '%s' (name already used)\n", name);
        return;
    }
    if (nent >= MAX_ENT) return;
    snprintf(ents[nent].name, sizeof ents[nent].name, "%s", name);
    snprintf(ents[nent].url, sizeof ents[nent].url, "%s", url);
    snprintf(ents[nent].sha, sizeof ents[nent].sha, "%s", sha);
    nent++;
}

/* every token ending in .so is a package; the file name is the package name */
static void parse_page(const char *base, const char *buf, const char *sums) {
    const char *p = buf;
    while ((p = strstr(p, ".so")) != NULL) {
        const char *end = p + 3, *st = p;
        p += 3;
        if (*end && !strchr("\"' <>?#)\r\n\t", *end)) continue;
        while (st > buf && !strchr("\"' <>=(\r\n\t", st[-1])) st--;

        size_t len = (size_t)(end - st);
        if (len < 4 || len > 300) continue;
        char tok[320], name[72], url[400];
        memcpy(tok, st, len);
        tok[len] = 0;

        const char *slash = strrchr(tok, '/');
        const char *stem = slash ? slash + 1 : tok;
        size_t k = 0;
        size_t sl = strlen(stem) - 3;                /* drop the trailing .so */
        for (size_t i = 0; i < sl && k + 1 < sizeof name; i++) {
            if (!strncmp(stem + i, "%20", 3)) { name[k++] = ' '; i += 2; }
            else if (!strncmp(stem + i, "%26", 3)) { name[k++] = '&'; i += 2; }
            else name[k++] = stem[i];
        }
        name[k] = 0;
        /* names that use other symbols are skipped */
        if (!name_ok(name)) continue;

        if (resolve(url, sizeof url, base, tok)) continue;
        char file[96], sha[129];
        snprintf(file, sizeof file, "%s.so", name);
        if (!find_sum(sums, file, sha)) {
            static char last_skip[72];
            if (strcmp(last_skip, name)) {
                fprintf(stderr, "aai: skipping '%s' (no SHA-512 in SHA512SUMS)\n", name);
                snprintf(last_skip, sizeof last_skip, "%s", name);
            }
            continue;
        }
        add_ent(name, url, sha);
    }
}

static void index_path(char *out, size_t n) { snprintf(out, n, "%s/.aai_index", dir); }

static void save_index(void) {
    char path[560];
    index_path(path, sizeof path);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "aai: cannot write %s\n", path); return; }
    for (int i = 0; i < nent; i++) fprintf(f, "%s\t%s\t%s\n", ents[i].name, ents[i].url, ents[i].sha);
    fclose(f);
}

static void load_index(void) {
    char path[560];
    index_path(path, sizeof path);
    char *s = read_all(path, PAGE_MAX);
    nent = 0;
    if (!s) return;
    for (char *line = strtok(s, "\n"); line; line = strtok(NULL, "\n")) {
        char *t1 = strchr(line, '\t');
        char *t2 = t1 ? strchr(t1 + 1, '\t') : NULL;
        if (!t2) continue;                       /* an old list without hashes: run aai update */
        *t1 = 0; *t2 = 0;
        char *url = t1 + 1, *sha = t2 + 1;
        sha[strcspn(sha, "\r")] = 0;
        if (name_ok(line) && scheme_ok(url) && is_sha512_hex(sha)) add_ent(line, url, sha);
    }
    free(s);
}

static int need_index(void) {
    load_index();
    if (nent == 0) { fputs("aai: no package list (run: aai update)\n", stderr); return 0; }
    return 1;
}

/* ── commands ────────────────────────────────────────────────────────────── */

static int cmd_set(const char *link) {
    for (const char *c = link; *c; c++)
        if ((unsigned char)*c <= ' ' || *c == 0x7f) { fputs("aai: bad link\n", stderr); return 1; }
    if (!scheme_ok(link) || strlen(link) > 300) {
        fputs("aai: the link must start with https:// (or file:// for a local folder)\n", stderr);
        return 1;
    }
    mkdir_p(root);
    char path[560];
    snprintf(path, sizeof path, "%s/aai_repo", root);
    FILE *f = fopen(path, "w");
    if (!f || fprintf(f, "%s\n", link) < 0) { fputs("aai: cannot save the repo\n", stderr); if (f) fclose(f); return 1; }
    fclose(f);
    printf("repo set to %s\n", link);
    return 0;
}

/* file:// repos: curl can't list a folder, so read it directly.
 * base is file:///path/to/pae64/ ; every *.so in it is a package. */
static int list_local(const char *base, const char *sums) {
    DIR *d = opendir(base + 7);                 /* skip "file://" */
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t l = strlen(e->d_name);
        if (l < 4 || strcmp(e->d_name + l - 3, ".so")) continue;
        char name[72], url[400];
        if (l - 3 >= sizeof name) continue;
        memcpy(name, e->d_name, l - 3);
        name[l - 3] = 0;
        if (!name_ok(name)) continue;
        if (join(url, sizeof url, base, strlen(base), e->d_name)) continue;
        char sha[129];
        if (!find_sum(sums, e->d_name, sha)) {
            fprintf(stderr, "aai: skipping '%s' (no SHA-512 in SHA512SUMS)\n", name);
            continue;
        }
        add_ent(name, url, sha);
    }
    closedir(d);
    return 0;
}

static int cmd_update(void) {
    char repo[400], base[420], tmp[560];
    if (!repo_get(repo, sizeof repo)) { fputs("aai: no repo set (aai set LINK)\n", stderr); return 1; }
    index_url(base, sizeof base, repo);
    mkdir_p(dir);
    char sumsurl[460], sumstmp[560];
    snprintf(sumsurl, sizeof sumsurl, "%sSHA512SUMS", base);
    snprintf(sumstmp, sizeof sumstmp, "%s/.aai_sums", dir);
    if (fetch(sumsurl, sumstmp) != 0) {
        fprintf(stderr, "aai: no SHA512SUMS at %s (every package needs a SHA-512)\n", sumsurl);
        unlink(sumstmp);
        return 1;
    }
    char *sums = read_all(sumstmp, PAGE_MAX);
    unlink(sumstmp);
    if (!sums) { fputs("aai: could not read SHA512SUMS\n", stderr); return 1; }
    if (!strncmp(base, "file://", 7)) {
        nent = 0;
        if (list_local(base, sums) != 0) { fprintf(stderr, "aai: cannot read folder %s\n", base + 7); free(sums); return 1; }
        free(sums);
        save_index();
        printf("%d package(s) listed at %s\n", nent, base);
        return 0;
    }
    snprintf(tmp, sizeof tmp, "%s/.aai_page", dir);
    if (fetch(base, tmp) != 0) { fprintf(stderr, "aai: could not fetch %s\n", base); unlink(tmp); free(sums); return 1; }
    char *page = read_all(tmp, PAGE_MAX);
    unlink(tmp);
    if (!page) { fputs("aai: could not read the page\n", stderr); free(sums); return 1; }
    nent = 0;
    parse_page(base, page, sums);
    free(page);
    free(sums);
    save_index();
    printf("%d package(s) listed at %s\n", nent, base);
    return 0;
}

/* download ents[i] to a temp file, check it, move it into place; 0 = ok */
static int download(int i, int replace_only_if_changed, int *changed) {
    char tmp[560], dest[560];
    snprintf(tmp, sizeof tmp, "%s/.aai_dl", dir);
    pkg_path(dest, sizeof dest, ents[i].name);
    mkdir_p(dir);
    if (fetch(ents[i].url, tmp) != 0) { fprintf(stderr, "aai: download failed: %s\n", ents[i].url); unlink(tmp); return 1; }
    char got[129];
    if (sha512_file(tmp, got) != 0 || strcasecmp(got, ents[i].sha) != 0) {
        fprintf(stderr, "aai: SHA-512 mismatch for %s -- refusing it\n  expected %s\n  got      %s\n",
                ents[i].name, ents[i].sha, got);
        unlink(tmp);
        return 1;
    }
    if (!is_elf(tmp)) { fprintf(stderr, "aai: %s is not a .so file\n", ents[i].url); unlink(tmp); return 1; }
    if (replace_only_if_changed && same_file(tmp, dest)) { unlink(tmp); *changed = 0; return 0; }
    if (rename(tmp, dest) != 0) { fprintf(stderr, "aai: cannot write %s\n", dest); unlink(tmp); return 1; }
    *changed = 1;
    return 0;
}

static int check_name(const char *name) {
    if (!name_ok(name)) {
        fputs("aai: names may only use letters, numbers, & _ - and spaces\n", stderr);
        return 0;
    }
    return 1;
}

static int cmd_install(const char *name) {
    if (!check_name(name) || !need_index()) return 1;
    int i = find_ent(name);
    if (i < 0) { fprintf(stderr, "aai: no package '%s' (try: aai search)\n", name); return 1; }
    char dest[560];
    pkg_path(dest, sizeof dest, ents[i].name);
    if (access(dest, F_OK) == 0) { printf("%s is already installed (use: aai upgrade)\n", ents[i].name); return 0; }
    int changed;
    if (download(i, 0, &changed)) return 1;
    printf("installed %s in %s\n", ents[i].name, dir);
    return 0;
}

static int cmd_upgrade(const char *name) {
    if (name && !check_name(name)) return 1;
    if (!need_index()) return 1;
    int rc = 0, any = 0;
    for (int i = 0; i < nent; i++) {
        if (name && strcasecmp(name, ents[i].name)) continue;
        char dest[560];
        pkg_path(dest, sizeof dest, ents[i].name);
        if (access(dest, F_OK) != 0) {
            if (name) { fprintf(stderr, "aai: %s is not installed\n", ents[i].name); return 1; }
            continue;
        }
        any = 1;
        int changed = 0;
        if (download(i, 1, &changed)) { rc = 1; continue; }
        printf("%s %s\n", ents[i].name, changed ? "upgraded" : "already up to date");
    }
    if (name && !any) { fprintf(stderr, "aai: no package '%s'\n", name); return 1; }
    if (!name && !any) puts("nothing installed");
    return rc;
}

static int cmd_remove(const char *name) {
    if (!check_name(name)) return 1;
    char path[560];
    pkg_path(path, sizeof path, name);
    if (unlink(path) != 0) {
        if (errno == ENOENT) fprintf(stderr, "aai: %s is not installed\n", name);
        else                 fprintf(stderr, "aai: cannot remove %s\n", path);
        return 1;
    }
    printf("removed %s\n", name);
    return 0;
}

static int cmd_search(const char *text) {
    if (!need_index()) return 1;
    int hits = 0;
    for (int i = 0; i < nent; i++) {
        if (text && !strcasestr(ents[i].name, text)) continue;
        char p[560];
        pkg_path(p, sizeof p, ents[i].name);
        printf("%s%s\n", ents[i].name, access(p, F_OK) == 0 ? "  [installed]" : "");
        hits++;
    }
    if (!hits) puts("no match");
    return 0;
}

static int cmd_info(const char *name) {
    if (!check_name(name)) return 1;
    load_index();
    int i = find_ent(name);
    char path[560];
    pkg_path(path, sizeof path, i >= 0 ? ents[i].name : name);
    struct stat sb;
    int inst = stat(path, &sb) == 0;
    if (i < 0 && !inst) { fprintf(stderr, "aai: no package '%s'\n", name); return 1; }

    printf("name:       %s\nbitness:    %d\ninstalled:  %s\n", i >= 0 ? ents[i].name : name, bits, inst ? "yes" : "no");
    if (i >= 0) printf("source:     %s\nsha512:     %s\n", ents[i].url, ents[i].sha);
    if (!inst) return 0;
    printf("file:       %s (%lld bytes)\n", path, (long long)sb.st_size);
    if (i >= 0) {
        char got[129];
        if (sha512_file(path, got) == 0)
            printf("verified:   %s\n", strcasecmp(got, ents[i].sha) == 0 ? "yes, matches the package list"
                                                                          : "NO - differs from the package list (outdated or changed)");
    }

    void *h = dlopen(path, RTLD_NOW);
    if (!h) { printf("(could not load it: %s)\n", dlerror()); return 0; }
    const char *const *opt  = (const char *const *)dlsym(h, "pae_pkg_option");
    const int *num          = (const int *)dlsym(h, "pae_pkg_number");
    const int *ksa          = (const int *)dlsym(h, "pae_pkg_keystone_arch");
    const int *ksm          = (const int *)dlsym(h, "pae_pkg_keystone_mode");
    const char *const *info = (const char *const *)dlsym(h, "pae_pkg_info");
    if (opt && *opt) printf("menu name:  %s\n", *opt);
    else             puts("menu name:  (missing add_arch_option, PAE will skip this package)");
    if (num) printf("menu number: %d\n", *num);
    else     puts("menu number: (not set, counts after the biggest number)");
    if (ksa) printf("keystone arch: %d\n", *ksa);
    else     puts("keystone arch: (missing set_keystone_arch, PAE will skip this package)");
    if (ksm) printf("keystone mode: %d\n", *ksm);
    const int *elm = (const int *)dlsym(h, "pae_pkg_elf_machine");
    const int *elb = (const int *)dlsym(h, "pae_pkg_elf_bits");
    if (elm) printf("elf machine: %d%s\n", *elm, elb ? "" : " (--asm)");
    if (elb) printf("elf bits:   %d\n", *elb);
    const int *rw = (const int *)dlsym(h, "pae_pkg_reg_width");
    const int *rc = (const int *)dlsym(h, "pae_pkg_reg_count");
    int runs = rw && rc && dlsym(h, "pae_pkg_reg_names") && dlsym(h, "pae_pkg_build") && dlsym(h, "pae_pkg_host");
    if (runs) printf("runs code:  yes (%d registers, %d bytes each)\n", *rc, *rw);
    else      puts("runs code:  no (prints bytes only)");
    printf("info:       %s\n", (info && *info) ? *info : "(none)");
    dlclose(h);
    return 0;
}

static void usage(void) {
    fputs("usage: aai [--bitness 64|32] COMMAND   (aai --version)\n"
          "  set LINK | update | install ARCH | upgrade [ARCH] | remove ARCH\n"
          "  search [TEXT] | info ARCH\n", stderr);
}

int main(int argc, char **argv) {
    const char *av[8];
    int n = 0;
    for (int i = 1; i < argc; i++) {
        const char *s = argv[i], *v = NULL;
        if (!strcmp(s, "--bitness")) {
            if (++i >= argc) { fputs("aai: --bitness needs 32 or 64\n", stderr); return 2; }
            v = argv[i];
        } else if (!strncmp(s, "--bitness=", 10)) {
            v = s + 10;
        } else if (!strcmp(s, "--version")) {
            puts("aai " AAI_VERSION " (Assembly Architecture Installer)");
            return 0;
        } else if (s[0] == '-' && s[1] == '-') {
            fprintf(stderr, "aai: unknown option '%s'\n", s);
            usage();
            return 2;
        } else {
            if (n >= 8) { usage(); return 2; }
            av[n++] = s;
            continue;
        }
        if (!strcmp(v, "64")) bits = 64;
        else if (!strcmp(v, "32")) bits = 32;
        else { fputs("aai: --bitness must be 32 or 64\n", stderr); return 2; }
    }
    if (n == 0) { usage(); return 2; }
    set_paths();

    const char *c = av[0];
    if (!strcmp(c, "update") && n == 1)                return cmd_update();
    if (!strcmp(c, "set")      && n == 2)              return cmd_set(av[1]);
    if (!strcmp(c, "install")  && n == 2)              return cmd_install(av[1]);
    if (!strcmp(c, "upgrade")  && n <= 2)              return cmd_upgrade(n == 2 ? av[1] : NULL);
    if (!strcmp(c, "remove")   && n == 2)              return cmd_remove(av[1]);
    if (!strcmp(c, "search")   && n <= 2)              return cmd_search(n == 2 ? av[1] : NULL);
    if (!strcmp(c, "info")     && n == 2)              return cmd_info(av[1]);
    usage();
    return 2;
}
