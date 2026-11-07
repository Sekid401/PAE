/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 sekid. See the LICENSE file. */

/*
 * PAE32 - Personal Assembly Executor (32-bit edition)
 *
 *   pae32                                   REPL (architecture menu)
 *   pae32 --arch=ARCH                       REPL, architecture given
 *   pae32 --persist [--arch=ARCH]           REPL, registers and data memory kept between sessions
 *   pae32 --mem=SIZE ...                   data memory size (default 64k; k/m suffix, e.g. 128k, 1m)
 *   pae32 --timeout=SECONDS ...            stop a block that runs longer than that (default: no limit)
 *   pae32 --version
 *   pae32 --arch=ARCH file.s                run an assembly file   (.s / .S / .asm)
 *   pae32 --exec file.s --arch=ARCH         same thing, --exec is an alias
 *   pae32 --arch=ARCH "code<newline>code"   run code given on the command line
 *   pae32 --asm --arch=ARCH file.s -o OUT   assemble and link: writes OUT.o and OUT (an ELF executable)
 *   pae32 --asm --no-elf --arch=ARCH file.s -o OUT
 *                                           same, but OUT is raw machine code (OUT.o is still written)
 *
 * ARCH: arm32 x86 mips32
 * This program only handles 32-bit architectures and must be built as a
 * 32-bit process.
 * Running a file or inline code always uses a persisted session.
 * Data memory: a zeroed read/write region (64 KB by default) is mapped at startup,
 * at DATA_BASE (0x10000000) when that address is free. Code can load and store there
 * with absolute addresses. REPL: mem, dump, poke, memload. It is saved with --persist.
 * --asm never runs anything and does not touch the saved registers: it works for every
 * architecture, whatever the host CPU. The name given to -o decides the executable's name
 * (any extension is yours, none is the default); the object is OUT.o. The program starts at
 * its first byte (symbol _start) and must end itself, since nothing is wrapped around it.
 *
 * Crash isolation: every block runs in a child process. A crash (SIGSEGV, SIGBUS, SIGILL ...),
 * an exit, or Ctrl-C only stops that block: the registers stay as they were and the session goes
 * on. Data memory changes made before a crash are kept.
 * Build:  clang pae32.c -o pae32 -lkeystone -ldl     (32-bit toolchain and libkeystone)
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <time.h>

#include <keystone/keystone.h>

#if UINTPTR_MAX != 0xFFFFFFFFu
#error "pae32 must be built as a 32-bit process"
#endif

#define PAE_NAME "pae32"

#ifdef __APPLE__
#include <pthread.h>
#include <libkern/OSCacheControl.h>
#endif

/* MIPS: match the host's byte order when running on MIPS, big-endian otherwise */
#if defined(__mips__) && defined(__MIPSEL__)
#define MIPS_ENDIAN KS_MODE_LITTLE_ENDIAN
#else
#define MIPS_ENDIAN KS_MODE_BIG_ENDIAN
#endif

#define MEM_SIZE   65536            /* executable buffer */
#define BLOCK_MAX  65536            /* largest { ... } block in the REPL */
#define FILE_MAX   (1 << 20)        /* largest source file */
#define STATE_VER  1
#define DATA_BASE    0x10000000u      /* preferred address of the data memory */
#define DATA_DEFAULT (64u * 1024u)    /* data memory size at startup */
#define DATA_MAX     (64u * 1024u * 1024u)

#define PAE_VERSION  "1.0.0"

/* ── register banks ─────────────────────────────────────────────────────── */
/* The wrappers below read and write these arrays at fixed offsets.         */

static uint32_t bank_arm32[17];   /* r0..r15, cpsr (r12..r15 not tracked)   */
static uint32_t bank_x86[9];      /* eax ecx edx ebx esp ebp esi edi eflags */
static uint32_t bank_mips32[27];  /* $1..$25, hi, lo                        */

static const char *const names_arm32[] = {
    "r0","r1","r2","r3","r4","r5","r6","r7",
    "r8","r9","r10","r11","r12","r13","r14","r15","cpsr"
};
static const char *const names_x86[] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi","eflags"
};
static const char *const names_mips32[] = {
    "$at","$v0","$v1","$a0","$a1","$a2","$a3",
    "$t0","$t1","$t2","$t3","$t4","$t5","$t6","$t7",
    "$s0","$s1","$s2","$s3","$s4","$s5","$s6","$s7",
    "$t8","$t9","hi","lo"
};

static const char *const rets_arm32[] = { "bx lr", "mov pc, lr", NULL };
static const char *const rets_x86[]   = { "ret", "retn", NULL };
static const char *const rets_mips[]  = { "jr $ra", "jr $31", NULL };

/* ── emit helper ─────────────────────────────────────────────────────────── */

static void emit(char *out, size_t n, size_t *o, const char *fmt, ...) {
    if (*o >= n) return;
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(out + *o, n - *o, fmt, ap);
    va_end(ap);
    if (r > 0) *o += (size_t)r;
    if (*o > n) *o = n;
}

/* ── ARM32 wrapper ───────────────────────────────────────────────────────── */
/* regs array passed in r0; r12 used as pointer (not tracked)                */
/* layout: r0..r15 at [0..60], cpsr at [64]; only r0..r11 and the flags move */

static int build_arm32(char *out, size_t n, const char *line) {
    size_t o = 0;
#define A(...) emit(out, n, &o, __VA_ARGS__)
    /* r0 (the array pointer) goes on the stack first, at [sp, #0] */
    A("push {r0, r4, r5, r6, r7, r8, r9, r10, r11, r12, lr}\n");
    A("mov r12, r0\n");
    A("ldm r12, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11}\n");
    A("ldr r12, [r12, #64]\n");
    A("msr cpsr_f, r12\n");
    A("%s\n", line);
    A("ldr r12, [sp]\n");
    A("stm r12, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11}\n");
    A("mrs r0, cpsr\n");
    A("str r0, [r12, #64]\n");
    A("pop {r0, r4, r5, r6, r7, r8, r9, r10, r11, r12, lr}\n");
    A("bx lr\n");
#undef A
    return o < n ? 0 : -1;
}

/* ── x86 wrapper (32-bit) ────────────────────────────────────────────────── */
/* array ptr passed on the stack (cdecl first arg)                           */
/* layout: eax ecx edx ebx esp ebp esi edi eflags (esp not tracked)          */

static int build_x86(char *out, size_t n, const char *line) {
    size_t o = 0;
#define A(...) emit(out, n, &o, __VA_ARGS__)
    A("push ebp\n");
    A("mov ebp, esp\n");
    A("push esi\n");
    A("push edi\n");
    A("push ebx\n");
    A("mov esi, [ebp+8]\n");
    A("push esi\n");               /* array ptr kept on the stack */
    A("mov eax, [esi+32]\n");
    A("push eax\n");
    A("popf\n");
    A("mov eax, [esi+0]\n");
    A("mov ecx, [esi+4]\n");
    A("mov edx, [esi+8]\n");
    A("mov ebx, [esi+12]\n");
    A("mov ebp, [esi+20]\n");
    A("mov edi, [esi+28]\n");
    A("mov esi, [esi+24]\n");
    A("%s\n", line);
    A("push esi\n");
    A("mov esi, [esp+4]\n");       /* array ptr, from the stack not from ebp */
    A("mov [esi+0],  eax\n");
    A("mov [esi+4],  ecx\n");
    A("mov [esi+8],  edx\n");
    A("mov [esi+12], ebx\n");
    A("mov [esi+20], ebp\n");
    A("pop eax\n");                /* the user's esi */
    A("mov [esi+24], eax\n");
    A("mov [esi+28], edi\n");
    A("pushf\n");
    A("pop eax\n");
    A("mov [esi+32], eax\n");
    A("add esp, 4\n");             /* drop the saved array ptr */
    A("pop ebx\n");
    A("pop edi\n");
    A("pop esi\n");
    A("pop ebp\n");
    A("ret\n");
#undef A
    return o < n ? 0 : -1;
}

/* ── MIPS32 wrapper (o32) ────────────────────────────────────────────────── */
/* array ptr in $a0 ($4); $30 ($fp) is the pointer and is not tracked        */
/* $1..$25 at [0..96], hi at [100], lo at [104]. Registers by number so the  */
/* assembler never complains about $at. Ends with jr $ra + its delay slot.   */

static int build_mips32(char *out, size_t n, const char *line) {
    size_t o = 0;
#define A(...) emit(out, n, &o, __VA_ARGS__)
    A("addiu $29, $29, -48\n");
    for (int i = 0; i < 8; i++) A("sw $%d, %d($29)\n", 16 + i, i * 4);
    A("sw $28, 32($29)\n");
    A("sw $30, 36($29)\n");
    A("sw $31, 40($29)\n");
    A("sw $4, 44($29)\n");
    A("move $30, $4\n");
    A("lw $2, 100($30)\n");
    A("mthi $2\n");
    A("lw $2, 104($30)\n");
    A("mtlo $2\n");
    for (int i = 1; i <= 25; i++) A("lw $%d, %d($30)\n", i, (i - 1) * 4);
    A("%s\n", line);
    A("lw $30, 44($29)\n");
    for (int i = 1; i <= 25; i++) A("sw $%d, %d($30)\n", i, (i - 1) * 4);
    A("mfhi $1\n");
    A("sw $1, 100($30)\n");
    A("mflo $1\n");
    A("sw $1, 104($30)\n");
    for (int i = 0; i < 8; i++) A("lw $%d, %d($29)\n", 16 + i, i * 4);
    A("lw $28, 32($29)\n");
    A("lw $30, 36($29)\n");
    A("lw $31, 40($29)\n");
    A("addiu $29, $29, 48\n");
    A("jr $31\n");
    A("nop\n");
#undef A
    return o < n ? 0 : -1;
}

/* ── architecture table ──────────────────────────────────────────────────── */

enum { FK_NONE = 0, FK_NZCV, FK_X86 };

/* CF PF AF ZF SF DF OF */
#define X86_FLAGS_MASK 0xCD5ull

typedef struct {
    const char        *id;        /* --arch name, also used in the state file name */
    const char        *label;     /* shown in the menu */
    ks_arch            arch;
    int                mode;
    int                width;     /* bytes per register slot: 4 or 8 */
    int                count;     /* slots in the bank */
    const char *const *names;
    uint32_t           hidden;    /* slots that exist in the array but aren't tracked */
    int                flag_slot;
    int                flag_kind;
    void              *data;
    const char *const *rets;      /* trailing return instructions that get stripped */
    int                delay_nop; /* a nop may follow the return (MIPS delay slot) */
    int              (*build)(char *, size_t, const char *);
    int              (*host)(void);   /* AAI package: 1 = this CPU can run it */
    int                elf_machine; /* AAI package: ELF e_machine for --asm (0 = work it out) */
    int                elf_bits;    /* AAI package: 32 or 64 (0 = work it out) */
} Arch;

static const Arch ARCHES[] = {
    { "arm32",  "ARM32",  KS_ARCH_ARM,   KS_MODE_ARM,           4, 17, names_arm32,
      0xF000u,      16, FK_NZCV, bank_arm32,  rets_arm32, 0, build_arm32, NULL, 0, 0 },
    { "x86",    "x86",    KS_ARCH_X86,   KS_MODE_32,            4,  9, names_x86,
      1u << 4,       8, FK_X86,  bank_x86,    rets_x86,   0, build_x86, NULL, 0, 0 },
    { "mips32", "MIPS32", KS_ARCH_MIPS,  KS_MODE_MIPS32 | MIPS_ENDIAN, 4, 27, names_mips32,
      0,            -1, FK_NONE, bank_mips32, rets_mips,  1, build_mips32, NULL, 0, 0 },
};

#define NBUILTIN ((int)(sizeof ARCHES / sizeof ARCHES[0]))
#define NARCH_MAX 64

/* ── AAI packages ────────────────────────────────────────────────────────── */
/* Every .so in $PAE32I (default $PREFIX/share/pae/pae32) is loaded at startup.  */
/* A package exports pae_pkg_option (menu name, required), pae_pkg_keystone_arch  */
/* (required, the Keystone architecture to open), pae_pkg_keystone_mode and       */
/* pae_pkg_number (its menu number; without it the package is numbered after the  */
/* biggest number in use). With registers, a wrapper builder and a host check the */
/* package runs code like a built-in architecture, otherwise it prints bytes.     */

static const char *const rets_none[] = { NULL };
static Arch ALL[NARCH_MAX];
static int  NUM[NARCH_MAX];          /* menu number of each entry */
static int  NARCH;
static int  pkg_req[NARCH_MAX];
static char pkg_ids[NARCH_MAX][48];
static char pkg_labels[NARCH_MAX][64];

static void load_packages(void) {
    memcpy(ALL, ARCHES, sizeof ARCHES);
    NARCH = NBUILTIN;
    for (int i = 0; i < NBUILTIN; i++) NUM[i] = i + 1;

    char dir[512];
    const char *env = getenv("PAE32I"), *pre = getenv("PREFIX");
    if (env && *env) snprintf(dir, sizeof dir, "%s", env);
    else snprintf(dir, sizeof dir, "%s/share/pae/pae32", (pre && *pre) ? pre : "/usr");

    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && NARCH < NARCH_MAX) {
        size_t l = strlen(e->d_name);
        if (e->d_name[0] == '.' || l < 4 || strcmp(e->d_name + l - 3, ".so")) continue;

        char path[1100];
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        void *h = dlopen(path, RTLD_NOW);
        if (!h) { fprintf(stderr, "pae: skipping %s (%s)\n", e->d_name, dlerror()); continue; }

        const char *const *opt = (const char *const *)dlsym(h, "pae_pkg_option");
        const int *ksa  = (const int *)dlsym(h, "pae_pkg_keystone_arch");
        const int *ksm  = (const int *)dlsym(h, "pae_pkg_keystone_mode");
        const int *num  = (const int *)dlsym(h, "pae_pkg_number");
        const int *rw   = (const int *)dlsym(h, "pae_pkg_reg_width");
        const int *rc   = (const int *)dlsym(h, "pae_pkg_reg_count");
        const char *const *rn = (const char *const *)dlsym(h, "pae_pkg_reg_names");
        const unsigned *hid   = (const unsigned *)dlsym(h, "pae_pkg_hidden");
        const int *fsl  = (const int *)dlsym(h, "pae_pkg_flags_slot");
        const int *fkd  = (const int *)dlsym(h, "pae_pkg_flags_kind");
        const char *const *rts = (const char *const *)dlsym(h, "pae_pkg_rets");
        const int *dnop = (const int *)dlsym(h, "pae_pkg_delay_nop");
        int (*bld)(char *, size_t, const char *) =
            (int (*)(char *, size_t, const char *))dlsym(h, "pae_pkg_build");
        int (*hst)(void) = (int (*)(void))dlsym(h, "pae_pkg_host");
        const int *elm  = (const int *)dlsym(h, "pae_pkg_elf_machine");
        const int *elb  = (const int *)dlsym(h, "pae_pkg_elf_bits");
        if (!opt || !*opt || !**opt) { dlclose(h); continue; }
        if (!ksa) {
            fprintf(stderr, "pae: skipping %s (no set_keystone_arch, Keystone would not know the architecture)\n", e->d_name);
            dlclose(h);
            continue;
        }

        char *id = pkg_ids[NARCH], *lb = pkg_labels[NARCH];
        snprintf(lb, sizeof pkg_labels[0], "%s", *opt);
        size_t k = 0;
        for (const char *p = lb; *p && k + 1 < sizeof pkg_ids[0]; p++) {
            unsigned char c = (unsigned char)*p;
            if (c == ' ') id[k++] = '-';
            else if (isalnum(c) || c == '-' || c == '_') id[k++] = (char)tolower(c);
            else id[k++] = '_';
        }
        id[k] = 0;

        int dup = 0;
        for (int i = 0; i < NARCH; i++)
            if (!strcasecmp(ALL[i].id, id) || !strcasecmp(ALL[i].label, lb)) dup = 1;
        if (dup) {
            fprintf(stderr, "pae: skipping %s (name '%s' already used)\n", e->d_name, lb);
            dlclose(h);
            continue;
        }

        Arch *a = &ALL[NARCH];
        memset(a, 0, sizeof *a);
        a->id = id;
        a->label = lb;
        a->arch = (ks_arch)*ksa;
        a->mode = ksm ? *ksm : 0;
        a->width = (int)sizeof(void *);
        a->flag_slot = -1;
        a->flag_kind = FK_NONE;
        a->rets = rets_none;
        a->elf_machine = elm ? *elm : 0;
        a->elf_bits = elb ? *elb : 0;

        /* a package that brings registers, a wrapper builder and a host check can run code */
        int any = rn || rc || rw || bld || hst;
        int can = rn && rc && rw && bld && hst && (*rw == 4 || *rw == 8) && *rc >= 1 && *rc <= 32;
        void *bank = can ? calloc((size_t)*rc, (size_t)*rw) : NULL;
        if (can && bank) {
            a->width = *rw;
            a->count = *rc;
            a->names = rn;
            a->data  = bank;
            a->hidden = hid ? *hid : 0;
            if (fkd && fsl && (*fkd == FK_NZCV || *fkd == FK_X86) && *fsl >= 0 && *fsl < *rc) {
                a->flag_slot = *fsl;
                a->flag_kind = *fkd;
            }
            if (rts) a->rets = rts;
            a->delay_nop = dnop ? *dnop : 0;
            a->build = bld;
            a->host  = hst;
        } else if (any) {
            fprintf(stderr, "pae: %s: registers, wrapper builder or host check missing or invalid "
                            "(width 4 or 8, 1 to 32 registers), assemble-only\n", e->d_name);
        }
        pkg_req[NARCH] = num ? *num : 0;
        NUM[NARCH] = 0;
        NARCH++;
    }
    closedir(d);

    /* packages in name order, so unnumbered ones get the same numbers every run */
    for (int i = NBUILTIN + 1; i < NARCH; i++)
        for (int j = i; j > NBUILTIN && strcasecmp(ALL[j - 1].id, ALL[j].id) > 0; j--) {
            Arch ta = ALL[j]; ALL[j] = ALL[j - 1]; ALL[j - 1] = ta;
            int tr = pkg_req[j]; pkg_req[j] = pkg_req[j - 1]; pkg_req[j - 1] = tr;
        }

    /* numbers asked for with set_arch_number first, the rest count after the biggest */
    int top = NBUILTIN;
    for (int i = NBUILTIN; i < NARCH; i++) {
        int r = pkg_req[i];
        if (r < 1) continue;
        int used = r > 999;
        for (int j = 0; j < NARCH && !used; j++) if (NUM[j] == r) used = 1;
        if (used) {
            fprintf(stderr, "pae: number %d for '%s' is not available, using the next free one\n", r, ALL[i].label);
            continue;
        }
        NUM[i] = r;
        if (r > top) top = r;
    }
    for (int i = NBUILTIN; i < NARCH; i++) if (!NUM[i]) NUM[i] = ++top;

    /* menu order = number order (built-ins are 1..NBUILTIN and never move) */
    for (int i = NBUILTIN + 1; i < NARCH; i++)
        for (int j = i; j > NBUILTIN && NUM[j - 1] > NUM[j]; j--) {
            Arch ta = ALL[j]; ALL[j] = ALL[j - 1]; ALL[j - 1] = ta;
            int tn = NUM[j]; NUM[j] = NUM[j - 1]; NUM[j - 1] = tn;
        }
}

static const Arch *find_arch(const char *name) {
    static const struct { const char *alias; int idx; } AL[] = {
        {"arm32",0}, {"arm",0},
        {"x86",1},   {"i386",1},
        {"mips32",2},{"mips",2},
    };
    for (size_t i = 0; i < sizeof AL / sizeof AL[0]; i++)
        if (!strcasecmp(name, AL[i].alias)) return &ALL[AL[i].idx];
    for (int i = NBUILTIN; i < NARCH; i++)
        if (!strcasecmp(name, ALL[i].id) || !strcasecmp(name, ALL[i].label)) return &ALL[i];
    return NULL;
}

/* ── showing and setting registers ───────────────────────────────────────── */

static uint64_t slot_get(const void *base, int width, int i) {
    if (width == 8) return ((const uint64_t *)base)[i];
    return ((const uint32_t *)base)[i];
}

static void slot_put(void *base, int width, int i, uint64_t v) {
    if (width == 8) ((uint64_t *)base)[i] = v;
    else            ((uint32_t *)base)[i] = (uint32_t)v;
}

static void print_reg(const Arch *a, int i, uint64_t v) {
    const char *nm = a->names[i];

    if (i == a->flag_slot && a->flag_kind == FK_NZCV) {
        printf("%-6s = N=%d Z=%d C=%d V=%d\n", nm,
               (int)((v >> 31) & 1), (int)((v >> 30) & 1),
               (int)((v >> 29) & 1), (int)((v >> 28) & 1));
        return;
    }
    if (i == a->flag_slot && a->flag_kind == FK_X86) {
        static const struct { unsigned bit; const char *name; } F[] = {
            {0,"CF"}, {2,"PF"}, {4,"AF"}, {6,"ZF"}, {7,"SF"}, {10,"DF"}, {11,"OF"}
        };
        printf("%-6s = 0x%llx [", nm, (unsigned long long)v);
        int first = 1;
        for (size_t k = 0; k < sizeof F / sizeof F[0]; k++) {
            if ((v >> F[k].bit) & 1) {
                printf("%s%s", first ? "" : " ", F[k].name);
                first = 0;
            }
        }
        puts("]");
        return;
    }
    if (a->width == 8)
        printf("%-6s = 0x%016llx (%lld)\n", nm,
               (unsigned long long)v, (long long)v);
    else
        printf("%-6s = 0x%08x (%d)\n", nm,
               (unsigned)v, (int)(int32_t)(uint32_t)v);
}

/* before == NULL: print every tracked register. Otherwise only changed ones. */
static void show(const Arch *a, const unsigned char *before) {
    int shown = 0;
    for (int i = 0; i < a->count; i++) {
        if (a->hidden & (1u << i)) continue;
        uint64_t cur = slot_get(a->data, a->width, i);
        if (before) {
            uint64_t old = slot_get(before, a->width, i);
            /* x86 flags: ignore the always-set reserved bit and IF */
            if (i == a->flag_slot && a->flag_kind == FK_X86) {
                if ((cur & X86_FLAGS_MASK) == (old & X86_FLAGS_MASK)) continue;
            } else if (old == cur) continue;
        }
        print_reg(a, i, cur);
        shown = 1;
    }
    if (before && !shown) puts("(no register changed)");
}

/* ── persistence ─────────────────────────────────────────────────────────── */
/* one file per architecture: ~/.pae_state_<arch>                            */

typedef struct { char magic[4]; uint32_t version; uint32_t size; } StateHdr;

static void state_path(char *buf, size_t n, const Arch *a) {
    const char *home = getenv("HOME");
    snprintf(buf, n, "%s/.pae_state_%s", (home && *home) ? home : ".", a->id);
}

/* returns 1 if a saved state was loaded */
static int state_load(const Arch *a) {
    if (a->count == 0) return 0;
    char path[512];
    state_path(path, sizeof path, a);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    size_t sz = (size_t)a->count * (size_t)a->width;
    unsigned char *tmp = malloc(sz);
    StateHdr h;
    int ok = 0;
    if (tmp && fread(&h, sizeof h, 1, f) == 1 &&
        !memcmp(h.magic, "PAE1", 4) && h.version == STATE_VER && h.size == sz &&
        fread(tmp, 1, sz, f) == sz) {
        memcpy(a->data, tmp, sz);
        ok = 1;
    } else {
        fprintf(stderr, "pae: ignoring unreadable state file %s\n", path);
    }
    free(tmp);
    fclose(f);
    return ok;
}

static void state_save(const Arch *a) {
    if (a->count == 0) return;
    char path[512], tmp[560];
    state_path(path, sizeof path, a);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);

    size_t sz = (size_t)a->count * (size_t)a->width;
    StateHdr h;
    memcpy(h.magic, "PAE1", 4);
    h.version = STATE_VER;
    h.size = (uint32_t)sz;

    FILE *f = fopen(tmp, "wb");
    if (!f ||
        fwrite(&h, sizeof h, 1, f) != 1 ||
        fwrite(a->data, 1, sz, f) != sz ||
        fclose(f) != 0 ||
        rename(tmp, path) != 0) {
        fprintf(stderr, "pae: could not save state to %s\n", path);
    }
}

/* ── data memory ─────────────────────────────────────────────────────────── */
/* A zeroed RW region that executed code can read and write. It lives at the   */
/* same address every run (DATA_BASE) so programs can use absolute addresses.  */
/* With persistence it is saved next to the registers: ~/.pae_mem_<arch>       */

static unsigned char *dmem;       /* the region */
static unsigned char *dshadow;    /* copy as last saved, to skip needless writes */
static size_t         dsize;

static size_t page_size(void) {
    long p = sysconf(_SC_PAGESIZE);
    return p > 0 ? (size_t)p : 4096;
}

/* "65536", "64k", "1m"; returns 0 on a bad value */
static size_t parse_size(const char *s) {
    char *end;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s) return 0;
    if (*end == 'k' || *end == 'K') { v <<= 10; end++; }
    else if (*end == 'm' || *end == 'M') { v <<= 20; end++; }
    if (*end || v == 0 || v > DATA_MAX) return 0;
    return (size_t)v;
}

/* "2", "0.5"; -1 on a bad value */
static double parse_timeout(const char *s) {
    char *end;
    double v = strtod(s, &end);
    if (end == s || *end || !(v >= 0.001) || v > 86400) return -1;
    return v;
}

static int data_init(size_t size) {
    size_t pg = page_size();
    dsize = (size + pg - 1) / pg * pg;
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0       /* old kernels: the address is only a hint */
#endif
    void *m = mmap((void *)(uintptr_t)DATA_BASE, dsize, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);   /* shared: survives the fork */
    if (m == MAP_FAILED) return -1;
    dmem = m;
    if ((uintptr_t)m != (uintptr_t)DATA_BASE)
        fprintf(stderr, "pae: 0x%x is taken, data memory is at %p instead\n",
                (unsigned)DATA_BASE, m);
    dshadow = calloc(1, dsize);
    return 0;
}

static void data_path(char *buf, size_t n, const Arch *a) {
    const char *home = getenv("HOME");
    snprintf(buf, n, "%s/.pae_mem_%s", (home && *home) ? home : ".", a->id);
}

static void data_load(const Arch *a) {
    char path[512];
    data_path(path, sizeof path, a);
    FILE *f = fopen(path, "rb");
    if (!f) return;
    StateHdr h;
    if (fread(&h, sizeof h, 1, f) == 1 && !memcmp(h.magic, "PAEM", 4) &&
        h.version == STATE_VER && h.size > 0) {
        size_t n = h.size < dsize ? h.size : dsize;
        if (fread(dmem, 1, n, f) != n) {
            fprintf(stderr, "pae: ignoring unreadable memory file %s\n", path);
            memset(dmem, 0, dsize);
        } else if (h.size > dsize) {
            fprintf(stderr, "pae: saved memory is %u bytes, only the first %zu were loaded (use --mem)\n",
                    (unsigned)h.size, dsize);
        }
    } else {
        fprintf(stderr, "pae: ignoring unreadable memory file %s\n", path);
    }
    fclose(f);
    if (dshadow) memcpy(dshadow, dmem, dsize);
}

static void data_save(const Arch *a) {
    if (dshadow && !memcmp(dshadow, dmem, dsize)) return;   /* nothing changed */
    char path[512], tmp[560];
    data_path(path, sizeof path, a);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    StateHdr h;
    memcpy(h.magic, "PAEM", 4);
    h.version = STATE_VER;
    h.size = (uint32_t)dsize;
    FILE *f = fopen(tmp, "wb");
    if (!f || fwrite(&h, sizeof h, 1, f) != 1 ||
        fwrite(dmem, 1, dsize, f) != dsize || fclose(f) != 0 || rename(tmp, path) != 0) {
        fprintf(stderr, "pae: could not save memory to %s\n", path);
        return;
    }
    if (dshadow) memcpy(dshadow, dmem, dsize);
}

/* an absolute address inside the region, or an offset from its start */
static int data_off(const char *s, size_t *off) {
    char *end;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s || *end) return -1;
    uintptr_t base = (uintptr_t)dmem;
    if (v >= base && v - base < dsize) *off = (size_t)(v - base);
    else if (v < dsize)                *off = (size_t)v;
    else return -1;
    return 0;
}

static void cmd_mem(void) {
    printf("data memory: %zu bytes (%zu KB) at %p\n", dsize, dsize >> 10, (void *)dmem);
    puts("  dump <addr> [len]  |  poke <addr> <value> [1|2|4|8]  |  memload <file> [addr]");
}

static void cmd_dump(const char *line) {
    char a[48], l[48];
    int n = sscanf(line, "dump %47s %47s", a, l);
    size_t off, len = 64;
    if (n < 1 || data_off(a, &off) != 0) { printf("usage: dump <addr> [len]  (addr inside %p..%p)\n", (void *)dmem, (void *)(dmem + dsize)); return; }
    if (n == 2) { char *e; len = (size_t)strtoull(l, &e, 0); if (e == l || !len) { puts("bad length"); return; } }
    if (len > dsize - off) len = dsize - off;
    for (size_t i = 0; i < len; i += 16) {
        printf("%p  ", (void *)(dmem + off + i));
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", dmem[off + i + j]); else printf("   ");
            if (j == 7) putchar(' ');
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = dmem[off + i + j];
            putchar(isprint(c) ? c : '.');
        }
        puts("|");
    }
}

static void cmd_poke(const Arch *a, int persist, const char *line) {
    char as[48], vs[48];
    unsigned sz = 1;
    size_t off;
    int n = sscanf(line, "poke %47s %47s %u", as, vs, &sz);
    if (n < 2 || (sz != 1 && sz != 2 && sz != 4 && sz != 8)) { puts("usage: poke <addr> <value> [1|2|4|8]"); return; }
    if (data_off(as, &off) != 0 || off + sz > dsize) { puts("address outside data memory"); return; }
    uint64_t v = strtoull(vs, NULL, 0);
    memcpy(dmem + off, &v, sz);        /* host byte order, same as code that runs here */
    printf("%p <- 0x%llx (%u byte%s)\n", (void *)(dmem + off), (unsigned long long)v, sz, sz > 1 ? "s" : "");
    if (persist) data_save(a);
}

static void cmd_memload(const Arch *a, int persist, const char *line) {
    char path[400], as[48] = "0";
    size_t off;
    if (sscanf(line, "memload %399s %47s", path, as) < 1) { puts("usage: memload <file> [addr]"); return; }
    if (data_off(as, &off) != 0) { puts("address outside data memory"); return; }
    FILE *f = fopen(path, "rb");
    if (!f) { printf("cannot read '%s'\n", path); return; }
    size_t r = fread(dmem + off, 1, dsize - off, f);
    int more = fgetc(f) != EOF;
    fclose(f);
    printf("loaded %zu bytes at %p%s\n", r, (void *)(dmem + off), more ? " (file truncated: memory full)" : "");
    if (persist) data_save(a);
}

/* ── code loader ─────────────────────────────────────────────────────────── */

static int load_code(void *mem, const unsigned char *bytes, size_t size) {
#ifdef __APPLE__
    pthread_jit_write_protect_np(0);
    memcpy(mem, bytes, size);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(mem, size);
    return 0;
#else
    if (mprotect(mem, MEM_SIZE, PROT_READ | PROT_WRITE) != 0) return -1;
    memcpy(mem, bytes, size);
    if (mprotect(mem, MEM_SIZE, PROT_READ | PROT_EXEC) != 0) return -1;
#ifdef __GNUC__
    __builtin___clear_cache((char *)mem, (char *)mem + size);
#endif
    return 0;
#endif
}

/* ── host detection ──────────────────────────────────────────────────────── */
/* 1 = this process's CPU can run the architecture directly, 0 = bytes only  */

static int host_matches(const Arch *a) {
    if (a->host) return a->host();   /* AAI package */
    if (a->count == 0) return 0;     /* AAI package without registers: assemble only */
#if defined(__arm__)
    return a->arch == KS_ARCH_ARM && a->mode == KS_MODE_ARM;
#elif defined(__i386__)
    return a->arch == KS_ARCH_X86 && (a->mode & KS_MODE_32);
#elif defined(__mips__)
    if (a->arch != KS_ARCH_MIPS) return 0;
    int hostbig = (MIPS_ENDIAN == KS_MODE_BIG_ENDIAN);
    int wantbig = (a->mode & KS_MODE_BIG_ENDIAN) != 0;
    return (a->mode & KS_MODE_MIPS32) != 0 && hostbig == wantbig;
#else
    (void)a;
    return 0;
#endif
}

/* ── trailing return stripping ───────────────────────────────────────────── */
/* A file or block usually ends with "ret". Inside the wrapper that would   */
/* skip the register save and crash, so the last return is removed.         */

static size_t trim_tail(const char *s, size_t n) {
    while (n && (isspace((unsigned char)s[n - 1]) || s[n - 1] == ';')) n--;
    return n;
}

static size_t stmt_start(const char *s, size_t n) {
    size_t i = n;
    while (i && s[i - 1] != '\n' && s[i - 1] != ';') i--;
    return i;
}

static int stmt_eq(const char *s, size_t a, size_t b, const char *want) {
    while (a < b && isspace((unsigned char)s[a])) a++;
    size_t len = b - a;
    return len == strlen(want) && strncasecmp(s + a, want, len) == 0;
}

static void strip_ret(char *s, const Arch *a) {
    size_t n  = trim_tail(s, strlen(s));
    size_t st = stmt_start(s, n);

    if (a->delay_nop && stmt_eq(s, st, n, "nop")) {
        n  = trim_tail(s, st);
        st = stmt_start(s, n);
    }
    for (const char *const *r = a->rets; *r; r++) {
        if (stmt_eq(s, st, n, *r)) { s[st] = 0; return; }
    }
}

static int blank(const char *s) {
    for (; *s; s++)
        if (!isspace((unsigned char)*s) && *s != ';') return 0;
    return 1;
}

/* ── running one block of code ───────────────────────────────────────────── */

typedef struct {
    ks_engine  *ks;
    void       *mem;
    const Arch *arch;
    int         persist;
    int         can_exec;   /* 1 = host CPU matches arch exactly */
} Ctx;

/* ── crash isolation ─────────────────────────────────────────────────────── */
/* Every block runs in a forked child. If the code crashes (SIGSEGV, SIGBUS,    */
/* SIGILL ...), exits the process, or is stopped with Ctrl-C, only the child is */
/* lost: the registers stay as they were and the session goes on. The child     */
/* sends the registers back through a pipe. Data memory is a shared mapping, so */
/* what the code wrote there survives the fork (even when the code then crashes).*/

typedef struct { int sig; int code; uint64_t addr; } CrashMsg;

static int    crash_fd = -1;
static double block_timeout;      /* --timeout: seconds a block may run, 0 = no limit */
static char crash_stack[64 * 1024];

static void crash_handler(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    unsigned char buf[1 + sizeof(CrashMsg)];
    CrashMsg m;
    m.sig  = sig;
    m.code = si ? si->si_code : 0;
    m.addr = si ? (uint64_t)(uintptr_t)si->si_addr : 0;
    buf[0] = 'F';
    memcpy(buf + 1, &m, sizeof m);
    ssize_t r = write(crash_fd, buf, sizeof buf);
    (void)r;
    _exit(128 + sig);
}

static void child_run(const Arch *a, void *mem, int fd, size_t size) {
    crash_fd = fd;
    stack_t ss;
    memset(&ss, 0, sizeof ss);
    ss.ss_sp = crash_stack;
    ss.ss_size = sizeof crash_stack;
    sigaltstack(&ss, NULL);                       /* the handler must work even if sp is wrecked */

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGSYS };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) sigaction(sigs[i], &sa, NULL);

    ((void (*)(void *))mem)(a->data);

    unsigned char out[1 + 256];
    out[0] = 'R';
    memcpy(out + 1, a->data, size);
    ssize_t r = write(fd, out, 1 + size);
    (void)r;
    _exit(0);
}

static const char *sig_name(int s) {
    switch (s) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS:  return "SIGBUS";
    case SIGILL:  return "SIGILL";
    case SIGFPE:  return "SIGFPE";
    case SIGTRAP: return "SIGTRAP";
    case SIGSYS:  return "SIGSYS";
    case SIGABRT: return "SIGABRT";
    case SIGKILL: return "SIGKILL";
    case SIGTERM: return "SIGTERM";
    default:      return "signal";
    }
}

static void report_crash(int sig, const CrashMsg *m) {
    printf("crashed: %s (%s)", sig_name(sig), strsignal(sig));
    if (m && (sig == SIGSEGV || sig == SIGBUS))
        printf(" at address 0x%llx", (unsigned long long)m->addr);
    putchar('\n');
}

/* 1 = the code ran and the registers came back, 0 = it did not (the reason is printed) */
static int run_isolated(const Ctx *c) {
    const Arch *a = c->arch;
    size_t size = (size_t)a->count * (size_t)a->width;
    int fds[2];
    pid_t pid;

    fflush(NULL);
    if (pipe(fds) != 0) {
        puts("pae: cannot start a child process, running without crash protection");
        ((void (*)(void *))c->mem)(a->data);
        return 1;
    }
    pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]);
        puts("pae: cannot start a child process, running without crash protection");
        ((void (*)(void *))c->mem)(a->data);
        return 1;
    }
    if (pid == 0) {
        close(fds[0]);
        child_run(a, c->mem, fds[1], size);       /* does not return */
    }
    close(fds[1]);

    /* Ctrl-C stops the code, not PAE */
    struct sigaction ign, old;
    memset(&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGINT, &ign, &old);

    unsigned char buf[1 + 256];
    size_t n = 0;
    int timed_out = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        int wait_ms = -1;
        if (block_timeout > 0 && !timed_out) {
            struct timespec t1;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double used = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
            double left = block_timeout - used;
            if (left <= 0) { kill(pid, SIGKILL); timed_out = 1; continue; }
            wait_ms = (int)(left * 1000.0) + 1;
        }
        struct pollfd pf;
        pf.fd = fds[0]; pf.events = POLLIN; pf.revents = 0;
        int pr = poll(&pf, 1, wait_ms);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) continue;                    /* the time check at the top decides */
        ssize_t r = read(fds[0], buf + n, sizeof buf - n);
        if (r > 0) { n += (size_t)r; if (n == sizeof buf) break; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    close(fds[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    sigaction(SIGINT, &old, NULL);

    if (n >= 1 + size && buf[0] == 'R' && WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        memcpy(a->data, buf + 1, size);
        return 1;
    }

    if (timed_out) {
        printf("timed out after %g s: the code was stopped\n", block_timeout);
        goto lost;
    }
    if (n >= 1 + sizeof(CrashMsg) && buf[0] == 'F') {
        CrashMsg m;
        memcpy(&m, buf + 1, sizeof m);
        if (m.sig > 0 && m.sig < 65) { report_crash(m.sig, &m); goto lost; }
    }
    if (WIFSIGNALED(st)) {
        if (WTERMSIG(st) == SIGINT) puts("interrupted (Ctrl-C)");
        else                        report_crash(WTERMSIG(st), NULL);
    } else if (WIFEXITED(st)) {
        printf("the code ended the process (exit status %d) instead of returning\n", WEXITSTATUS(st));
    } else {
        puts("the code stopped unexpectedly");
    }
lost:
    puts("registers unchanged (data memory may have changed)");
    return 0;
}

/* returns 0 on success, 1 on an error */
static int exec_block(Ctx *c, const char *code) {
    const Arch *a = c->arch;
    unsigned char *bytes = NULL;
    size_t size = 0, count = 0;
    char *user = NULL, *src = NULL;
    int rc = 0;

    if (blank(code)) { puts("(nothing to run)"); return 0; }

    /* host can't run this architecture directly: show the bytes */
    if (!c->can_exec) {
        if (ks_asm(c->ks, code, 0, &bytes, &size, &count) != KS_ERR_OK) {
            printf("asm error: %s\n", ks_strerror(ks_errno(c->ks)));
            return 1;
        }
        printf("bytes (%zu):", size);
        for (size_t i = 0; i < size; i++) printf(" %02x", bytes[i]);
        putchar('\n');
        ks_free(bytes);
        return 0;
    }

    user = strdup(code);
    if (!user) { puts("out of memory"); return 1; }
    strip_ret(user, a);
    if (blank(user)) { puts("(nothing to run)"); free(user); return 0; }

    size_t sn = strlen(user) + 16384;
    src = malloc(sn);
    if (!src) { puts("out of memory"); free(user); return 1; }

    if (a->build(src, sn, user) != 0) {
        puts("internal error: generated source too large");
        rc = 1; goto done;
    }
    if (ks_asm(c->ks, src, 0, &bytes, &size, &count) != KS_ERR_OK) {
        printf("asm error: %s\n", ks_strerror(ks_errno(c->ks)));
        rc = 1; goto done;
    }
    if (size == 0)        { puts("(nothing assembled)"); ks_free(bytes); goto done; }
    if (size > MEM_SIZE)  { puts("code too big");         ks_free(bytes); rc = 1; goto done; }

    if (load_code(c->mem, bytes, size) != 0) {
        puts("failed to make code executable");
        ks_free(bytes);
        rc = 1; goto done;
    }
    ks_free(bytes);

    {
        unsigned char before[256];
        memcpy(before, a->data, (size_t)a->count * (size_t)a->width);
        if (!run_isolated(c)) { rc = 1; goto done; }
        show(a, before);
        if (c->persist) { state_save(a); data_save(a); }
    }

done:
    free(src);
    free(user);
    return rc;
}

/* ── small helpers ───────────────────────────────────────────────────────── */

/* 1 = line read, 0 = EOF, -1 = line too long (rest of it discarded) */
static int read_line(const char *prompt, char *buf, size_t n) {
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)n, stdin)) return 0;
    if (!strchr(buf, '\n') && !feof(stdin)) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {}
        return -1;
    }
    size_t len = strcspn(buf, "\r\n");
    buf[len] = 0;
    while (len && isspace((unsigned char)buf[len - 1])) buf[--len] = 0;
    return 1;
}

static int looks_like_file(const char *s) {
    if (strchr(s, '\n')) return 0;
    size_t n = strlen(s);
    if (n >= 4 && !strcasecmp(s + n - 4, ".asm")) return 1;
    if (n >= 2 && !strcasecmp(s + n - 2, ".s"))   return 1;
    return 0;
}

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    while (buf) {
        if (len + 1 >= cap) {
            if (cap >= FILE_MAX) { free(buf); buf = NULL; break; }
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); buf = NULL; break; }
            buf = nb;
        }
        size_t r = fread(buf + len, 1, cap - len - 1, f);
        if (r == 0) break;
        len += r;
    }
    if (buf) buf[len] = 0;
    fclose(f);
    return buf;
}

static void cmd_set(Ctx *c, const char *line) {
    const Arch *a = c->arch;
    char name[16], val[64];
    if (sscanf(line, "set %15s %63s", name, val) != 2) {
        puts("usage: set <reg> <value>");
        return;
    }
    for (int i = 0; i < a->count; i++) {
        if (a->hidden & (1u << i)) continue;
        if (!strcasecmp(name, a->names[i])) {
            slot_put(a->data, a->width, i, strtoull(val, NULL, 0));
            print_reg(a, i, slot_get(a->data, a->width, i));
            if (c->persist) state_save(a);
            return;
        }
    }
    printf("unknown or untracked register '%s' (type regs to list them)\n", name);
}

/* ── linker (--asm) ──────────────────────────────────────────────────────── */
/* PAE does its own linking: the assembled bytes become a relocatable ELF      */
/* object (OUT.o) and a static ELF executable (OUT), or raw bytes (--no-elf).  */
/* The entry point is the first byte of the code, symbol _start. Nothing is    */
/* wrapped or stripped: the program has to end itself (exit syscall, loop...). */

typedef struct {
    int      bits;      /* 32 or 64 (ELF class) */
    int      big;       /* 1 = big-endian */
    int      machine;   /* e_machine */
    unsigned flags;     /* e_flags */
    int      thumb;     /* ARM Thumb: entry and _start get bit 0 set */
} ElfInfo;

typedef struct { unsigned char *p; size_t n, cap; int big, err; } EBuf;

#define ELF_BASE 0x400000ull

/* 0 = ok, -1 = no ELF description for this architecture */
static int elf_info(const Arch *a, ElfInfo *e) {
    int m = a->mode;
    memset(e, 0, sizeof *e);
    e->big = (m & KS_MODE_BIG_ENDIAN) != 0;
    switch (a->arch) {
    case KS_ARCH_ARM:
        e->machine = 40; e->bits = 32; e->flags = 0x05000000u;     /* EABI v5 */
        e->thumb = (m & KS_MODE_THUMB) != 0;
        break;
    case KS_ARCH_ARM64:
        e->machine = 183; e->bits = 64;
        break;
    case KS_ARCH_X86:
        if (m & KS_MODE_64) { e->machine = 62; e->bits = 64; }
        else if (m & KS_MODE_32) { e->machine = 3; e->bits = 32; }
        break;                                                      /* 16-bit: no ELF */
    case KS_ARCH_MIPS:
        e->machine = 8;
        if (m & KS_MODE_MIPS64) { e->bits = 64; e->flags = 0x60000001u; }   /* MIPS64, noreorder */
        else                    { e->bits = 32; e->flags = 0x50001001u; }   /* MIPS32, o32, noreorder */
        break;
    case KS_ARCH_PPC:
        if (m & KS_MODE_PPC64) { e->machine = 21; e->bits = 64; }
        else                   { e->machine = 20; e->bits = 32; }
        break;
    case KS_ARCH_SPARC:
        e->big = 1;
        if (m & KS_MODE_SPARC64) { e->machine = 43; e->bits = 64; }
        else                     { e->machine = 2;  e->bits = 32; }
        break;
    case KS_ARCH_SYSTEMZ:
        e->machine = 22; e->bits = 64; e->big = 1;
        break;
    case KS_ARCH_HEXAGON:
        e->machine = 164; e->bits = 32;
        break;
    default:
        break;
    }
    /* an AAI package can say it itself (set_elf_machine / set_elf_bits) */
    if (a->elf_machine) e->machine = a->elf_machine;
    if (a->elf_bits)    e->bits = a->elf_bits;
    return (e->machine && (e->bits == 32 || e->bits == 64)) ? 0 : -1;
}

static void eb_byte(EBuf *b, unsigned v) {
    if (b->err) return;
    if (b->n == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        unsigned char *np = realloc(b->p, nc);
        if (!np) { b->err = 1; return; }
        b->p = np; b->cap = nc;
    }
    b->p[b->n++] = (unsigned char)v;
}

/* a number of `bytes` bytes in the file's byte order */
static void eb_num(EBuf *b, uint64_t v, int bytes) {
    for (int i = 0; i < bytes; i++) {
        int sh = b->big ? (bytes - 1 - i) * 8 : i * 8;
        eb_byte(b, (unsigned)((v >> sh) & 0xff));
    }
}

static void eb_raw(EBuf *b, const void *d, size_t len) {
    for (size_t i = 0; i < len; i++) eb_byte(b, ((const unsigned char *)d)[i]);
}

static void eb_pad(EBuf *b, size_t align) { while (b->n % align) eb_byte(b, 0); }

static size_t up(size_t v, size_t a) { return (v + a - 1) / a * a; }

/* ELF header; exec = ET_EXEC with one program header, else ET_REL with section headers */
static void elf_header(EBuf *b, const ElfInfo *e, int exec, uint64_t entry,
                       uint64_t shoff, int shnum, int shstrndx) {
    int w = e->bits / 8;
    int eh = w == 8 ? 64 : 52, ph = w == 8 ? 56 : 32, sh = w == 8 ? 64 : 40;
    static const unsigned char magic[4] = { 0x7f, 'E', 'L', 'F' };
    eb_raw(b, magic, 4);
    eb_byte(b, w == 8 ? 2 : 1);
    eb_byte(b, e->big ? 2 : 1);
    eb_byte(b, 1);                                  /* EV_CURRENT */
    for (int i = 7; i < 16; i++) eb_byte(b, 0);
    eb_num(b, exec ? 2 : 1, 2);                     /* e_type */
    eb_num(b, (uint64_t)e->machine, 2);
    eb_num(b, 1, 4);                                /* e_version */
    eb_num(b, entry, w);
    eb_num(b, exec ? (uint64_t)eh : 0, w);          /* e_phoff */
    eb_num(b, shoff, w);
    eb_num(b, e->flags, 4);
    eb_num(b, (uint64_t)eh, 2);
    eb_num(b, exec ? (uint64_t)ph : 0, 2);
    eb_num(b, exec ? 1 : 0, 2);
    eb_num(b, (uint64_t)sh, 2);
    eb_num(b, (uint64_t)shnum, 2);
    eb_num(b, (uint64_t)shstrndx, 2);
}

/* where the first code byte lives in the executable */
static uint64_t elf_code_off(const ElfInfo *e) {
    return up(e->bits == 64 ? 64 + 56 : 52 + 32, 16);
}

/* static executable: headers + code in one read/execute segment */
static unsigned char *elf_exec(const ElfInfo *e, const unsigned char *code, size_t size, size_t *len) {
    EBuf b = { NULL, 0, 0, e->big, 0 };
    int w = e->bits / 8;
    uint64_t off = elf_code_off(e), total = off + size;

    elf_header(&b, e, 1, ELF_BASE + off + (e->thumb ? 1 : 0), 0, 0, 0);
    if (w == 8) {
        eb_num(&b, 1, 4); eb_num(&b, 5, 4);                     /* PT_LOAD, R+X */
        eb_num(&b, 0, 8); eb_num(&b, ELF_BASE, 8); eb_num(&b, ELF_BASE, 8);
        eb_num(&b, total, 8); eb_num(&b, total, 8); eb_num(&b, 0x10000, 8);
    } else {
        eb_num(&b, 1, 4);
        eb_num(&b, 0, 4); eb_num(&b, ELF_BASE, 4); eb_num(&b, ELF_BASE, 4);
        eb_num(&b, total, 4); eb_num(&b, total, 4); eb_num(&b, 5, 4); eb_num(&b, 0x10000, 4);
    }
    while (b.n < off) eb_byte(&b, 0);
    eb_raw(&b, code, size);
    if (b.err) { free(b.p); return NULL; }
    *len = b.n;
    return b.p;
}

static void elf_shdr(EBuf *b, int w, uint32_t name, uint32_t type, uint64_t flags, uint64_t off,
                     uint64_t size, uint32_t link, uint32_t info, uint64_t align, uint64_t ent) {
    eb_num(b, name, 4); eb_num(b, type, 4);
    eb_num(b, flags, w);
    eb_num(b, 0, w);                                /* sh_addr */
    eb_num(b, off, w); eb_num(b, size, w);
    eb_num(b, link, 4); eb_num(b, info, 4);
    eb_num(b, align, w); eb_num(b, ent, w);
}

/* relocatable object: .text plus a symbol table that holds the global _start */
static unsigned char *elf_object(const ElfInfo *e, const unsigned char *code, size_t size, size_t *len) {
    static const char shstr[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
    static const char strtab[] = "\0_start";
    const size_t shstr_n = sizeof shstr, str_n = sizeof strtab;      /* both include the final NUL */
    EBuf b = { NULL, 0, 0, e->big, 0 };
    int w = e->bits / 8;
    size_t hdr = w == 8 ? 64 : 52, symsz = w == 8 ? 24 : 16;
    size_t text_off  = up(hdr, 16);
    size_t sym_off   = up(text_off + size, 8);
    size_t str_off   = sym_off + 3 * symsz;
    size_t shstr_off = str_off + str_n;
    size_t sh_off    = up(shstr_off + shstr_n, 8);
    uint64_t sval = e->thumb ? 1 : 0;

    elf_header(&b, e, 0, 0, sh_off, 5, 4);
    while (b.n < text_off) eb_byte(&b, 0);
    eb_raw(&b, code, size);
    eb_pad(&b, 8);

    /* symbols: null, .text section, _start */
    for (size_t i = 0; i < symsz; i++) eb_byte(&b, 0);
    if (w == 8) {
        eb_num(&b, 0, 4); eb_byte(&b, 3); eb_byte(&b, 0); eb_num(&b, 1, 2); eb_num(&b, 0, 8); eb_num(&b, 0, 8);
        eb_num(&b, 1, 4); eb_byte(&b, 0x12); eb_byte(&b, 0); eb_num(&b, 1, 2); eb_num(&b, sval, 8); eb_num(&b, size, 8);
    } else {
        eb_num(&b, 0, 4); eb_num(&b, 0, 4); eb_num(&b, 0, 4); eb_byte(&b, 3); eb_byte(&b, 0); eb_num(&b, 1, 2);
        eb_num(&b, 1, 4); eb_num(&b, sval, 4); eb_num(&b, size, 4); eb_byte(&b, 0x12); eb_byte(&b, 0); eb_num(&b, 1, 2);
    }
    eb_raw(&b, strtab, str_n);
    eb_raw(&b, shstr, shstr_n);
    eb_pad(&b, 8);

    for (size_t i = 0; i < (w == 8 ? 64u : 40u); i++) eb_byte(&b, 0);    /* null section */
    elf_shdr(&b, w, 1,  1, 6, text_off, size, 0, 0, 4, 0);                /* .text: PROGBITS, A+X */
    elf_shdr(&b, w, 7,  2, 0, sym_off, 3 * symsz, 3, 2, 8, symsz);        /* .symtab, first global = 2 */
    elf_shdr(&b, w, 15, 3, 0, str_off, str_n, 0, 0, 1, 0);                /* .strtab */
    elf_shdr(&b, w, 23, 3, 0, shstr_off, shstr_n, 0, 0, 1, 0);            /* .shstrtab */
    if (b.err) { free(b.p); return NULL; }
    *len = b.n;
    return b.p;
}

/* OUT.o next to OUT: the last extension of the file name is replaced by .o */
static void obj_name(char *dst, size_t n, const char *out) {
    const char *slash = strrchr(out, '/');
    const char *base = slash ? slash + 1 : out;
    const char *dot = strrchr(base, '.');
    size_t len = (dot && dot != base) ? (size_t)(dot - out) : strlen(out);
    snprintf(dst, n, "%.*s.o", (int)len, out);
}

static int write_out(const char *path, const void *data, size_t len, mode_t mode) {
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "pae: cannot write %s\n", path);
        if (f) fclose(f);
        return -1;
    }
    if (fclose(f) != 0) { fprintf(stderr, "pae: cannot write %s\n", path); return -1; }
    chmod(path, mode);
    return 0;
}

/* --asm: assemble target (a file or inline code) and write OUT.o and OUT */
static int asm_link(ks_engine *ks, const Arch *a, const char *target, const char *out, int raw) {
    char obj[600];
    ElfInfo e;
    unsigned char *at0 = NULL, *atx = NULL, *file = NULL, *objb = NULL;
    size_t n0 = 0, nx = 0, flen = 0, olen = 0, cnt = 0;
    char *code;
    int rc = 1;

    obj_name(obj, sizeof obj, out);
    if (!strcmp(obj, out)) {
        fputs("pae: the output name must not end in .o (that file is the object)\n", stderr);
        return 1;
    }
    int have_elf = elf_info(a, &e) == 0;
    if (!have_elf && !raw) {
        fprintf(stderr, "pae: no ELF format known for %s (use --no-elf for raw bytes)\n", a->id);
        return 1;
    }

    if (looks_like_file(target)) {
        code = read_file(target);
        if (!code) { fprintf(stderr, "pae: cannot read '%s' (not found, or larger than 1 MB)\n", target); return 1; }
    } else {
        code = strdup(target);
        if (!code) { fputs("pae: out of memory\n", stderr); return 1; }
    }
    if (blank(code)) { fputs("pae: nothing to assemble\n", stderr); free(code); return 1; }

    /* the object and the raw file are assembled at 0, the executable where it will be loaded,
       so absolute addresses and labels come out right in each */
    if (ks_asm(ks, code, 0, &at0, &n0, &cnt) != KS_ERR_OK) {
        fprintf(stderr, "asm error: %s\n", ks_strerror(ks_errno(ks)));
        goto done;
    }
    if (n0 == 0) { fputs("pae: nothing assembled\n", stderr); goto done; }

    if (raw) {
        file = at0; flen = n0;
    } else {
        if (ks_asm(ks, code, ELF_BASE + elf_code_off(&e), &atx, &nx, &cnt) != KS_ERR_OK) {
            fprintf(stderr, "asm error: %s\n", ks_strerror(ks_errno(ks)));
            goto done;
        }
        file = elf_exec(&e, atx, nx, &flen);
        if (!file) { fputs("pae: out of memory\n", stderr); goto done; }
    }
    if (have_elf) {
        objb = elf_object(&e, at0, n0, &olen);
        if (!objb) { fputs("pae: out of memory\n", stderr); goto done; }
        if (write_out(obj, objb, olen, 0644) != 0) goto done;
    }
    if (write_out(out, file, flen, raw ? 0644 : 0755) != 0) goto done;

    if (have_elf) printf("wrote %s and %s (%zu bytes of code)\n", obj, out, n0);
    else          printf("wrote %s (%zu bytes of code; no ELF format known for %s, so no .o)\n", out, n0, a->id);
    rc = 0;

done:
    if (file && file != at0) free(file);
    free(objb);
    if (at0) ks_free(at0);
    if (atx) ks_free(atx);
    free(code);
    return rc;
}

/* menu: returns an index into ARCHES, or -1 on EOF */
static int menu_pick(void) {
    puts("Select architecture:");
    for (int i = 0; i < NARCH; i++)
        printf("  %d) %s%s%s\n", NUM[i], ALL[i].label,
               i == 0 ? "  (default)" : "",
               ks_arch_supported(ALL[i].arch) ? "" : "  [not in this build]");
    printf("choice> ");
    fflush(stdout);

    char buf[16];
    if (!fgets(buf, sizeof buf, stdin)) return -1;
    int ch = atoi(buf);
    for (int i = 0; i < NARCH; i++)
        if (NUM[i] == ch) return i;
    return 0;
}

static void usage(void) {
    fputs("usage: " PAE_NAME " [--persist] [--mem=SIZE] [--timeout=SECONDS] [--arch=ARCH]\n"
          "       " PAE_NAME " --arch=ARCH FILE.s|FILE.asm\n"
          "       " PAE_NAME " --exec FILE --arch=ARCH\n"
          "       " PAE_NAME " --arch=ARCH \"code\"\n"
          "       " PAE_NAME " --asm [--no-elf] --arch=ARCH FILE.s|\"code\" -o OUT\n"
          "ARCH: arm32 x86 mips32, plus any package installed with aai\n"
          "Running a file or code always uses a persisted session.\n"
          "--timeout=SECONDS stops a block that runs longer than that (default: no limit)\n"
          "--version prints the version\n"
          "--mem=SIZE sets the data memory (default 64k; 128k, 1m ...), mapped at 0x10000000\n"
          "--asm assembles and links without running: OUT.o and OUT (ELF executable, or raw bytes with --no-elf)\n", stderr);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    load_packages();
    int persist = 0;
    const char *arch_name = NULL, *target = NULL, *out_name = NULL;
    int asm_mode = 0, no_elf = 0;
    size_t mem_size = DATA_DEFAULT;

    for (int i = 1; i < argc; i++) {
        const char *s = argv[i];
        if (!strcmp(s, "--persist")) {
            persist = 1;
        } else if (!strcmp(s, "--asm")) {
            asm_mode = 1;
        } else if (!strcmp(s, "--no-elf")) {
            no_elf = 1;
        } else if (!strcmp(s, "-o") || !strcmp(s, "--output")) {
            if (++i >= argc) { fprintf(stderr, "pae: %s needs a file name\n", s); usage(); return 2; }
            out_name = argv[i];
        } else if (!strncmp(s, "--output=", 9)) {
            out_name = s + 9;
        } else if (!strcmp(s, "--version")) {
            unsigned kmaj = 0, kmin = 0;
            ks_version(&kmaj, &kmin);
            printf(PAE_NAME " " PAE_VERSION " (Personal Assembly Executor), keystone %u.%u\n", kmaj, kmin);
            return 0;
        } else if (!strncmp(s, "--timeout=", 10)) {
            block_timeout = parse_timeout(s + 10);
            if (block_timeout < 0) { fputs("pae: bad --timeout (seconds, 0.001 to 86400)\n", stderr); return 2; }
        } else if (!strcmp(s, "--timeout")) {
            if (++i >= argc || (block_timeout = parse_timeout(argv[i])) < 0) { fputs("pae: --timeout needs seconds (e.g. 2 or 0.5)\n", stderr); return 2; }
        } else if (!strncmp(s, "--mem=", 6)) {
            mem_size = parse_size(s + 6);
            if (!mem_size) { fputs("pae: bad --mem size (1 byte to 64m)\n", stderr); return 2; }
        } else if (!strcmp(s, "--mem")) {
            if (++i >= argc || !(mem_size = parse_size(argv[i]))) { fputs("pae: --mem needs a size (e.g. 64k, 1m)\n", stderr); return 2; }
        } else if (!strncmp(s, "--arch=", 7)) {
            arch_name = s + 7;
        } else if (!strcmp(s, "--arch")) {
            if (++i >= argc) { fputs("pae: --arch needs a value\n", stderr); usage(); return 2; }
            arch_name = argv[i];
        } else if (!strncmp(s, "--exec=", 7)) {
            if (target) { fputs("pae: only one file or code argument\n", stderr); return 2; }
            target = s + 7;
        } else if (!strcmp(s, "--exec")) {
            if (++i >= argc) { fputs("pae: --exec needs a file\n", stderr); usage(); return 2; }
            if (target) { fputs("pae: only one file or code argument\n", stderr); return 2; }
            target = argv[i];
        } else if (s[0] == '-' && s[1] == '-') {
            fprintf(stderr, "pae: unknown option '%s'\n", s);
            usage();
            return 2;
        } else {
            if (target) { fputs("pae: only one file or code argument\n", stderr); return 2; }
            target = s;
        }
    }

    const Arch *arch = NULL;
    if (arch_name) {
        arch = find_arch(arch_name);
        if (!arch) {
            fprintf(stderr, "pae: unknown architecture '%s'\n", arch_name);
            usage();
            return 2;
        }
    }
    if (target && !arch) {
        fputs("pae: --arch is required when running a file or code\n", stderr);
        return 2;
    }
    if (asm_mode) {
        if (!target)   { fputs("pae: --asm needs a file or code to assemble\n", stderr); return 2; }
        if (!out_name || !*out_name) { fputs("pae: --asm needs -o OUTPUT\n", stderr); return 2; }
    } else if (no_elf || out_name) {
        fprintf(stderr, "pae: %s only works together with --asm\n", no_elf ? "--no-elf" : "-o");
        return 2;
    }
    if (target && !asm_mode) persist = 1;

    ks_engine *ks = NULL;
    if (arch) {
        ks_err e = ks_open(arch->arch, arch->mode, &ks);
        if (e != KS_ERR_OK) {
            fprintf(stderr, "pae: ks_open failed for %s: %s (is it in this Keystone build?)\n",
                    arch->id, ks_strerror(e));
            return 1;
        }
    } else {
        for (;;) {
            int idx = menu_pick();
            if (idx < 0) return 1;
            arch = &ALL[idx];
            ks_err e = ks_open(arch->arch, arch->mode, &ks);
            if (e == KS_ERR_OK) break;
            printf("ks_open failed: %s -- pick another architecture\n", ks_strerror(e));
        }
    }

    if (asm_mode) {
        int arc = asm_link(ks, arch, target, out_name, no_elf);
        ks_close(ks);
        return arc;
    }

#ifdef __APPLE__
    void *mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
    void *mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (mem == MAP_FAILED) { fputs("pae: mmap failed\n", stderr); return 1; }

    if (data_init(mem_size) != 0) { fputs("pae: cannot map data memory\n", stderr); return 1; }
    Ctx ctx = { ks, mem, arch, persist, host_matches(arch) };
    int loaded = persist ? state_load(arch) : 0;
    if (persist) data_load(arch);

    /* ── file or inline code: run once and exit ── */
    if (target) {
        char *code;
        if (looks_like_file(target)) {
            code = read_file(target);
            if (!code) {
                fprintf(stderr, "pae: cannot read '%s' (not found, or larger than 1 MB)\n", target);
                return 1;
            }
        } else {
            code = strdup(target);
            if (!code) { fputs("pae: out of memory\n", stderr); return 1; }
        }
        if (!ctx.can_exec)
            fprintf(stderr, "note: host CPU doesn't match %s -- printing bytes only\n", arch->id);
        int rc = exec_block(&ctx, code);
        free(code);
        ks_close(ks);
        return rc;
    }

    /* ── REPL ── */
    char line[256];
    char *blk = malloc(BLOCK_MAX);
    if (!blk) { fputs("pae: out of memory\n", stderr); return 1; }

    printf("PAE - Personal Assembly Executor [" PAE_NAME "] (%s%s)\n", arch->id,
           persist ? (loaded ? ", persist on, saved registers loaded" : ", persist on") : "");
    printf("data memory: %zu KB at %p (type mem for commands)\n", dsize >> 10, (void *)dmem);
    puts("commands: regs, reset, set <reg> <value>, mem, dump, poke, memload, { ... } for multi-line, quit");
    if (!ctx.can_exec)
        puts("note: this CPU can't run that architecture -- lines will be assembled and shown as bytes only");

    int done = 0;
    while (!done) {
        int r = read_line("pae> ", line, sizeof line);
        if (r == 0) break;
        if (r < 0) { puts("line too long (max 255 chars)"); continue; }
        if (!*line) continue;
        if (!strcmp(line, "quit")) break;

        if (!strcmp(line, "reset")) {
            memset(arch->data, 0, (size_t)arch->count * (size_t)arch->width);
            memset(dmem, 0, dsize);
            puts("registers and data memory cleared");
            if (persist) { state_save(arch); data_save(arch); }
            continue;
        }
        if (!strcmp(line, "regs"))          { show(arch, NULL); continue; }
        if (!strncmp(line, "set ", 4))      { cmd_set(&ctx, line); continue; }
        if (!strcmp(line, "mem"))           { cmd_mem(); continue; }
        if (!strncmp(line, "dump ", 5))     { cmd_dump(line); continue; }
        if (!strncmp(line, "poke ", 5))     { cmd_poke(arch, persist, line); continue; }
        if (!strncmp(line, "memload ", 8))  { cmd_memload(arch, persist, line); continue; }

        if (!strcmp(line, "{")) {
            size_t len = 0;
            int ok = 1;
            blk[0] = 0;
            for (;;) {
                int rr = read_line("  ... ", line, sizeof line);
                if (rr == 0) { puts("\n(unterminated block discarded)"); ok = 0; done = 1; break; }
                if (rr < 0)  { puts("line too long (max 255 chars)"); continue; }
                if (!strcmp(line, "}")) break;
                size_t l = strlen(line);
                if (len + l + 2 > BLOCK_MAX) { ok = 0; continue; }
                memcpy(blk + len, line, l);
                len += l;
                blk[len++] = '\n';
                blk[len] = 0;
            }
            if (!ok && !done) puts("block too large");
            if (ok) exec_block(&ctx, blk);
            continue;
        }

        exec_block(&ctx, line);
    }

    free(blk);
    ks_close(ks);
    return 0;
}
