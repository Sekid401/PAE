/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 sekid. See the LICENSE file. */

/*
 * aai_pkg.h - what an AAI package (a .so) says about itself to PAE
 *
 * Menu
 *   add_arch_option("Name")        required: the name shown in the PAE menu
 *   set_arch_number(N)             menu number that starts this package; without it the
 *                                  package counts after the biggest number in use
 *                                  (built-ins are 1..3, so the first package is 4)
 *   add_arch_info("text")          shown by "aai info", optional
 *
 * Keystone
 *   set_keystone_arch(A)           required: Keystone architecture (a ks_arch value),
 *                                  so Keystone does not fall back to x86
 *   set_keystone_mode(M)           Keystone mode (a ks_mode value), optional
 *
 * Linking (--asm), optional
 *   set_elf_machine(N)             ELF e_machine number, for architectures PAE does not know
 *                                  (PAE already knows ARM, ARM64, MIPS, x86, PowerPC, SPARC, SystemZ,
 *                                  Hexagon and picks it from set_keystone_arch / mode)
 *   set_elf_bits(32 or 64)         ELF class, same story
 *
 * Running code (all of these together; without them the package only prints bytes)
 *   set_register_width(4 or 8)     bytes per register slot
 *   add_registers("r1", "r2", ...) the tracked registers, in array order (1 to 32)
 *   set_hidden_registers(MASK)     slots that are in the array but not shown (bit i = slot i)
 *   set_flags_register(SLOT, KIND) optional, KIND = AAI_FLAGS_NZCV or AAI_FLAGS_X86
 *   set_return_instructions("ret", ...)  trailing returns PAE strips from your code
 *   set_delay_slot(1)              optional: a nop may follow the return (MIPS style)
 *   add_host_check { ... }         return 1 when this CPU can run the architecture
 *   add_wrapper_builder { ... }    write the wrapper source (see below)
 *
 * The wrapper builder is a function body with these names:
 *     int pae_pkg_build(char *out, size_t n, const char *line)
 * Write assembly source into out (aai_emit does the bounds checking): save the registers the
 * host ABI wants kept, load every tracked register from the array whose address arrives in the
 * first argument register (slot i at byte i * width), put `line` in the middle, store every
 * register back, restore, and return. Return 0, or -1 if out was too small.
 *
 * Example skeleton:
 *   #include <keystone/keystone.h>
 *   #include "aai_pkg.h"
 *   add_arch_option("PowerPC 32");
 *   set_arch_number(4);
 *   set_keystone_arch(KS_ARCH_PPC);
 *   set_keystone_mode(KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN);
 *   set_register_width(4);
 *   add_registers("r3", "r4", "r5");
 *   set_return_instructions("blr");
 *   add_host_check { return 0; }            (or an #if on the host CPU)
 *   add_wrapper_builder {
 *       size_t o = 0;
 *       aai_emit(out, n, &o, "...save and load...\n");
 *       aai_emit(out, n, &o, "%s\n", line);
 *       aai_emit(out, n, &o, "...store and restore...\n");
 *       return o < n ? 0 : -1;
 *   }
 *
 * Build:  cc -shared -fPIC powerpc-32.c -o powerpc-32.so
 * Upload the .so to the repo; the file name (without .so) is the package name.
 */
#ifndef AAI_PKG_H
#define AAI_PKG_H

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>

#define AAI_EXPORT __attribute__((visibility("default")))

#define AAI_FLAGS_NZCV 1
#define AAI_FLAGS_X86  2

#define add_arch_option(name)    AAI_EXPORT const char *pae_pkg_option        = name
#define set_arch_number(num)     AAI_EXPORT const int   pae_pkg_number        = (num)
#define add_arch_info(text)      AAI_EXPORT const char *pae_pkg_info          = text
#define set_keystone_arch(arch)  AAI_EXPORT const int   pae_pkg_keystone_arch = (int)(arch)
#define set_keystone_mode(mode)  AAI_EXPORT const int   pae_pkg_keystone_mode = (int)(mode)
#define set_elf_machine(m)       AAI_EXPORT const int   pae_pkg_elf_machine   = (m)
#define set_elf_bits(b)          AAI_EXPORT const int   pae_pkg_elf_bits      = (b)

#define set_register_width(w)    AAI_EXPORT const int   pae_pkg_reg_width = (w)
#define add_registers(...) \
    AAI_EXPORT const char *const pae_pkg_reg_names[] = { __VA_ARGS__ }; \
    AAI_EXPORT const int pae_pkg_reg_count = (int)(sizeof pae_pkg_reg_names / sizeof pae_pkg_reg_names[0])
#define set_hidden_registers(mask) AAI_EXPORT const unsigned pae_pkg_hidden = (mask)
#define set_flags_register(slot, kind) \
    AAI_EXPORT const int pae_pkg_flags_slot = (slot); \
    AAI_EXPORT const int pae_pkg_flags_kind = (kind)
#define set_return_instructions(...) AAI_EXPORT const char *const pae_pkg_rets[] = { __VA_ARGS__, 0 }
#define set_delay_slot(v)        AAI_EXPORT const int pae_pkg_delay_nop = (v)

#define add_host_check           AAI_EXPORT int pae_pkg_host(void)
#define add_wrapper_builder      AAI_EXPORT int pae_pkg_build(char *out, size_t n, const char *line)

/* bounds-checked printf into the wrapper source */
static inline void aai_emit(char *out, size_t n, size_t *o, const char *fmt, ...) {
    if (*o >= n) return;
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(out + *o, n - *o, fmt, ap);
    va_end(ap);
    if (r > 0) *o += (size_t)r;
    if (*o > n) *o = n;
}

#endif
