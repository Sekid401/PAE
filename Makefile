# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 sekid. See the LICENSE file.

# PAE build: pae64 (64-bit), pae32 (32-bit) and aai (the package manager)
#
#   make            build all three
#   make aai        package manager only (native toolchain, needs curl at run time)
#   make zip        pack the sources and this Makefile into pae-aai.zip
#   make dist       build aai (compile check), make the zip, copy it to OUTDIR
#   make install    copy what was built to $(BINDIR), create the package folders and set
#                   PAE32I / PAE64I (through $(PROFILED)/pae.sh)
#   make uninstall  remove the binaries and pae.sh (installed packages are left alone)
#   make pae64      64-bit only  (native Termux toolchain + libkeystone)
#   make pae32      32-bit only  (needs a 32-bit toolchain and a 32-bit libkeystone)
#   make clean
#
# install puts the binaries in PREFIX/bin (PREFIX is Termux's own when set, else /usr/local)
# and makes PREFIX/share/pae/pae32 and pae64, the folders $PAE32I and $PAE64I point at.
# pae.sh exports both variables; login shells read profile.d (Termux does), or run
# ". PREFIX/etc/profile.d/pae.sh" once. DESTDIR works for staged installs.
#
# aai builds with the same native compiler as pae64 (CC64). The zip holds sources only,
# so it builds on whatever device unpacks it. OUTDIR defaults to the chat outputs folder;
# override it elsewhere:  make dist OUTDIR=$$HOME/storage/downloads
#
# pae64 uses whatever clang and libkeystone Termux already has.
#
# pae32 must be a real 32-bit ARM process, so it needs:
#   CXX32     a 32-bit ARM clang++ (default: Termux clang++ with --target).
#             It is used as the linker because libkeystone is C++; the source
#             is still compiled as C.
#   KS32_LIB  directory holding a 32-bit libkeystone (.a or .so);
#             default: $$HOME/keystone/build32/llvm/lib
#   KS32_INC  include dir with keystone/keystone.h (the header is the same
#             for every architecture, so Termux's own copy works)
#
# Termux's clang can already target 32-bit ARM, so no NDK is needed for the
# compiler itself. Example:
#   make pae32                      (uses the default KS32_LIB)
#   make pae32 KS32_LIB=$$HOME/somewhere/else/lib
#
# armeabi-v7a is the target: it covers armeabi-v7a and, on 64-bit CPUs, runs
# as a 32-bit process under the same kernel. The old plain "armeabi" ABI
# (ARMv5/v6) was dropped from current NDKs and isn't needed for this.

CFLAGS   ?= -O2 -Wall -Wextra

CC64     ?= clang
KS64_INC ?=
KS64_LIB ?=

CXX32    ?= clang++ --target=armv7a-linux-androideabi24
KS32_INC ?= $(PREFIX)/include
KS32_LIB ?= $(HOME)/keystone/build32/llvm/lib
LDLIBS32 ?= -static-libstdc++

# pae loads AAI packages with dlopen
LDLIBDL  ?= -ldl

PREFIX   ?= /usr/local
DESTDIR  ?=
BINDIR   ?= $(PREFIX)/bin
PAEDIR   ?= $(PREFIX)/share/pae
PROFILED ?= $(PREFIX)/etc/profile.d

OUTDIR   ?= /mnt/user-data/outputs
ZIPNAME  ?= pae-aai.zip
ZIPFILES  = README.md LICENSE Makefile pae32.c pae64.c aai.c aai_pkg.h

.PHONY: all clean zip dist install uninstall
all: pae64 pae32 aai

pae64: pae64.c
	$(CC64) $(CFLAGS) $(if $(KS64_INC),-I$(KS64_INC)) pae64.c -o $@ \
		$(if $(KS64_LIB),-L$(KS64_LIB)) -lkeystone $(LDLIBDL)

aai: aai.c
	$(CC64) $(CFLAGS) aai.c -o $@ $(LDLIBDL)

pae32: pae32.c
	@command -v $(firstword $(CXX32)) >/dev/null 2>&1 || { \
		echo "make: 32-bit compiler '$(CXX32)' not found -- set CXX32=..."; exit 1; }
	@ls "$(KS32_LIB)"/libkeystone.* >/dev/null 2>&1 || { \
		echo "make: no libkeystone in KS32_LIB=$(KS32_LIB) -- set KS32_LIB=<dir with a 32-bit libkeystone>"; exit 1; }
	$(CXX32) $(CFLAGS) $(if $(KS32_INC),-I$(KS32_INC)) -x c pae32.c -x none -o $@ \
		-L$(KS32_LIB) -Wl,-rpath,$(KS32_LIB) -lkeystone $(LDLIBDL) $(LDLIBS32)
	@file $@ 2>/dev/null || true

zip: $(ZIPFILES)
	rm -f $(ZIPNAME)
	zip -q $(ZIPNAME) $(ZIPFILES)

dist: aai zip
	mkdir -p $(OUTDIR)
	cp $(ZIPNAME) $(OUTDIR)/
	@echo "copied $(ZIPNAME) to $(OUTDIR)"

install:
	@have=""; for b in pae64 pae32 aai; do test -f $$b && have="$$have $$b"; done; \
	test -n "$$have" || { echo "make: nothing built yet -- run make (or make pae64 aai) first"; exit 1; }; \
	mkdir -p "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(PAEDIR)/pae32" "$(DESTDIR)$(PAEDIR)/pae64" "$(DESTDIR)$(PROFILED)" || exit 1; \
	for b in $$have; do \
		cp $$b "$(DESTDIR)$(BINDIR)/$$b" && chmod 755 "$(DESTDIR)$(BINDIR)/$$b" || exit 1; \
		echo "installed $(BINDIR)/$$b"; \
	done; \
	printf '%s\n' '# PAE and AAI install folders (written by make install)' \
		'export PAE32I="$(PAEDIR)/pae32"' 'export PAE64I="$(PAEDIR)/pae64"' \
		> "$(DESTDIR)$(PROFILED)/pae.sh" || exit 1; \
	echo "package folders: $(PAEDIR)/pae32 and $(PAEDIR)/pae64"; \
	echo "wrote $(PROFILED)/pae.sh, it sets PAE32I and PAE64I"; \
	echo "open a new shell, or run:  . $(PROFILED)/pae.sh"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/pae64" "$(DESTDIR)$(BINDIR)/pae32" "$(DESTDIR)$(BINDIR)/aai" "$(DESTDIR)$(PROFILED)/pae.sh"
	@echo "removed the binaries and pae.sh; left $(PAEDIR) alone (it holds installed AAI packages)"

clean:
	rm -f pae32 pae64 aai $(ZIPNAME)
