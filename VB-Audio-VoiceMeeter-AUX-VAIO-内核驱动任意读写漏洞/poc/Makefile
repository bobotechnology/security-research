#
# Makefile — build all PoC programs
#
# Usage:
#   make              build everything
#   make clean        remove all executables
#   make 01_double_free.exe   build just one PoC
#
# Requires: MinGW-w64 GCC (x86_64-w64-mingw32-gcc)
#

CC      = gcc
CFLAGS  = -O2 -DUNICODE -D_WIN32_WINNT=0x0600
LDFLAGS = -lsetupapi -lwinmm -static

TARGETS = 01_double_free.exe \
          02_stale_map.exe \
          03_extend_mdl.exe \
          04_live_alias.exe \
          05_eop_token_steal.exe

all: $(TARGETS)

# each .exe depends on its .c file AND the shared device.h
%.exe: %.c device.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	del /q *.exe 2>nul

.PHONY: all clean
