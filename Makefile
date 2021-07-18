CC = gcc
LDLIBS = -l:libcrypto.so -l:libzip.so -l:libbsd.so -l:libcurses.so
DFLAGS = $(LDLIBS) -Wall -Wextra -Werror -fstack-protector -pedantic -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -fstack-clash-protection -Wshadow -Wformat=2 -Wformat-truncation -Wformat-overflow -fno-common -fstack-usage
#IDIR = ./include/
SRCDIR = ./src/
SOURCES = $(SRCDIR)*.c

debug:
	rm -f Psswd; $(CC) $(SOURCES) $(DFLAGS) -Og -o Psswd ; ./Psswd

all:
	rm -f Psswd; $(CC) $(SOURCES) $(LDLIBS) -fno-gcse -O3 -o Psswd ; ./Psswd

size:
	rm -f Psswd; $(CC) $(SOURCES) $(LDLIBS) -Os -o Psswd; ./Psswd

release:
	rm -f Psswd
	$(CC) $(SOURCES) $(DFLAGS) -O3 -o Psswd
