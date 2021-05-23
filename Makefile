CC = gcc
DFLAGS = -lcrypto -lzip -Wall -Wextra -Werror -pedantic
CFLAGS = -lcrypto -lzip
#IDIR = ./include/
SRCDIR = ./src/
SOURCES = $(SRCDIR)*.c

debug:
	rm -f Psswd; $(CC) $(SOURCES) $(DFLAGS) -Og -o Psswd ; ./Psswd

all:
	rm -f Psswd; $(CC) $(SOURCES) $(CFLAGS) -fno-gcse -O3 -o Psswd ; ./Psswd

size:
	rm -f Psswd; $(CC) $(SOURCES) $(CFLAGS) -Os -o Psswd; ./Psswd
