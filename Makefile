CC = gcc
DFLAGS = -I$(IDIR) -lcrypto -Wall -Wextra -Werror -pedantic
CFLAGS = -I$(IDIR) -lcrypto
IDIR = ./include/
SRCDIR = ./src/
SOURCES = $(SRCDIR)*.c

debug:
	rm Psswd; $(CC) $(SOURCES) $(DFLAGS) -o Psswd ; ./Psswd

all:
	rm Psswd; $(CC) $(SOURCES) $(CFLAGS) -o Psswd ; ./Psswd
