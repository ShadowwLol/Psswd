CC = gcc
DFLAGS = -lcrypto -Wall -Wextra -Werror -pedantic
CFLAGS = -lcrypto
#IDIR = ./include/
SRCDIR = ./src/
SOURCES = $(SRCDIR)*.c

debug:
	rm Psswd; $(CC) $(SOURCES) $(DFLAGS) -o Psswd ; ./Psswd

all:
	rm Psswd; $(CC) $(SOURCES) $(CFLAGS) -o Psswd ; ./Psswd
