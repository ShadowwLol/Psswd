CC = gcc
#DFLAGS = -I$(IDIR) -lcrypto -Wall -Wextra -Werror -pedantic
#CFLAGS = -I$(IDIR) -lcrypto
#IDIR = ./include/
DFLAGS = -lcrypto -Wall -Wextra -Werror -pedantic
CFLAGS = -lcrypto
SRCDIR = ./src/
SOURCES = $(SRCDIR)*.c

debug:
	rm Psswd; $(CC) $(SOURCES) $(DFLAGS) -o Psswd ; ./Psswd

all:
	rm Psswd; $(CC) $(SOURCES) $(CFLAGS) -o Psswd ; ./Psswd
