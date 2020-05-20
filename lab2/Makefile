# The following two macros set up the compiler flags and compiler command

DFLAGS = -DDEBUG -g
CFLAGS = -Wall 
CC = gcc

# Default rule to compile files using the same CC command

% : %.c
	$(CC) $(DFLAGS) $(CFLAGS) $< -o $@

# Start of the target section

PROG = vcrec_Modified vcsend_Modified

tcp:	$(PROG)

clean:
	rm $(PROG)
