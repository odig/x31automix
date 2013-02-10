PROGRAM = x32automix
RM = /bin/rm

CC       = g++
DEFS     = -DOS_IS_MACOSX=1 
CFLAGS   = -O0 -Wall -mmacosx-version-min=10.6 -g -GGDB 
CFLAGS  += -I$(INCLUDE) -I$(INCLUDE)/include
LIBRARY  = 

all : $(PROGRAM)

$(PROGRAM) : $(PROGRAM).cpp
	$(CC) $(CFLAGS) $(DEFS) -o $(PROGRAM) $(PROGRAM).cpp $(LIBRARY)

clean : 
	$(RM) -f $(PROGRAM)
	$(RM) -f *~

strip : 
	strip $(PROGRAM)
