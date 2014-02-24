# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++ -m64
CC = clang -m64
OPTFLAGS = -O4
DBGFLAGS = -g -O0 -DDEBUG
CFLAGS = -Wall -fstrict-aliasing -I.
LIBNAME = libcalico.a


# Object files

library_o = chacha.o chacha_blocks_ref.o Clock.o BitMath.o EndianNeutral.o \
			SecureErase.o AntiReplayWindow.o Calico.o AuthEnc.o Poly1305.o


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : library


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : LIBNAME = libcalico_debug.a
debug : library


# Library (internal) target; use release or debug

library : $(library_o)
	ar rcs $(LIBNAME) $(library_o)


# Shared objects

Clock.o : Clock.cpp
	$(CCPP) $(CFLAGS) -c Clock.cpp

SecureErase.o : SecureErase.cpp
	$(CCPP) $(CFLAGS) -c SecureErase.cpp

EndianNeutral.o : EndianNeutral.cpp
	$(CCPP) $(CFLAGS) -c EndianNeutral.cpp

BitMath.o : BitMath.cpp
	$(CCPP) $(CFLAGS) -c BitMath.cpp


# ChaCha objects

chacha.o : chacha.c
	$(CC) $(CFLAGS) -c chacha.c

chacha_blocks_ref.o : chacha_blocks_ref.c
	$(CC) $(CFLAGS) -c chacha_blocks_ref.c


# Calico objects

AntiReplayWindow.o : AntiReplayWindow.cpp
	$(CCPP) $(CFLAGS) -c AntiReplayWindow.cpp

Calico.o : Calico.cpp
	$(CCPP) $(CFLAGS) -c Calico.cpp

AuthEnc.o : AuthEnc.cpp
	$(CCPP) $(CFLAGS) -c AuthEnc.cpp

Poly1305.o : Poly1305.cpp
	$(CCPP) $(CFLAGS) -c Poly1305.cpp


# Cleanup

.PHONY : clean

clean :
	-rm *.a *.o

