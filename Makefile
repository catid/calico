# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++ -m64
CC = clang -m64
OPTFLAGS = -O3
DBGFLAGS = -g -O0 -DDEBUG
CFLAGS = -Wall -fstrict-aliasing -I./blake2/sse -I./chacha-opt -I./libcat -I./include \
		 -Dchacha_blocks_impl=chacha_blocks_ssse3 -Dhchacha_impl=hchacha
LIBNAME = libcalico.a
LIBS =


# Object files

shared_test_o = Clock.o

extern_o = blake2b.o chacha.o chacha_blocks_ssse3-64.o

libcat_o = BitMath.o EndianNeutral.o

calico_o = AntiReplayWindow.o Calico.o ChaChaVMAC.o VHash.o $(libcat_o) $(extern_o)

calico_test_o = calico_test.o $(shared_test_o)


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : library


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : LIBNAME = libcalico_debug.a
debug : library


# Library target

library : CFLAGS += $(OPTFLAGS)
library : $(calico_o)
	ar rcs $(LIBNAME) $(calico_o)


# tester executables

test : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test : clean $(calico_test_o) library
	$(CCPP) $(calico_test_o) $(LIBS) -L. -lcalico -o test
	./test


# Shared objects

Clock.o : libcat/Clock.cpp
	$(CCPP) $(CFLAGS) -c libcat/Clock.cpp

EndianNeutral.o : libcat/EndianNeutral.cpp
	$(CCPP) $(CFLAGS) -c libcat/EndianNeutral.cpp

BitMath.o : libcat/BitMath.cpp
	$(CCPP) $(CFLAGS) -c libcat/BitMath.cpp


# Library objects

calico.o : src/calico.cpp
	$(CCPP) $(CFLAGS) -c src/calico.cpp

AntiReplayWindow.o : src/AntiReplayWindow.cpp
	$(CCPP) $(CFLAGS) -c AntiReplayWindow.cpp

Calico.o : src/Calico.cpp
	$(CCPP) $(CFLAGS) -c Calico.cpp

ChaChaVMAC.o : src/ChaChaVMAC.cpp
	$(CCPP) $(CFLAGS) -c ChaChaVMAC.cpp

VHash.o : src/VHash.cpp
	$(CCPP) $(CFLAGS) -c VHash.cpp

blake2b.o : blake2/sse/blake2b.c
	$(CC) $(CFLAGS) -c blake2/sse/blake2b.c

chacha.o : chacha-opt/chacha.c
	$(CC) $(CFLAGS) -c chacha-opt/chacha.c

chacha_blocks_ssse3-64.o : chacha-opt/chacha_blocks_ssse3-64.S
	$(CC) $(CFLAGS) -c chacha-opt/chacha_blocks_ssse3-64.S


# Executable objects

calico_test.o : tests/calico_test.cpp
	$(CCPP) $(CFLAGS) -c tests/calico_test.cpp


# Cleanup

.PHONY : clean

clean :
	git submodule update --init
	-rm test libcalico.a $(shared_test_o) $(calico_test_o) $(calico_o)

