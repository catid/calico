# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++ -m64
CC = clang -m64
OPTFLAGS = -O4 -DCAT_CHACHA_IMPL
DBGFLAGS = -g -O0 -DDEBUG -DCAT_CHACHA_IMPL
CFLAGS = -Wall -fstrict-aliasing -I./libcat -I./include -I./chacha-opt \
		 -Dchacha_blocks_impl=chacha_blocks_ssse3 -Dhchacha_impl=hchacha \
		 -I./blake2/sse
LIBNAME = bin/libcalico.a
LIBS = -L./bin -lcalico


# Object files

shared_test_o =

extern_o = chacha.o chacha_blocks_ssse3-64.o blake2b.o

libcat_o = BitMath.o EndianNeutral.o SecureErase.o Clock.o

calico_o = AntiReplayWindow.o Calico.o SipHash.o $(libcat_o) $(extern_o)

calico_test_o = calico_test.o $(shared_test_o) SecureEqual.o
siphash_test_o = siphash_test.o $(shared_test_o)
calico_example_o = calico_example.o


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : library


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : LIBNAME = bin/libcalico_debug.a
debug : library


# Library target

library : $(calico_o)
	ar rcs $(LIBNAME) $(calico_o)


# tester executables

example : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
example : clean $(calico_example_o) library
	$(CCPP) $(calico_example_o) $(LIBS) -o example
	./example

test : CFLAGS += -DUNIT_TEST $(OPTFLAGS) -DRATCHET_REMOTE_TIMEOUT=500
test : clean $(calico_test_o) library
	$(CCPP) $(calico_test_o) $(LIBS) -o test
	./test

test-mobile : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test-mobile : clean $(calico_test_o)
	$(CCPP) $(calico_test_o) -L./calico-mobile -lcalico -o test
	./test

mactest : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
mactest : clean $(siphash_test_o) library
	$(CCPP) $(siphash_test_o) $(LIBS) -o mactest
	./mactest

valgrind : CFLAGS += -DUNIT_TEST $(DBGFLAGS)
valgrind : clean $(calico_test_o) debug
	$(CCPP) $(calico_test_o) -L./bin -lcalico_debug -o valgrindtest
	valgrind --dsymutil=yes --leak-check=yes ./valgrindtest


# Shared objects

Clock.o : libcat/Clock.cpp
	$(CCPP) $(CFLAGS) -c libcat/Clock.cpp

EndianNeutral.o : libcat/EndianNeutral.cpp
	$(CCPP) $(CFLAGS) -c libcat/EndianNeutral.cpp

SecureErase.o : libcat/SecureErase.cpp
	$(CCPP) $(CFLAGS) -c libcat/SecureErase.cpp

SecureEqual.o : libcat/SecureEqual.cpp
	$(CCPP) $(CFLAGS) -c libcat/SecureEqual.cpp

BitMath.o : libcat/BitMath.cpp
	$(CCPP) $(CFLAGS) -c libcat/BitMath.cpp

SipHash.o : libcat/SipHash.cpp
	$(CCPP) $(CFLAGS) -c libcat/SipHash.cpp


# Library objects

AntiReplayWindow.o : src/AntiReplayWindow.cpp
	$(CCPP) $(CFLAGS) -c src/AntiReplayWindow.cpp

Calico.o : src/Calico.cpp
	$(CCPP) $(CFLAGS) -c src/Calico.cpp

chacha.o : chacha-opt/chacha.c
	$(CC) $(CFLAGS) -std=c99 -c chacha-opt/chacha.c

chacha_blocks_ssse3-64.o : chacha-opt/chacha_blocks_ssse3-64.S
	$(CC) $(CFLAGS) -c chacha-opt/chacha_blocks_ssse3-64.S

blake2b.o : blake2/sse/blake2b.c
	$(CC) $(CFLAGS) -std=c99 -c blake2/sse/blake2b.c


# Executable objects

calico_test.o : tests/calico_test.cpp
	$(CCPP) $(CFLAGS) -c tests/calico_test.cpp

calico_example.o : tests/calico_example.cpp
	$(CCPP) $(CFLAGS) -c tests/calico_example.cpp

siphash_test.o : tests/siphash_test.cpp
	$(CCPP) $(CFLAGS) -c tests/siphash_test.cpp


# Cleanup

.PHONY : clean

clean :
	git submodule update --init
	-rm mactest test example *.o bin/*.a

