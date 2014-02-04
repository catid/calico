# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++ -m64
CC = clang -m64
OPTFLAGS = -O3 -DCAT_CHACHA_IMPL
DBGFLAGS = -g -O0 -DDEBUG -DCAT_CHACHA_IMPL
CFLAGS = -Wall -fstrict-aliasing -I./libcat -I./include -I./chacha-opt \
		 -Dchacha_blocks_impl=chacha_blocks_ssse3 -Dhchacha_impl=hchacha
LIBNAME = bin/libcalico.a
LIBS =


# Object files

shared_test_o = Clock.o

extern_o = chacha.o chacha_blocks_ssse3-64.o

libcat_o = BitMath.o EndianNeutral.o SecureErase.o

calico_o = AntiReplayWindow.o Calico.o ChaChaVMAC.o VHash.o $(libcat_o) $(extern_o)

calico_test_o = calico_test.o $(shared_test_o) SecureEqual.o
calico_example_o = calico_example.o


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : library


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : LIBNAME = libcalico_debug.a
debug : library


# Library target

library : $(calico_o)
	ar rcs $(LIBNAME) $(calico_o)


# tester executables

example : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
example : clean $(calico_example_o) library
	$(CCPP) $(calico_example_o) $(LIBS) -L./bin -lcalico -o example
	./example

test : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test : clean $(calico_test_o) library
	$(CCPP) $(calico_test_o) $(LIBS) -L./bin -lcalico -o test
	./test

test-mobile : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test-mobile : clean $(calico_test_o)
	$(CCPP) $(calico_test_o) -L./calico-mobile -lcalico -o test
	./test


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


# Library objects

AntiReplayWindow.o : src/AntiReplayWindow.cpp
	$(CCPP) $(CFLAGS) -c src/AntiReplayWindow.cpp

Calico.o : src/Calico.cpp
	$(CCPP) $(CFLAGS) -c src/Calico.cpp

ChaChaVMAC.o : src/ChaChaVMAC.cpp
	$(CCPP) $(CFLAGS) -c src/ChaChaVMAC.cpp

VHash.o : src/VHash.cpp
	$(CCPP) $(CFLAGS) -c src/VHash.cpp

chacha.o : chacha-opt/chacha.c
	$(CC) $(CFLAGS) -std=c99 -c chacha-opt/chacha.c

chacha_blocks_ssse3-64.o : chacha-opt/chacha_blocks_ssse3-64.S
	$(CC) $(CFLAGS) -c chacha-opt/chacha_blocks_ssse3-64.S


# Executable objects

calico_test.o : tests/calico_test.cpp
	$(CCPP) $(CFLAGS) -c tests/calico_test.cpp

calico_example.o : tests/calico_example.cpp
	$(CCPP) $(CFLAGS) -c tests/calico_example.cpp


# Cleanup

.PHONY : clean

clean :
	git submodule update --init
	-rm test example $(shared_test_o) $(calico_test_o) $(calico_o)

