# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++ -m64
CC = clang -m64
OPTFLAGS = -O3
DBGFLAGS = -g -O0 -DDEBUG
CFLAGS = -Wall -fstrict-aliasing -I./libcat -I./include
LIBNAME = bin/libcalico.a
LIBS =


# Object files

shared_test_o = Clock.o

extern_o = 

libcat_o = BitMath.o EndianNeutral.o SecureErase.o

calico_o = AntiReplayWindow.o Calico.o ChaChaVMAC.o VHash.o $(libcat_o) $(extern_o)

calico_test_o = calico_test.o $(shared_test_o)
calico_example_o = calico_example.o


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

example : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
example : clean $(calico_example_o) library
	$(CCPP) $(calico_example_o) $(LIBS) -L./bin -lcalico -o example
	./example

test : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test : clean $(calico_test_o) library
	$(CCPP) $(calico_test_o) $(LIBS) -L./bin -lcalico -o test
	./test


# Shared objects

Clock.o : libcat/Clock.cpp
	$(CCPP) $(CFLAGS) -c libcat/Clock.cpp

EndianNeutral.o : libcat/EndianNeutral.cpp
	$(CCPP) $(CFLAGS) -c libcat/EndianNeutral.cpp

SecureErase.o : libcat/SecureErase.cpp
	$(CCPP) $(CFLAGS) -c libcat/SecureErase.cpp

BitMath.o : libcat/BitMath.cpp
	$(CCPP) $(CFLAGS) -c libcat/BitMath.cpp


# Library objects

calico.o : src/calico.cpp
	$(CCPP) $(CFLAGS) -c src/calico.cpp

AntiReplayWindow.o : src/AntiReplayWindow.cpp
	$(CCPP) $(CFLAGS) -c src/AntiReplayWindow.cpp

Calico.o : src/Calico.cpp
	$(CCPP) $(CFLAGS) -c src/Calico.cpp

ChaChaVMAC.o : src/ChaChaVMAC.cpp
	$(CCPP) $(CFLAGS) -c src/ChaChaVMAC.cpp

VHash.o : src/VHash.cpp
	$(CCPP) $(CFLAGS) -c src/VHash.cpp


# Executable objects

calico_test.o : tests/calico_test.cpp
	$(CCPP) $(CFLAGS) -c tests/calico_test.cpp

calico_example.o : tests/calico_example.cpp
	$(CCPP) $(CFLAGS) -c tests/calico_example.cpp


# Cleanup

.PHONY : clean

clean :
	git submodule update --init
	-rm test bin/libcalico.a $(shared_test_o) $(calico_test_o) $(calico_o)

