# Change your compiler settings here

CC = clang++

ifeq ($(CALICO_DEBUG),1)
CFLAGS = -g -O0 -I. -v
else
CFLAGS = -O4 -I. -v
endif


# List of object files to make

blake2_o = blake2b-ref.o

ae_objects = AntiReplayWindow.o BitMath.o Calico.o ChaChaVMAC.o \
			 EndianNeutral.o VHash.o $(blake2_o)

tester_objects = Tester.o Clock.o $(ae_objects)

example_objects = Example.o $(ae_objects)


# Applications

example : $(example_objects)
	$(CC) -o example $(example_objects)

tester : $(tester_objects)
	$(CC) -o tester $(tester_objects)


# Support files

Example.o : tests/Example.cpp
	$(CC) $(CFLAGS) -c tests/Example.cpp

Clock.o : tests/Clock.cpp
	$(CC) $(CFLAGS) -c tests/Clock.cpp

Tester.o : tests/Tester.cpp
	$(CC) $(CFLAGS) -c tests/Tester.cpp


# Blake2 files

blake2b-ref.o : blake2/ref/blake2b-ref.c
	$(CC) $(CFLAGS) -c blake2/ref/blake2b-ref.c


# Library files

AntiReplayWindow.o : AntiReplayWindow.cpp
	$(CC) $(CFLAGS) -c AntiReplayWindow.cpp

BitMath.o : BitMath.cpp
	$(CC) $(CFLAGS) -c BitMath.cpp

Calico.o : Calico.cpp
	$(CC) $(CFLAGS) -c Calico.cpp

ChaChaVMAC.o : ChaChaVMAC.cpp
	$(CC) $(CFLAGS) -c ChaChaVMAC.cpp

EndianNeutral.o : EndianNeutral.cpp
	$(CC) $(CFLAGS) -c EndianNeutral.cpp

VHash.o : VHash.cpp
	$(CC) $(CFLAGS) -c VHash.cpp


# Clean target

.PHONY : clean

clean :
	-rm tester $(tester_objects)
	-rm example $(example_objects)

