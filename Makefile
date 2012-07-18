# Change your compiler settings here

CC = clang++

ifeq ($(CALICO_DEBUG),1)
CFLAGS = -g -O0 -I. -v
else
CFLAGS = -O4 -I. -v
endif


# List of object files to make

ae_objects = AntiReplayWindow.o BitMath.o Calico.o ChaChaVMAC.o \
			 EndianNeutral.o Skein.o Skein256.o VHash.o

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

Skein.o : Skein.cpp
	$(CC) $(CFLAGS) -c Skein.cpp

Skein256.o : Skein256.cpp
	$(CC) $(CFLAGS) -c Skein256.cpp

VHash.o : VHash.cpp
	$(CC) $(CFLAGS) -c VHash.cpp


# Clean target

.PHONY : clean

clean :
	-rm tester $(tester_objects)
	-rm example $(example_objects)

