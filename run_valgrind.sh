make clean
CALICO_DEBUG=1 make tester
valgrind --dsymutil=yes --leak-check=yes ./tester
