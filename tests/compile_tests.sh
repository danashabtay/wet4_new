#!/bin/bash

cd libomer/
gcc -shared -fPIC -o libomer.so libomer.c
cd ../
gcc -no-pie -o main_test.o main_test.c ./libomer/libomer.so -zlazy
