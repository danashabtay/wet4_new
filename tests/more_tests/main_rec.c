#include <stdio.h>

int bar(int n);
int foo(int n);

int main () {
    int y = foo(7);
    int x = bar(100);
    return 0;
}

/*
 * foo(7) returns 6
 * bar(100) calls foo(100), which returns 99
 */