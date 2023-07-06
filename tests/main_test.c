// gcc -no-pie -o main_test.o main_test.c /usr/lib/libomer.so -Wl,-zlazy
#include <stdio.h>

int omer_echo(int number);
int another_func(int num);
int bar(int m);

int shani_plusplus(int num) {
    return num+1;
}

int recursion(int times) {
    if (times <= 0) {
        return times;
    }
    recursion(times - 1);
    return times;
}

int foo(int n) {
    if (n<=0) {
        return 0;
    }
    return bar(n-1);
}

int bar(int m) {
    if (m<=0) {
        return 0;
    }
    return foo(m-1);
}

int main(int argc, char *const argv[]) {
    int a = 4;
    int b = 8;
    omer_echo(a);
    shani_plusplus(11);
    omer_echo(b);
    another_func(2);
    shani_plusplus(-5);
    omer_echo(77);
    shani_plusplus(b);
    recursion(10);
    foo(9);
    foo(8);
    bar(11);
    bar(10);
    return 0;
}
