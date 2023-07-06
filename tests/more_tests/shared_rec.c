#include <stdio.h>

int bar(int n);

int foo(int n) {
    if (n == 0)
        return 0;
    n--;
    return bar(n);
}

int bar(int n) {
    if (n == 0)
        return foo(0);
    return 1 + foo(n);
}
