// gcc -shared -fPIC -o libomer.so libomer.c
// sudo mv libomer.so /usr/lib
int omer_echo(int number) {
    return number;
}

int another_func(int num) {
    int n = omer_echo(num + 1);
    return n + 1;
}