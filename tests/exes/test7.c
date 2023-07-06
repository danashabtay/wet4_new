/*
Test when an outsider dynamic library calls the reqursive_func_to_track which is defined in this file
and is reqursivly calling itself.
*/


#include "dynamic_utils.h"


extern int reqursive_outsider_call(int);


int reqursive_func_to_track(int a, int b){
    if (a > 0)
        reqursive_func_to_track(a - 1, b + 1);
    return a + 1;
}

int func_to_track(int a, int b){return 0;} // Not used, for compilation

int main(){
    reqursive_func_to_track(0, 0);
    reqursive_outsider_call(2);
    reqursive_func_to_track(4, -2);
    reqursive_outsider_call(6);
    return 0;
}