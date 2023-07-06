/*
Test when the reqursive_func_to_track is in a dynamic library and is reqursivly calling itself.
*/


#include "dynamic_utils.h"

extern int reqursive_func_to_track(int, int);

int main(){
    reqursive_func_to_track(0, 0);
    reqursive_func_to_track(2, -1);
    reqursive_func_to_track(4, -2);
    reqursive_func_to_track(6, -3);
    return 0;
}