/*
Test when the func_to_track is in a dynamic library, and is called by an other dynamic library
*/


#include "dynamic_utils.h"

extern int reqursive_func_to_track(int, int);
extern int reqursive_outsider_call(int);


int main(){
    reqursive_func_to_track(0, 0);
    reqursive_outsider_call(2);
    reqursive_func_to_track(4, -2);
    reqursive_outsider_call(6);
    return 0;
}