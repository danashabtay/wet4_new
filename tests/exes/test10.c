/*
Test when the func_to_track is in a dynamic library and called from with in that dynamic library
*/


#include "dynamic_utils.h"


extern int reqursive_func_to_track(int, int);
extern void reqursive_call_inside_dynamic_func_to_trace(int);


int main(){
    reqursive_func_to_track(0, 0);
    reqursive_call_inside_dynamic_func_to_trace(2);
    reqursive_func_to_track(4, -2);
    reqursive_call_inside_dynamic_func_to_trace(6);
    return 0;
}