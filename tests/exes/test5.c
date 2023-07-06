/*
Test when the func_to_track is in a dynamic library and called from with in that dynamic library
*/


#include "dynamic_utils.h"


extern int func_to_track(int, int);
extern void call_inside_dynamic_func_to_trace(int);


int main(){
    func_to_track(0, 0);
    call_inside_dynamic_func_to_trace(2);
    func_to_track(4, -2);
    call_inside_dynamic_func_to_trace(6);
    return 0;
}