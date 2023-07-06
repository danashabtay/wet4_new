/*
Test when an outsider dynamic library calls the func_to_track which is defined in this file
*/


#include "dynamic_utils.h"

extern int outsider_call(int);

int func_to_track(int a, int b){
    
    return a + 1;
}

int reqursive_func_to_track(int a, int b){return 0;} // Not used, for compilation

int main(){
    func_to_track(0, 0);
    outsider_call(2);
    func_to_track(4, -2);
    outsider_call(6);
    return 0;
}