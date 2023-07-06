/*
Test when the func_to_track is in a dynamic library
*/


#include "dynamic_utils.h"

extern int func_to_track(int, int);

int main(){
    func_to_track(0, 0);
    func_to_track(2, -1);
    func_to_track(4, -2);
    func_to_track(6, -3);
    return 0;
}