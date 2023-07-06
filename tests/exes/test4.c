/*
Test when the func_to_track is in a dynamic library, and is called by an other dynamic library
*/


#include "dynamic_utils.h"

extern int func_to_track(int, int);
extern int outsider_call(int);


int main(){
    func_to_track(0, 0);
    outsider_call(2);
    func_to_track(4, -2);
    outsider_call(6);
    return 0;
}