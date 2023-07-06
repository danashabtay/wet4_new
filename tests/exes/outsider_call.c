
#include "dynamic_utils.h"  

extern int func_to_track(int a, int b);
extern int reqursive_func_to_track(int a, int b);

int outsider_call_counter = 0;

int outsider_call(int a)
{
    func_to_track(a, outsider_call_counter++);
}

int reqursive_outsider_call(int a)
{
    reqursive_func_to_track(a, outsider_call_counter++);
}