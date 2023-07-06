/*
Simple test, the function is a global defined in this file, but is recursive.
*/


int reqursive_func_to_track(int a, int b){
    if (a > 0)
        reqursive_func_to_track(a - 1, b + 1);
    return a + 1;
}

int main(){
    reqursive_func_to_track(0, 0);
    reqursive_func_to_track(2, -1);
    reqursive_func_to_track(4, -2);
    reqursive_func_to_track(6, -3);
    return 0;
}
