

int func_to_track(int a, int b){
    return a + 1;
}

void call_inside_dynamic_func_to_trace(int a){
    func_to_track(a, 0);
}


int reqursive_func_to_track(int a, int b){
    if (a > 0)
        reqursive_func_to_track(a - 1, b + 1);
    return a + 1;
}

void reqursive_call_inside_dynamic_func_to_trace(int a){
    reqursive_func_to_track(a, 0);
}