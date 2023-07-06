/*
Simple test, the function is a global defined in this file.
*/


int func_to_track(int a, int b){
    return a + 1;
}

int main(){
    func_to_track(0, 0);
    func_to_track(2, -1);
    func_to_track(4, -2);
    func_to_track(6, -3);
    return 0;
}
