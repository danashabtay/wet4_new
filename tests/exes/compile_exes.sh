
cd exes

gcc -c outsider_call.c -fpic -o outsider_call.dyn.o
gcc outsider_call.dyn.o -shared -o liboutsider_call.so

gcc -c outsider_func.c -fpic -o outsider_func.dyn.o
gcc outsider_func.dyn.o -shared -o liboutsider_func.so


gcc test1.c -no-pie -o test1.exe 
gcc test2.c -no-pie -o test2.exe -L. -l outsider_call

gcc test3.c -no-pie -o test3.exe -L. -l outsider_func
gcc test4.c -no-pie -o test4.exe -L. -l outsider_func -l outsider_call
gcc test5.c -no-pie -o test5.exe -L. -l outsider_func

gcc test6.c -no-pie -o test6.exe 
gcc test7.c -no-pie -o test7.exe -L. -l outsider_call
gcc test8.c -no-pie -o test8.exe -L. -l outsider_func
gcc test9.c -no-pie -o test9.exe -L. -l outsider_func -l outsider_call
gcc test10.c -no-pie -o test10.exe -L. -l outsider_func

cd ..