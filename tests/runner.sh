#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

SHARED_LIB_COMP="gcc -shared -fPIC -o shared_rec.so shared_rec.c"
MAIN_COMP="gcc -no-pie -o main_rec.out main_rec.c /usr/lib/shared_rec.so -Wl,-zlazy"
PRF_CMD="../prf foo ./more_tests/main_rec.out"
EXPECTED="PRF:: run #1 first parameter is 7\nPRF:: run #1 returned with 6\nPRF:: run #2 first parameter is 100\nPRF:: run #2 returned with 99"

printf "getting ready...\n"

cd ../
gcc -std=c99 *.c -o prf
cd tests/

./compile_tests.sh
exes/compile_exes.sh

cd more_tests
$SHARED_LIB_COMP
sudo mv shared_rec.so /usr/lib
$MAIN_COMP
cd ../

dos2unix expected_out_files/* 2> /dev/null

pass_or_fail () {
  	if [ $? -eq 0 ]
  	then
  		printf "${GREEN}pass${NC},\n"
  	else
          printf "${RED}fail${NC},\n"
  	fi
}

export LD_LIBRARY_PATH=./exes

for i in 1 2 3 4 5 6 7 8 9 10
do 
	TO_TRACK=func_to_track
    if [ "$i" -gt 5 ]
    then 
        TO_TRACK=reqursive_func_to_track
    fi
    printf "test$i: "
    ../prf $TO_TRACK exes/test$i.exe > $i.out
    diff -q $i.out expected_out_files/expected_out.txt
    pass_or_fail
done


printf "test11: " #global_defined
../prf shani_plusplus ./main_test.o > global_defined.out
diff -q global_defined.out expected_out_files/shani_plusplus.out
pass_or_fail

printf "test12: " #recursion
../prf recursion ./main_test.o > recursion.out
diff -q recursion.out expected_out_files/recursion.out
pass_or_fail

printf "test13: " #lib_1
../prf another_func ./main_test.o > another_func.out
diff -q another_func.out expected_out_files/another_func.out
pass_or_fail

printf "test14: " #lib_2
../prf omer_echo ./main_test.o > omer_echo.out
diff -q omer_echo.out expected_out_files/omer_echo.out
pass_or_fail

printf "test15: " #func_doesnt_exist
../prf not_a_func ./main_test.o > not_a_func.out
diff -q not_a_func.out expected_out_files/not_a_func.out
pass_or_fail

printf "test16: " #double_recursion_1
../prf foo ./main_test.o > foo.out
diff -q foo.out expected_out_files/foo.out
pass_or_fail

printf "test17: " #double_recursion_2
../prf bar ./main_test.o > bar.out
diff -q bar.out expected_out_files/bar.out
pass_or_fail


output=$($PRF_CMD)
printf "test18: " #double_recursion_3
diff -q --strip-trailing-cr <(echo -e "$EXPECTED") <(echo -e "$output") >/dev/null 2>&1
pass_or_fail


rm *.out
rm exes/*.o
rm exes/*.so
rm exes/*.exe
rm main_test.o
rm libomer/libomer.so
rm more_tests/main_rec.out

