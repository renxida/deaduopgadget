//#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
uint64_t array1[1000];
size_t array1_size;

uint64_t victim(size_t x_victim) {
    // bounds check to be crossed via spectre
    if(0< x_victim && x_victim < array1_size) {
        //this statement leaves a trace in array2 depending on value of array1[x]
        //temp &= array2[array1[x] * 512];
        return array1[x_victim];
    } else {
        return -1;
    }
}

uint64_t return_tainted(size_t x_return_tainted){
    return 4 * x_return_tainted; // taint y
}

uint64_t return_untainted(size_t x_return_untainted){
    return 4;
}

int main(int argc, char** argv){
    // array1_size = 1000;
    // size_t x;
    // for(x = 0; x < array1_size; x+=1){
    //     array1[x]=x;
    // }

    // printf("calling victim");
    // for(x = 1; x < 10000; x*=4){
    //     uint64_t y = victim(x);
    //     printf("x:\t%ld\ny:\t%ld\n", x, y);
    // }

    // printf("calling return_tainted");
    // for(x = 1; x < 10000; x*=4){
    //     uint64_t y = return_tainted(x);
    //     printf("x:\t%ld\ny:\t%ld\n", x, y);
    // }

    // printf("calling return_untainted");
    // for(x = 1; x < 10000; x*=4){
    //     uint64_t y = return_untainted(x);
    //     printf("x:\t%ld\ny:\t%ld\n", x, y);
    // }
}
