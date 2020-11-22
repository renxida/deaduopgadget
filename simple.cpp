//#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
uint64_t array1[1000];
size_t array1_size;

uint64_t victim_function(size_t x) {
    // bounds check to be crossed via spectre
    if(0< x && x < array1_size) {
        //this statement leaves a trace in array2 depending on value of array1[x]
        //temp &= array2[array1[x] * 512];
        return array1[x];
    } else {
        return -1;
    }
}

int main(int argc, char** argv){
    array1_size = 1000;
    size_t x;
    for(x = 0; x < array1_size; x+=1){
        array1[x]=x;
    }

    for(x = 1; x < 10000; x*=4){
        uint64_t y = victim_function(x);
        printf("x:\t%ld\ny\t%ld\n", x, y);
    }
}
