// ----------------------------------------------------------------------------------------
// Define the types used, and specify as extern's the arrays, etc. we will access.
// Note that temp is used so that operations aren't optimized away.
//
// Compilation flags:  cl /c /d2guardspecload /O2 /Faout.asm
// Note: Per Microsoft's blog post, /d2guardspecload flag will be renamed /Qspectre
//
// This code is free under the MIT license (https://opensource.org/licenses/MIT), but
// is intentionally insecure so is only intended for testing purposes.
// 
// This code is not meant to be run.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cstring>
size_t array1_size=1024, array2_size=1024, array_size_mask;
uint8_t array1[1024], array2[1024], temp;


// ----------------------------------------------------------------------------------------
// EXAMPLE 1:  This is the sample function from the Spectre paper.
//
// Comments:  The generated assembly (below) includes an LFENCE on the vulnerable code 
// path, as expected

void victim_function_v01(size_t x) {
     if (x < array1_size) {
          temp &= array2[array1[x] * 512];
     }
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN2@victim_fun
//    lfence
//    lea     rdx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rdx+rcx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rdx]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 2:  Moving the leak to a local function that can be inlined.
// 
// Comments:  Produces identical assembly to the example above (i.e. LFENCE is included)
// ----------------------------------------------------------------------------------------

void leakByteLocalFunction_v02(uint8_t k) { temp &= array2[(k)* 512]; }
void victim_function_v02(size_t x) {
     if (x < array1_size) {
          leakByteLocalFunction_v02(array1[x]);
     }
}


// ----------------------------------------------------------------------------------------
// EXAMPLE 3:  Moving the leak to a function that cannot be inlined.
//
// Comments: Output is unsafe.  The same results occur if leakByteNoinlineFunction() 
// is in another source module.

__attribute__((noinline)) void leakByteNoinlineFunction(uint8_t k) { temp &= array2[(k)* 512]; }
void victim_function_v03(size_t x) {
     if (x < array1_size)
          leakByteNoinlineFunction(array1[x]);
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN2@victim_fun
//    lea     rax, OFFSET FLAT:array1
//    movzx   ecx, BYTE PTR [rax+rcx]
//    jmp     leakByteNoinlineFunction
//  $LN2@victim_fun:
//    ret     0
//
//  leakByteNoinlineFunction PROC
//    movzx   ecx, cl
//    lea     rax, OFFSET FLAT:array2
//    shl     ecx, 9
//    movzx   eax, BYTE PTR [rcx+rax]
//    and     BYTE PTR temp, al
//    ret     0
//  leakByteNoinlineFunction ENDP


// ----------------------------------------------------------------------------------------
// EXAMPLE 4:  Add a left shift by one on the index.
// 
// Comments: Output is unsafe.

void victim_function_v04(size_t x) {
     if (x < array1_size)
          temp &= array2[array1[x << 1] * 512];
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN2@victim_fun
//    lea     rdx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rdx+rcx*2]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rdx]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 5:  Use x as the initial value in a for() loop.
//
// Comments: Output is unsafe.

void victim_function_v05(size_t x) {
     size_t i;
     if (x < array1_size) {
          for (i = x - 1; i >= 0; i--)
               temp &= array2[array1[i] * 512];
     }
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN3@victim_fun
//    movzx   edx, BYTE PTR temp
//    lea     r8, OFFSET FLAT:__ImageBase
//    lea     rax, QWORD PTR array1[r8-1]
//    add     rax, rcx
//  $LL4@victim_fun:
//    movzx   ecx, BYTE PTR [rax]
//    lea     rax, QWORD PTR [rax-1]
//    shl     rcx, 9
//    and     dl, BYTE PTR array2[rcx+r8]
//    jmp     SHORT $LL4@victim_fun
//  $LN3@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 6:  Check the bounds with an AND mask, rather than "<".
//
// Comments: Output is unsafe.

void victim_function_v06(size_t x) {
     if ((x & array_size_mask) == x)
          temp &= array2[array1[x] * 512];
}

//    mov     eax, DWORD PTR array_size_mask
//    and     rax, rcx
//    cmp     rax, rcx
//    jne     SHORT $LN2@victim_fun
//    lea     rdx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rdx+rcx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rdx]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 7:  Compare against the last known-good value.
//
// Comments: Output is unsafe.

void victim_function_v07(size_t x) {
     static size_t last_x = 0;
     if (x == last_x)
          temp &= array2[array1[x] * 512];
     if (x < array1_size)
          last_x = x;
}

//    mov     rdx, QWORD PTR ?last_x@?1??victim_function_v07@@9@9
//    cmp     rcx, rdx
//    jne     SHORT $LN2@victim_fun
//    lea     r8, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[r8+rcx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+r8]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    cmovb   rdx, rcx
//    mov     QWORD PTR ?last_x@?1??victim_function_v07@@9@9, rdx
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 8:  Use a ?: operator to check bounds.

void victim_function_v08(size_t x) {
     temp &= array2[array1[x < array1_size ? (x + 1) : 0] * 512];
}

//    cmp     rcx, QWORD PTR array1_size
//    jae     SHORT $LN3@victim_fun
//    inc     rcx
//    jmp     SHORT $LN4@victim_fun
//  $LN3@victim_fun:
//    xor     ecx, ecx
//  $LN4@victim_fun:
//    lea     rdx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rcx+rdx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rdx]
//    and     BYTE PTR temp, al
//    ret     0



// ----------------------------------------------------------------------------------------
// EXAMPLE 9:  Use a separate value to communicate the safety check status.
//
// Comments: Output is unsafe.

void victim_function_v09(size_t x, int *x_is_safe) {
     if (*x_is_safe)
          temp &= array2[array1[x] * 512];
}

//    cmp     DWORD PTR [rdx], 0
//    je      SHORT $LN2@victim_fun
//    lea     rdx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rcx+rdx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rdx]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 10:  Leak a comparison result.
//
// Comments: Output is unsafe.  Note that this vulnerability is a little different, namely
// the attacker is assumed to provide both x and k.  The victim code checks whether 
// array1[x] == k.  If so, the victim reads from array2[0].  The attacker can try
// values for k until finding the one that causes array2[0] to get brought into the cache.

void victim_function_v10(size_t x, uint8_t k) {
     if (x < array1_size) {
          if (array1[x] == k)
               temp &= array2[0];
     }
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN3@victim_fun
//    lea     rax, OFFSET FLAT:array1
//    cmp     BYTE PTR [rcx+rax], dl
//    jne     SHORT $LN3@victim_fun
//    movzx   eax, BYTE PTR array2
//    and     BYTE PTR temp, al
//  $LN3@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 11:  Use memcmp() to read the memory for the leak.
//
// Comments: Output is unsafe.

void victim_function_v11(size_t x) {
     if (x < array1_size)
          temp = memcmp(&temp, array2 + (array1[x] * 512), 1);
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN2@victim_fun
//    lea     rax, OFFSET FLAT:array1
//    movzx   ecx, BYTE PTR [rax+rcx]
//    lea     rax, OFFSET FLAT:array2
//    shl     rcx, 9
//    add     rcx, rax
//    movzx   eax, BYTE PTR temp
//    cmp     al, BYTE PTR [rcx]
//    jne     SHORT $LN4@victim_fun
//    xor     eax, eax
//    mov     BYTE PTR temp, al
//    ret     0
//  $LN4@victim_fun:
//    sbb     eax, eax
//    or      eax, 1
//    mov     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0

// ----------------------------------------------------------------------------------------
// EXAMPLE 12:  Make the index be the sum of two input parameters.
//
// Comments: Output is unsafe.

void victim_function_v12(size_t x, size_t y) {
     if ((x + y) < array1_size)
          temp &= array2[array1[x + y] * 512];
}

//    mov     eax, DWORD PTR array1_size
//    lea     r8, QWORD PTR [rcx+rdx]
//    cmp     r8, rax
//    jae     SHORT $LN2@victim_fun
//    lea     rax, QWORD PTR array1[rcx]
//    lea     r8, OFFSET FLAT:__ImageBase
//    add     rax, r8
//    movzx   ecx, BYTE PTR [rax+rdx]
//    shl     rcx, 9
//    movzx   eax, BYTE PTR array2[rcx+r8]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0

// ----------------------------------------------------------------------------------------
// EXAMPLE 13:  Do the safety check into an inline function
//
// Comments: Output is unsafe.

__inline int is_x_safe(size_t x) { if (x < array1_size) return 1; return 0; }
void victim_function_v13(size_t x) {
     if (is_x_safe(x))
          temp &= array2[array1[x] * 512];
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN2@victim_fun
//    lea     rdx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rdx+rcx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rdx]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 14:  Invert the low bits of x
//
// Comments: Output is unsafe.

void victim_function_v14(size_t x) {
     if (x < array1_size)
          temp &= array2[array1[x ^ 255] * 512];
}

//    mov     eax, DWORD PTR array1_size
//    cmp     rcx, rax
//    jae     SHORT $LN2@victim_fun
//    xor     rcx, 255                    ; 000000ffH
//    lea     rdx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rcx+rdx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rdx]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0


// ----------------------------------------------------------------------------------------
// EXAMPLE 15:  Pass a pointer to the length
//
// Comments: Output is unsafe.

void victim_function_v15(size_t *x) {
     if (*x < array1_size)
          temp &= array2[array1[*x] * 512];
}

//    mov     rax, QWORD PTR [rcx]
//    cmp     rax, QWORD PTR array1_size
//    jae     SHORT $LN2@victim_fun
//    lea     rcx, OFFSET FLAT:__ImageBase
//    movzx   eax, BYTE PTR array1[rax+rcx]
//    shl     rax, 9
//    movzx   eax, BYTE PTR array2[rax+rcx]
//    and     BYTE PTR temp, al
//  $LN2@victim_fun:
//    ret     0

int main(int argc, char** argv){
    size_t x = 10;
    size_t y = 10;
    int* x_is_safe = 0;
    uint8_t k = 10;
    victim_function_v01(x);
    victim_function_v02(x);
    victim_function_v03(x);
    victim_function_v04(x);
    victim_function_v05(x);
    victim_function_v06(x);
    victim_function_v07(x);
    victim_function_v08(x);
    victim_function_v09(x, x_is_safe);
    victim_function_v10(x,k);
    victim_function_v11(x);
    victim_function_v12(x,y);
    victim_function_v13(x);
    victim_function_v14(x);
    victim_function_v15(&x);

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
