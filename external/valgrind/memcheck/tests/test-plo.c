#include "tests/malloc.h"
#include <stdio.h>
#include <assert.h>

typedef  unsigned long long int  ULong;
typedef  unsigned long int       UWord;

__attribute__((noinline))
static int my_ffsll ( ULong x )
{
   int i;
   for (i = 0; i < 64; i++) {
      if ((x & 1ULL) == 1ULL)
         break;
      x >>= 1;
   }
   return i+1;
}

__attribute__((noinline))
static int aligned_strlen(char *s)
{
    
    assert(sizeof(ULong) == 8);
    
    assert(((unsigned long)s & 0x7) == 0);

    
    ULong val = *(ULong*)s;
    
    ULong val2 = val - 0x0101010101010101ULL;
    
    val2 ^= val;
    val2 &= 0x8080808080808080ULL;

    return (my_ffsll(val2) / 8) - 1;
}

__attribute__((noinline)) void foo ( int x )
{
   __asm__ __volatile__("":::"memory");
}

int
main(int argc, char *argv[])
{
    char *buf = memalign16(5);
    buf[0] = 'a';
    buf[1] = 'b';
    buf[2] = 'c';
    buf[3] = 'd';
    buf[4] = '\0';

    
    
    if (aligned_strlen(buf) == 4)
        foo(44);

    
    
    buf[4] = 'x';
    if (aligned_strlen(buf) == 0)
        foo(37);

    free(buf);

    UWord* words = malloc(3 * sizeof(UWord));
    free(words);

    
    UWord  w     = words[1];

    
    if (w == 0x31415927) {
       fprintf(stderr,
               "Elvis is alive and well and living in Milton Keynes.\n");
    }

    return 0;
}
