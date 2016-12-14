
#include "config.h"
#include <stdio.h>
#include <assert.h>


#undef PLAT_x86_linux
#undef PLAT_amd64_linux
#undef PLAT_ppc32_linux
#undef PLAT_ppc64_linux

#if defined(__i386__)
#  define PLAT_x86_linux 1
#elif defined(__x86_64__)
#  define PLAT_amd64_linux 1
#endif


#if defined(PLAT_amd64_linux) || defined(PLAT_x86_linux)
#  define XADD_R_R(_addr,_lval) \
	__asm__ __volatile__( \
	"xadd %1, %0" \
	:  "=r"(_lval),"=r"(_addr) \
	:   "0"(_lval),"1"(_addr) \
	: "flags" \
	)
#else
#  error "Unsupported architecture"
#endif

int main ( void )
{
   long d = 20, s = 2;
   long xadd_r_r_res;
#define XADD_R_R_RES 42
   
   XADD_R_R(s, d);
   xadd_r_r_res = s + d;
   assert(xadd_r_r_res == XADD_R_R_RES);

   if (xadd_r_r_res == XADD_R_R_RES)
      printf("success\n");
   else
      printf("failure\n");

   return xadd_r_r_res;
}
