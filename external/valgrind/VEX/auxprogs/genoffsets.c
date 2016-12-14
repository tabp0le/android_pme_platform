

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2004-2013 OpenWorks LLP
      info@open-works.net

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   The GNU General Public License is contained in the file COPYING.

   Neither the names of the U.S. Department of Energy nor the
   University of California nor the names of its contributors may be
   used to endorse or promote products derived from this software
   without prior written permission.
*/

#include <stdio.h>


#include "../pub/libvex_basictypes.h"
#include "../pub/libvex_guest_x86.h"
#include "../pub/libvex_guest_amd64.h"
#include "../pub/libvex_guest_ppc32.h"
#include "../pub/libvex_guest_ppc64.h"
#include "../pub/libvex_guest_arm.h"
#include "../pub/libvex_guest_arm64.h"
#include "../pub/libvex_guest_s390x.h"
#include "../pub/libvex_guest_mips32.h"
#include "../pub/libvex_guest_mips64.h"
#include "../pub/libvex_guest_tilegx.h"

#define VG_STRINGIFZ(__str)  #__str
#define VG_STRINGIFY(__str)  VG_STRINGIFZ(__str)

#define my_offsetof(__type,__field) (&((__type*)0)->__field)

#define GENOFFSET(_structUppercase,_structLowercase,_fieldname)  \
   __asm__ __volatile__ ( \
      "\n#define OFFSET_" \
      VG_STRINGIFY(_structLowercase) "_" \
      VG_STRINGIFY(_fieldname) \
      " xyzzy%0\n" :  \
                   :  "n" \
         (my_offsetof(VexGuest##_structUppercase##State, \
          guest_##_fieldname)) \
   )

void foo ( void );
__attribute__((noinline))
void foo ( void )
{
   
   GENOFFSET(X86,x86,EAX);
   GENOFFSET(X86,x86,EBX);
   GENOFFSET(X86,x86,ECX);
   GENOFFSET(X86,x86,EDX);
   GENOFFSET(X86,x86,ESI);
   GENOFFSET(X86,x86,EDI);
   GENOFFSET(X86,x86,EBP);
   GENOFFSET(X86,x86,ESP);
   GENOFFSET(X86,x86,EIP);
   GENOFFSET(X86,x86,CS);
   GENOFFSET(X86,x86,DS);
   GENOFFSET(X86,x86,ES);
   GENOFFSET(X86,x86,FS);
   GENOFFSET(X86,x86,GS);
   GENOFFSET(X86,x86,SS);

   
   GENOFFSET(AMD64,amd64,RAX);
   GENOFFSET(AMD64,amd64,RBX);
   GENOFFSET(AMD64,amd64,RCX);
   GENOFFSET(AMD64,amd64,RDX);
   GENOFFSET(AMD64,amd64,RSI);
   GENOFFSET(AMD64,amd64,RDI);
   GENOFFSET(AMD64,amd64,RSP);
   GENOFFSET(AMD64,amd64,RBP);
   GENOFFSET(AMD64,amd64,R8);
   GENOFFSET(AMD64,amd64,R9);
   GENOFFSET(AMD64,amd64,R10);
   GENOFFSET(AMD64,amd64,R11);
   GENOFFSET(AMD64,amd64,R12);
   GENOFFSET(AMD64,amd64,R13);
   GENOFFSET(AMD64,amd64,R14);
   GENOFFSET(AMD64,amd64,R15);
   GENOFFSET(AMD64,amd64,RIP);

   
   GENOFFSET(PPC32,ppc32,GPR0);
   GENOFFSET(PPC32,ppc32,GPR1);
   GENOFFSET(PPC32,ppc32,GPR2);
   GENOFFSET(PPC32,ppc32,GPR3);
   GENOFFSET(PPC32,ppc32,GPR4);
   GENOFFSET(PPC32,ppc32,GPR5);
   GENOFFSET(PPC32,ppc32,GPR6);
   GENOFFSET(PPC32,ppc32,GPR7);
   GENOFFSET(PPC32,ppc32,GPR8);
   GENOFFSET(PPC32,ppc32,GPR9);
   GENOFFSET(PPC32,ppc32,GPR10);
   GENOFFSET(PPC32,ppc32,CIA);
   GENOFFSET(PPC32,ppc32,CR0_0);

   
   GENOFFSET(PPC64,ppc64,GPR0);
   GENOFFSET(PPC64,ppc64,GPR1);
   GENOFFSET(PPC64,ppc64,GPR2);
   GENOFFSET(PPC64,ppc64,GPR3);
   GENOFFSET(PPC64,ppc64,GPR4);
   GENOFFSET(PPC64,ppc64,GPR5);
   GENOFFSET(PPC64,ppc64,GPR6);
   GENOFFSET(PPC64,ppc64,GPR7);
   GENOFFSET(PPC64,ppc64,GPR8);
   GENOFFSET(PPC64,ppc64,GPR9);
   GENOFFSET(PPC64,ppc64,GPR10);
   GENOFFSET(PPC64,ppc64,CIA);
   GENOFFSET(PPC64,ppc64,CR0_0);

   
   GENOFFSET(ARM,arm,R0);
   GENOFFSET(ARM,arm,R1);
   GENOFFSET(ARM,arm,R2);
   GENOFFSET(ARM,arm,R3);
   GENOFFSET(ARM,arm,R4);
   GENOFFSET(ARM,arm,R5);
   GENOFFSET(ARM,arm,R7);
   GENOFFSET(ARM,arm,R13);
   GENOFFSET(ARM,arm,R14);
   GENOFFSET(ARM,arm,R15T);

   
   GENOFFSET(ARM64,arm64,X0);
   GENOFFSET(ARM64,arm64,X1);
   GENOFFSET(ARM64,arm64,X2);
   GENOFFSET(ARM64,arm64,X3);
   GENOFFSET(ARM64,arm64,X4);
   GENOFFSET(ARM64,arm64,X5);
   GENOFFSET(ARM64,arm64,X6);
   GENOFFSET(ARM64,arm64,X7);
   GENOFFSET(ARM64,arm64,X8);
   GENOFFSET(ARM64,arm64,XSP);
   GENOFFSET(ARM64,arm64,PC);

   
   GENOFFSET(S390X,s390x,r2);
   GENOFFSET(S390X,s390x,r3);
   GENOFFSET(S390X,s390x,r4);
   GENOFFSET(S390X,s390x,r5);
   GENOFFSET(S390X,s390x,r6);
   GENOFFSET(S390X,s390x,r7);
   GENOFFSET(S390X,s390x,r15);
   GENOFFSET(S390X,s390x,IA);
   GENOFFSET(S390X,s390x,SYSNO);
   GENOFFSET(S390X,s390x,IP_AT_SYSCALL);
   GENOFFSET(S390X,s390x,fpc);
   GENOFFSET(S390X,s390x,CC_OP);
   GENOFFSET(S390X,s390x,CC_DEP1);
   GENOFFSET(S390X,s390x,CC_DEP2);
   GENOFFSET(S390X,s390x,CC_NDEP);

   
   GENOFFSET(MIPS32,mips32,r0);
   GENOFFSET(MIPS32,mips32,r1);   
   GENOFFSET(MIPS32,mips32,r2);
   GENOFFSET(MIPS32,mips32,r3);
   GENOFFSET(MIPS32,mips32,r4);
   GENOFFSET(MIPS32,mips32,r5);
   GENOFFSET(MIPS32,mips32,r6);
   GENOFFSET(MIPS32,mips32,r7);
   GENOFFSET(MIPS32,mips32,r8);
   GENOFFSET(MIPS32,mips32,r9);
   GENOFFSET(MIPS32,mips32,r10);
   GENOFFSET(MIPS32,mips32,r11);
   GENOFFSET(MIPS32,mips32,r12);
   GENOFFSET(MIPS32,mips32,r13);
   GENOFFSET(MIPS32,mips32,r14);
   GENOFFSET(MIPS32,mips32,r15);
   GENOFFSET(MIPS32,mips32,r15);
   GENOFFSET(MIPS32,mips32,r17);
   GENOFFSET(MIPS32,mips32,r18);
   GENOFFSET(MIPS32,mips32,r19);
   GENOFFSET(MIPS32,mips32,r20);
   GENOFFSET(MIPS32,mips32,r21);
   GENOFFSET(MIPS32,mips32,r22);
   GENOFFSET(MIPS32,mips32,r23);
   GENOFFSET(MIPS32,mips32,r24);
   GENOFFSET(MIPS32,mips32,r25);
   GENOFFSET(MIPS32,mips32,r26);
   GENOFFSET(MIPS32,mips32,r27);
   GENOFFSET(MIPS32,mips32,r28);
   GENOFFSET(MIPS32,mips32,r29);
   GENOFFSET(MIPS32,mips32,r30);
   GENOFFSET(MIPS32,mips32,r31);
   GENOFFSET(MIPS32,mips32,PC);
   GENOFFSET(MIPS32,mips32,HI);
   GENOFFSET(MIPS32,mips32,LO);

   
   GENOFFSET(MIPS64,mips64,r0);
   GENOFFSET(MIPS64,mips64,r1);
   GENOFFSET(MIPS64,mips64,r2);
   GENOFFSET(MIPS64,mips64,r3);
   GENOFFSET(MIPS64,mips64,r4);
   GENOFFSET(MIPS64,mips64,r5);
   GENOFFSET(MIPS64,mips64,r6);
   GENOFFSET(MIPS64,mips64,r7);
   GENOFFSET(MIPS64,mips64,r8);
   GENOFFSET(MIPS64,mips64,r9);
   GENOFFSET(MIPS64,mips64,r10);
   GENOFFSET(MIPS64,mips64,r11);
   GENOFFSET(MIPS64,mips64,r12);
   GENOFFSET(MIPS64,mips64,r13);
   GENOFFSET(MIPS64,mips64,r14);
   GENOFFSET(MIPS64,mips64,r15);
   GENOFFSET(MIPS64,mips64,r15);
   GENOFFSET(MIPS64,mips64,r17);
   GENOFFSET(MIPS64,mips64,r18);
   GENOFFSET(MIPS64,mips64,r19);
   GENOFFSET(MIPS64,mips64,r20);
   GENOFFSET(MIPS64,mips64,r21);
   GENOFFSET(MIPS64,mips64,r22);
   GENOFFSET(MIPS64,mips64,r23);
   GENOFFSET(MIPS64,mips64,r24);
   GENOFFSET(MIPS64,mips64,r25);
   GENOFFSET(MIPS64,mips64,r26);
   GENOFFSET(MIPS64,mips64,r27);
   GENOFFSET(MIPS64,mips64,r28);
   GENOFFSET(MIPS64,mips64,r29);
   GENOFFSET(MIPS64,mips64,r30);
   GENOFFSET(MIPS64,mips64,r31);
   GENOFFSET(MIPS64,mips64,PC);
   GENOFFSET(MIPS64,mips64,HI);
   GENOFFSET(MIPS64,mips64,LO);

   
   GENOFFSET(TILEGX,tilegx,r0);
   GENOFFSET(TILEGX,tilegx,r1);
   GENOFFSET(TILEGX,tilegx,r2);
   GENOFFSET(TILEGX,tilegx,r3);
   GENOFFSET(TILEGX,tilegx,r4);
   GENOFFSET(TILEGX,tilegx,r5);
   GENOFFSET(TILEGX,tilegx,r6);
   GENOFFSET(TILEGX,tilegx,r7);
   GENOFFSET(TILEGX,tilegx,r8);
   GENOFFSET(TILEGX,tilegx,r9);
   GENOFFSET(TILEGX,tilegx,r10);
   GENOFFSET(TILEGX,tilegx,r11);
   GENOFFSET(TILEGX,tilegx,r12);
   GENOFFSET(TILEGX,tilegx,r13);
   GENOFFSET(TILEGX,tilegx,r14);
   GENOFFSET(TILEGX,tilegx,r15);
   GENOFFSET(TILEGX,tilegx,r16);
   GENOFFSET(TILEGX,tilegx,r17);
   GENOFFSET(TILEGX,tilegx,r18);
   GENOFFSET(TILEGX,tilegx,r19);
   GENOFFSET(TILEGX,tilegx,r20);
   GENOFFSET(TILEGX,tilegx,r21);
   GENOFFSET(TILEGX,tilegx,r22);
   GENOFFSET(TILEGX,tilegx,r23);
   GENOFFSET(TILEGX,tilegx,r24);
   GENOFFSET(TILEGX,tilegx,r25);
   GENOFFSET(TILEGX,tilegx,r26);
   GENOFFSET(TILEGX,tilegx,r27);
   GENOFFSET(TILEGX,tilegx,r28);
   GENOFFSET(TILEGX,tilegx,r29);
   GENOFFSET(TILEGX,tilegx,r30);
   GENOFFSET(TILEGX,tilegx,r31);
   GENOFFSET(TILEGX,tilegx,r32);
   GENOFFSET(TILEGX,tilegx,r33);
   GENOFFSET(TILEGX,tilegx,r34);
   GENOFFSET(TILEGX,tilegx,r35);
   GENOFFSET(TILEGX,tilegx,r36);
   GENOFFSET(TILEGX,tilegx,r37);
   GENOFFSET(TILEGX,tilegx,r38);
   GENOFFSET(TILEGX,tilegx,r39);
   GENOFFSET(TILEGX,tilegx,r40);
   GENOFFSET(TILEGX,tilegx,r41);
   GENOFFSET(TILEGX,tilegx,r42);
   GENOFFSET(TILEGX,tilegx,r43);
   GENOFFSET(TILEGX,tilegx,r44);
   GENOFFSET(TILEGX,tilegx,r45);
   GENOFFSET(TILEGX,tilegx,r46);
   GENOFFSET(TILEGX,tilegx,r47);
   GENOFFSET(TILEGX,tilegx,r48);
   GENOFFSET(TILEGX,tilegx,r49);
   GENOFFSET(TILEGX,tilegx,r50);
   GENOFFSET(TILEGX,tilegx,r51);
   GENOFFSET(TILEGX,tilegx,r52);
   GENOFFSET(TILEGX,tilegx,r53);
   GENOFFSET(TILEGX,tilegx,r54);
   GENOFFSET(TILEGX,tilegx,r55);
   GENOFFSET(TILEGX,tilegx,pc);
   GENOFFSET(TILEGX,tilegx,EMNOTE);
   GENOFFSET(TILEGX,tilegx,CMSTART);
   GENOFFSET(TILEGX,tilegx,NRADDR);
}
