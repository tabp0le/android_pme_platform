

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2010-2013 RT-RK
      mips-valgrind@rt-rk.com

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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "libvex_basictypes.h"
#include "libvex_emnote.h"
#include "libvex_guest_mips32.h"
#include "libvex_guest_mips64.h"
#include "libvex_ir.h"
#include "libvex.h"

#include "main_util.h"
#include "main_globals.h"
#include "guest_generic_bb_to_IR.h"
#include "guest_mips_defs.h"


#define ALWAYSDEFD32(field)                            \
    { offsetof(VexGuestMIPS32State, field),            \
      (sizeof ((VexGuestMIPS32State*)0)->field) }

#define ALWAYSDEFD64(field)                            \
    { offsetof(VexGuestMIPS64State, field),            \
      (sizeof ((VexGuestMIPS64State*)0)->field) }

IRExpr *guest_mips32_spechelper(const HChar * function_name, IRExpr ** args,
                                IRStmt ** precedingStmts, Int n_precedingStmts)
{
   return NULL;
}

IRExpr *guest_mips64_spechelper ( const HChar * function_name, IRExpr ** args,
                                  IRStmt ** precedingStmts,
                                  Int n_precedingStmts )
{
   return NULL;
}

void LibVEX_GuestMIPS32_initialise(  VexGuestMIPS32State * vex_state)
{
   vex_state->guest_r0 = 0;   
   vex_state->guest_r1 = 0;   
   vex_state->guest_r2 = 0;   
   vex_state->guest_r3 = 0;   
   vex_state->guest_r4 = 0;   
   vex_state->guest_r5 = 0;
   vex_state->guest_r6 = 0;
   vex_state->guest_r7 = 0;
   vex_state->guest_r8 = 0;   
   vex_state->guest_r9 = 0;
   vex_state->guest_r10 = 0;
   vex_state->guest_r11 = 0;
   vex_state->guest_r12 = 0;
   vex_state->guest_r13 = 0;
   vex_state->guest_r14 = 0;
   vex_state->guest_r15 = 0;
   vex_state->guest_r16 = 0;  
   vex_state->guest_r17 = 0;
   vex_state->guest_r18 = 0;
   vex_state->guest_r19 = 0;
   vex_state->guest_r20 = 0;
   vex_state->guest_r21 = 0;
   vex_state->guest_r22 = 0;
   vex_state->guest_r23 = 0;
   vex_state->guest_r24 = 0;  
   vex_state->guest_r25 = 0;
   vex_state->guest_r26 = 0;  
   vex_state->guest_r27 = 0;
   vex_state->guest_r28 = 0;  
   vex_state->guest_r29 = 0;  
   vex_state->guest_r30 = 0;  
   vex_state->guest_r31 = 0;  
   vex_state->guest_PC = 0;   
   vex_state->guest_HI = 0;   
   vex_state->guest_LO = 0;   

   
   vex_state->guest_f0 = 0x7ff800007ff80000ULL; 
   vex_state->guest_f1 = 0x7ff800007ff80000ULL;
   vex_state->guest_f2 = 0x7ff800007ff80000ULL;
   vex_state->guest_f3 = 0x7ff800007ff80000ULL;
   vex_state->guest_f4 = 0x7ff800007ff80000ULL;
   vex_state->guest_f5 = 0x7ff800007ff80000ULL;
   vex_state->guest_f6 = 0x7ff800007ff80000ULL;
   vex_state->guest_f7 = 0x7ff800007ff80000ULL;
   vex_state->guest_f8 = 0x7ff800007ff80000ULL;
   vex_state->guest_f9 = 0x7ff800007ff80000ULL;
   vex_state->guest_f10 = 0x7ff800007ff80000ULL;
   vex_state->guest_f11 = 0x7ff800007ff80000ULL;
   vex_state->guest_f12 = 0x7ff800007ff80000ULL;
   vex_state->guest_f13 = 0x7ff800007ff80000ULL;
   vex_state->guest_f14 = 0x7ff800007ff80000ULL;
   vex_state->guest_f15 = 0x7ff800007ff80000ULL;
   vex_state->guest_f16 = 0x7ff800007ff80000ULL;
   vex_state->guest_f17 = 0x7ff800007ff80000ULL;
   vex_state->guest_f18 = 0x7ff800007ff80000ULL;
   vex_state->guest_f19 = 0x7ff800007ff80000ULL;
   vex_state->guest_f20 = 0x7ff800007ff80000ULL;
   vex_state->guest_f21 = 0x7ff800007ff80000ULL;
   vex_state->guest_f22 = 0x7ff800007ff80000ULL;
   vex_state->guest_f23 = 0x7ff800007ff80000ULL;
   vex_state->guest_f24 = 0x7ff800007ff80000ULL;
   vex_state->guest_f25 = 0x7ff800007ff80000ULL;
   vex_state->guest_f26 = 0x7ff800007ff80000ULL;
   vex_state->guest_f27 = 0x7ff800007ff80000ULL;
   vex_state->guest_f28 = 0x7ff800007ff80000ULL;
   vex_state->guest_f29 = 0x7ff800007ff80000ULL;
   vex_state->guest_f30 = 0x7ff800007ff80000ULL;
   vex_state->guest_f31 = 0x7ff800007ff80000ULL;

   vex_state->guest_FIR = 0;  
   vex_state->guest_FCCR = 0; 
   vex_state->guest_FEXR = 0; 
   vex_state->guest_FENR = 0; 
   vex_state->guest_FCSR = 0; 
   vex_state->guest_ULR = 0; 

   
   
   vex_state->guest_EMNOTE = 0;

   
   vex_state->guest_CMSTART = 0;
   vex_state->guest_CMLEN = 0;
   vex_state->host_EvC_COUNTER = 0;
   vex_state->host_EvC_FAILADDR = 0;

   vex_state->guest_NRADDR = 0;

   vex_state->guest_COND = 0;

   
   vex_state->guest_DSPControl = 0;   
   vex_state->guest_ac0 = 0;          
   vex_state->guest_ac1 = 0;          
   vex_state->guest_ac2 = 0;          
   vex_state->guest_ac3 = 0;          
}

void LibVEX_GuestMIPS64_initialise (  VexGuestMIPS64State * vex_state )
{
   vex_state->guest_r0 = 0;  
   vex_state->guest_r1 = 0;  
   vex_state->guest_r2 = 0;  
   vex_state->guest_r3 = 0;
   vex_state->guest_r4 = 0;  
   vex_state->guest_r5 = 0;
   vex_state->guest_r6 = 0;
   vex_state->guest_r7 = 0;
   vex_state->guest_r8 = 0;
   vex_state->guest_r9 = 0;
   vex_state->guest_r10 = 0;
   vex_state->guest_r11 = 0;
   vex_state->guest_r12 = 0;  
   vex_state->guest_r13 = 0;
   vex_state->guest_r14 = 0;
   vex_state->guest_r15 = 0;
   vex_state->guest_r16 = 0;  
   vex_state->guest_r17 = 0;
   vex_state->guest_r18 = 0;
   vex_state->guest_r19 = 0;
   vex_state->guest_r20 = 0;
   vex_state->guest_r21 = 0;
   vex_state->guest_r22 = 0;
   vex_state->guest_r23 = 0;
   vex_state->guest_r24 = 0;  
   vex_state->guest_r25 = 0;
   vex_state->guest_r26 = 0;  
   vex_state->guest_r27 = 0;
   vex_state->guest_r28 = 0;  
   vex_state->guest_r29 = 0;  
   vex_state->guest_r30 = 0;  
   vex_state->guest_r31 = 0;  
   vex_state->guest_PC = 0;   
   vex_state->guest_HI = 0;   
   vex_state->guest_LO = 0;   

   
   vex_state->guest_f0 =  0x7ff800007ff80000ULL;  
   vex_state->guest_f1 =  0x7ff800007ff80000ULL;
   vex_state->guest_f2 =  0x7ff800007ff80000ULL;
   vex_state->guest_f3 =  0x7ff800007ff80000ULL;
   vex_state->guest_f4 =  0x7ff800007ff80000ULL;
   vex_state->guest_f5 =  0x7ff800007ff80000ULL;
   vex_state->guest_f6 =  0x7ff800007ff80000ULL;
   vex_state->guest_f7 =  0x7ff800007ff80000ULL;
   vex_state->guest_f8 =  0x7ff800007ff80000ULL;
   vex_state->guest_f9 =  0x7ff800007ff80000ULL;
   vex_state->guest_f10 = 0x7ff800007ff80000ULL;
   vex_state->guest_f11 = 0x7ff800007ff80000ULL;
   vex_state->guest_f12 = 0x7ff800007ff80000ULL;
   vex_state->guest_f13 = 0x7ff800007ff80000ULL;
   vex_state->guest_f14 = 0x7ff800007ff80000ULL;
   vex_state->guest_f15 = 0x7ff800007ff80000ULL;
   vex_state->guest_f16 = 0x7ff800007ff80000ULL;
   vex_state->guest_f17 = 0x7ff800007ff80000ULL;
   vex_state->guest_f18 = 0x7ff800007ff80000ULL;
   vex_state->guest_f19 = 0x7ff800007ff80000ULL;
   vex_state->guest_f20 = 0x7ff800007ff80000ULL;
   vex_state->guest_f21 = 0x7ff800007ff80000ULL;
   vex_state->guest_f22 = 0x7ff800007ff80000ULL;
   vex_state->guest_f23 = 0x7ff800007ff80000ULL;
   vex_state->guest_f24 = 0x7ff800007ff80000ULL;
   vex_state->guest_f25 = 0x7ff800007ff80000ULL;
   vex_state->guest_f26 = 0x7ff800007ff80000ULL;
   vex_state->guest_f27 = 0x7ff800007ff80000ULL;
   vex_state->guest_f28 = 0x7ff800007ff80000ULL;
   vex_state->guest_f29 = 0x7ff800007ff80000ULL;
   vex_state->guest_f30 = 0x7ff800007ff80000ULL;
   vex_state->guest_f31 = 0x7ff800007ff80000ULL;

   vex_state->guest_FIR = 0;   
   vex_state->guest_FCCR = 0;  
   vex_state->guest_FEXR = 0;  
   vex_state->guest_FENR = 0;  
   vex_state->guest_FCSR = 0;  

   vex_state->guest_ULR = 0;

   
   
   vex_state->guest_EMNOTE = 0;

   
   vex_state->guest_CMSTART = 0;
   vex_state->guest_CMLEN = 0;
   vex_state->host_EvC_COUNTER = 0;
   vex_state->host_EvC_FAILADDR = 0;

   vex_state->guest_NRADDR = 0;

   vex_state->guest_COND = 0;
}


Bool guest_mips32_state_requires_precise_mem_exns (
        Int minoff, Int maxoff, VexRegisterUpdates pxControl
     )
{
   Int sp_min = offsetof(VexGuestMIPS32State, guest_r29);
   Int sp_max = sp_min + 4 - 1;
   Int pc_min = offsetof(VexGuestMIPS32State, guest_PC);
   Int pc_max = pc_min + 4 - 1;

   if (maxoff < sp_min || minoff > sp_max) {
      
      if (pxControl == VexRegUpdSpAtMemAccess)
         return False;  
   } else {
      return True;
   }

   if (maxoff < pc_min || minoff > pc_max) {
      
   } else {
      return True;
   }

   Int fp_min = offsetof(VexGuestMIPS32State, guest_r30);
   Int fp_max = fp_min + 4 - 1;

   if (maxoff < fp_min || minoff > fp_max) {
      
   } else {
      return True;
   }

   return False;
}

Bool guest_mips64_state_requires_precise_mem_exns (
        Int minoff, Int maxoff, VexRegisterUpdates pxControl
     )
{
   Int sp_min = offsetof(VexGuestMIPS64State, guest_r29);
   Int sp_max = sp_min + 8 - 1;
   Int pc_min = offsetof(VexGuestMIPS64State, guest_PC);
   Int pc_max = pc_min + 8 - 1;

   if ( maxoff < sp_min || minoff > sp_max ) {
      
      if (pxControl == VexRegUpdSpAtMemAccess)
         return False;  
   } else {
      return True;
   }

   if ( maxoff < pc_min || minoff > pc_max ) {
      
   } else {
      return True;
   }

   Int fp_min = offsetof(VexGuestMIPS64State, guest_r30);
   Int fp_max = fp_min + 8 - 1;

   if ( maxoff < fp_min || minoff > fp_max ) {
      
   } else {
      return True;
   }

   return False;
}

VexGuestLayout mips32Guest_layout = {
   
   .total_sizeB = sizeof(VexGuestMIPS32State),
   
   .offset_SP = offsetof(VexGuestMIPS32State, guest_r29),
   .sizeof_SP = 4,
   
   .offset_FP = offsetof(VexGuestMIPS32State, guest_r30),
   .sizeof_FP = 4,
   
   .offset_IP = offsetof(VexGuestMIPS32State, guest_PC),
   .sizeof_IP = 4,
   .n_alwaysDefd = 8,
   
   .alwaysDefd = {
              ALWAYSDEFD32(guest_r0),
              ALWAYSDEFD32(guest_r1),
              ALWAYSDEFD32(guest_EMNOTE),
              ALWAYSDEFD32(guest_CMSTART),
              ALWAYSDEFD32(guest_CMLEN),
              ALWAYSDEFD32(guest_r29),
              ALWAYSDEFD32(guest_r31),
              ALWAYSDEFD32(guest_ULR)
             }
};

VexGuestLayout mips64Guest_layout = {
   
   .total_sizeB = sizeof(VexGuestMIPS64State),
   
   .offset_SP = offsetof(VexGuestMIPS64State, guest_r29),
   .sizeof_SP = 8,
   
   .offset_FP = offsetof(VexGuestMIPS64State, guest_r30),
   .sizeof_FP = 8,
   
   .offset_IP = offsetof(VexGuestMIPS64State, guest_PC),
   .sizeof_IP = 8,
   .n_alwaysDefd = 7,
   
   .alwaysDefd = {
                   ALWAYSDEFD64 (guest_r0),
                   ALWAYSDEFD64 (guest_EMNOTE),
                   ALWAYSDEFD64 (guest_CMSTART),
                   ALWAYSDEFD64 (guest_CMLEN),
                   ALWAYSDEFD64 (guest_r29),
                   ALWAYSDEFD64 (guest_r31),
                   ALWAYSDEFD64 (guest_ULR)
                  }
};

#define ASM_VOLATILE_CASE(rd, sel) \
         case rd: \
            asm volatile ("mfc0 %0, $" #rd ", "#sel"\n\t" :"=r" (x) ); \
            break;

UInt mips32_dirtyhelper_mfc0(UInt rd, UInt sel)
{
   UInt x = 0;
#if defined(__mips__) && ((defined(__mips_isa_rev) && __mips_isa_rev >= 2))
   switch (sel) {
      case 0:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 0);
            ASM_VOLATILE_CASE(1, 0);
            ASM_VOLATILE_CASE(2, 0);
            ASM_VOLATILE_CASE(3, 0);
            ASM_VOLATILE_CASE(4, 0);
            ASM_VOLATILE_CASE(5, 0);
            ASM_VOLATILE_CASE(6, 0);
            ASM_VOLATILE_CASE(7, 0);
            ASM_VOLATILE_CASE(8, 0);
            ASM_VOLATILE_CASE(9, 0);
            ASM_VOLATILE_CASE(10, 0);
            ASM_VOLATILE_CASE(11, 0);
            ASM_VOLATILE_CASE(12, 0);
            ASM_VOLATILE_CASE(13, 0);
            ASM_VOLATILE_CASE(14, 0);
            ASM_VOLATILE_CASE(15, 0);
            ASM_VOLATILE_CASE(16, 0);
            ASM_VOLATILE_CASE(17, 0);
            ASM_VOLATILE_CASE(18, 0);
            ASM_VOLATILE_CASE(19, 0);
            ASM_VOLATILE_CASE(20, 0);
            ASM_VOLATILE_CASE(21, 0);
            ASM_VOLATILE_CASE(22, 0);
            ASM_VOLATILE_CASE(23, 0);
            ASM_VOLATILE_CASE(24, 0);
            ASM_VOLATILE_CASE(25, 0);
            ASM_VOLATILE_CASE(26, 0);
            ASM_VOLATILE_CASE(27, 0);
            ASM_VOLATILE_CASE(28, 0);
            ASM_VOLATILE_CASE(29, 0);
            ASM_VOLATILE_CASE(30, 0);
            ASM_VOLATILE_CASE(31, 0);
         default:
            break;
         }
         break;
      case 1:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 1);
            ASM_VOLATILE_CASE(1, 1);
            ASM_VOLATILE_CASE(2, 1);
            ASM_VOLATILE_CASE(3, 1);
            ASM_VOLATILE_CASE(4, 1);
            ASM_VOLATILE_CASE(5, 1);
            ASM_VOLATILE_CASE(6, 1);
            ASM_VOLATILE_CASE(7, 1);
            ASM_VOLATILE_CASE(8, 1);
            ASM_VOLATILE_CASE(9, 1);
            ASM_VOLATILE_CASE(10, 1);
            ASM_VOLATILE_CASE(11, 1);
            ASM_VOLATILE_CASE(12, 1);
            ASM_VOLATILE_CASE(13, 1);
            ASM_VOLATILE_CASE(14, 1);
            ASM_VOLATILE_CASE(15, 1);
            ASM_VOLATILE_CASE(16, 1);
            ASM_VOLATILE_CASE(17, 1);
            ASM_VOLATILE_CASE(18, 1);
            ASM_VOLATILE_CASE(19, 1);
            ASM_VOLATILE_CASE(20, 1);
            ASM_VOLATILE_CASE(21, 1);
            ASM_VOLATILE_CASE(22, 1);
            ASM_VOLATILE_CASE(23, 1);
            ASM_VOLATILE_CASE(24, 1);
            ASM_VOLATILE_CASE(25, 1);
            ASM_VOLATILE_CASE(26, 1);
            ASM_VOLATILE_CASE(27, 1);
            ASM_VOLATILE_CASE(28, 1);
            ASM_VOLATILE_CASE(29, 1);
            ASM_VOLATILE_CASE(30, 1);
            ASM_VOLATILE_CASE(31, 1);
         default:
            break;
         }
         break;
      case 2:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 2);
            ASM_VOLATILE_CASE(1, 2);
            ASM_VOLATILE_CASE(2, 2);
            ASM_VOLATILE_CASE(3, 1);
            ASM_VOLATILE_CASE(4, 2);
            ASM_VOLATILE_CASE(5, 2);
            ASM_VOLATILE_CASE(6, 2);
            ASM_VOLATILE_CASE(7, 2);
            ASM_VOLATILE_CASE(8, 2);
            ASM_VOLATILE_CASE(9, 2);
            ASM_VOLATILE_CASE(10, 2);
            ASM_VOLATILE_CASE(11, 2);
            ASM_VOLATILE_CASE(12, 2);
            ASM_VOLATILE_CASE(13, 2);
            ASM_VOLATILE_CASE(14, 2);
            ASM_VOLATILE_CASE(15, 2);
            ASM_VOLATILE_CASE(16, 2);
            ASM_VOLATILE_CASE(17, 2);
            ASM_VOLATILE_CASE(18, 2);
            ASM_VOLATILE_CASE(19, 2);
            ASM_VOLATILE_CASE(20, 2);
            ASM_VOLATILE_CASE(21, 2);
            ASM_VOLATILE_CASE(22, 2);
            ASM_VOLATILE_CASE(23, 2);
            ASM_VOLATILE_CASE(24, 2);
            ASM_VOLATILE_CASE(25, 2);
            ASM_VOLATILE_CASE(26, 2);
            ASM_VOLATILE_CASE(27, 2);
            ASM_VOLATILE_CASE(28, 2);
            ASM_VOLATILE_CASE(29, 2);
            ASM_VOLATILE_CASE(30, 2);
            ASM_VOLATILE_CASE(31, 2);
         default:
            break;
         }
         break;
      case 3:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 3);
            ASM_VOLATILE_CASE(1, 3);
            ASM_VOLATILE_CASE(2, 3);
            ASM_VOLATILE_CASE(3, 3);
            ASM_VOLATILE_CASE(4, 3);
            ASM_VOLATILE_CASE(5, 3);
            ASM_VOLATILE_CASE(6, 3);
            ASM_VOLATILE_CASE(7, 3);
            ASM_VOLATILE_CASE(8, 3);
            ASM_VOLATILE_CASE(9, 3);
            ASM_VOLATILE_CASE(10, 3);
            ASM_VOLATILE_CASE(11, 3);
            ASM_VOLATILE_CASE(12, 3);
            ASM_VOLATILE_CASE(13, 3);
            ASM_VOLATILE_CASE(14, 3);
            ASM_VOLATILE_CASE(15, 3);
            ASM_VOLATILE_CASE(16, 3);
            ASM_VOLATILE_CASE(17, 3);
            ASM_VOLATILE_CASE(18, 3);
            ASM_VOLATILE_CASE(19, 3);
            ASM_VOLATILE_CASE(20, 3);
            ASM_VOLATILE_CASE(21, 3);
            ASM_VOLATILE_CASE(22, 3);
            ASM_VOLATILE_CASE(23, 3);
            ASM_VOLATILE_CASE(24, 3);
            ASM_VOLATILE_CASE(25, 3);
            ASM_VOLATILE_CASE(26, 3);
            ASM_VOLATILE_CASE(27, 3);
            ASM_VOLATILE_CASE(28, 3);
            ASM_VOLATILE_CASE(29, 3);
            ASM_VOLATILE_CASE(30, 3);
            ASM_VOLATILE_CASE(31, 3);
         default:
            break;
         }
         break;
      case 4:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 4);
            ASM_VOLATILE_CASE(1, 4);
            ASM_VOLATILE_CASE(2, 4);
            ASM_VOLATILE_CASE(3, 4);
            ASM_VOLATILE_CASE(4, 4);
            ASM_VOLATILE_CASE(5, 4);
            ASM_VOLATILE_CASE(6, 4);
            ASM_VOLATILE_CASE(7, 4);
            ASM_VOLATILE_CASE(8, 4);
            ASM_VOLATILE_CASE(9, 4);
            ASM_VOLATILE_CASE(10, 4);
            ASM_VOLATILE_CASE(11, 4);
            ASM_VOLATILE_CASE(12, 4);
            ASM_VOLATILE_CASE(13, 4);
            ASM_VOLATILE_CASE(14, 4);
            ASM_VOLATILE_CASE(15, 4);
            ASM_VOLATILE_CASE(16, 4);
            ASM_VOLATILE_CASE(17, 4);
            ASM_VOLATILE_CASE(18, 4);
            ASM_VOLATILE_CASE(19, 4);
            ASM_VOLATILE_CASE(20, 4);
            ASM_VOLATILE_CASE(21, 4);
            ASM_VOLATILE_CASE(22, 4);
            ASM_VOLATILE_CASE(23, 4);
            ASM_VOLATILE_CASE(24, 4);
            ASM_VOLATILE_CASE(25, 4);
            ASM_VOLATILE_CASE(26, 4);
            ASM_VOLATILE_CASE(27, 4);
            ASM_VOLATILE_CASE(28, 4);
            ASM_VOLATILE_CASE(29, 4);
            ASM_VOLATILE_CASE(30, 4);
            ASM_VOLATILE_CASE(31, 4);
         default:
            break;
         }
         break;
      case 5:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 5);
            ASM_VOLATILE_CASE(1, 5);
            ASM_VOLATILE_CASE(2, 5);
            ASM_VOLATILE_CASE(3, 5);
            ASM_VOLATILE_CASE(4, 5);
            ASM_VOLATILE_CASE(5, 5);
            ASM_VOLATILE_CASE(6, 5);
            ASM_VOLATILE_CASE(7, 5);
            ASM_VOLATILE_CASE(8, 5);
            ASM_VOLATILE_CASE(9, 5);
            ASM_VOLATILE_CASE(10, 5);
            ASM_VOLATILE_CASE(11, 5);
            ASM_VOLATILE_CASE(12, 5);
            ASM_VOLATILE_CASE(13, 5);
            ASM_VOLATILE_CASE(14, 5);
            ASM_VOLATILE_CASE(15, 5);
            ASM_VOLATILE_CASE(16, 5);
            ASM_VOLATILE_CASE(17, 5);
            ASM_VOLATILE_CASE(18, 5);
            ASM_VOLATILE_CASE(19, 5);
            ASM_VOLATILE_CASE(20, 5);
            ASM_VOLATILE_CASE(21, 5);
            ASM_VOLATILE_CASE(22, 5);
            ASM_VOLATILE_CASE(23, 5);
            ASM_VOLATILE_CASE(24, 5);
            ASM_VOLATILE_CASE(25, 5);
            ASM_VOLATILE_CASE(26, 5);
            ASM_VOLATILE_CASE(27, 5);
            ASM_VOLATILE_CASE(28, 5);
            ASM_VOLATILE_CASE(29, 5);
            ASM_VOLATILE_CASE(30, 5);
            ASM_VOLATILE_CASE(31, 5);
         default:
            break;
         }
         break;
      case 6:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 6);
            ASM_VOLATILE_CASE(1, 6);
            ASM_VOLATILE_CASE(2, 6);
            ASM_VOLATILE_CASE(3, 6);
            ASM_VOLATILE_CASE(4, 6);
            ASM_VOLATILE_CASE(5, 6);
            ASM_VOLATILE_CASE(6, 6);
            ASM_VOLATILE_CASE(7, 6);
            ASM_VOLATILE_CASE(8, 6);
            ASM_VOLATILE_CASE(9, 6);
            ASM_VOLATILE_CASE(10, 6);
            ASM_VOLATILE_CASE(11, 6);
            ASM_VOLATILE_CASE(12, 6);
            ASM_VOLATILE_CASE(13, 6);
            ASM_VOLATILE_CASE(14, 6);
            ASM_VOLATILE_CASE(15, 6);
            ASM_VOLATILE_CASE(16, 6);
            ASM_VOLATILE_CASE(17, 6);
            ASM_VOLATILE_CASE(18, 6);
            ASM_VOLATILE_CASE(19, 6);
            ASM_VOLATILE_CASE(20, 6);
            ASM_VOLATILE_CASE(21, 6);
            ASM_VOLATILE_CASE(22, 6);
            ASM_VOLATILE_CASE(23, 6);
            ASM_VOLATILE_CASE(24, 6);
            ASM_VOLATILE_CASE(25, 6);
            ASM_VOLATILE_CASE(26, 6);
            ASM_VOLATILE_CASE(27, 6);
            ASM_VOLATILE_CASE(28, 6);
            ASM_VOLATILE_CASE(29, 6);
            ASM_VOLATILE_CASE(30, 6);
            ASM_VOLATILE_CASE(31, 6);
         default:
            break;
         }
         break;
      case 7:
         
         switch (rd) {
            ASM_VOLATILE_CASE(0, 7);
            ASM_VOLATILE_CASE(1, 7);
            ASM_VOLATILE_CASE(2, 7);
            ASM_VOLATILE_CASE(3, 7);
            ASM_VOLATILE_CASE(4, 7);
            ASM_VOLATILE_CASE(5, 7);
            ASM_VOLATILE_CASE(6, 7);
            ASM_VOLATILE_CASE(7, 7);
            ASM_VOLATILE_CASE(8, 7);
            ASM_VOLATILE_CASE(9, 7);
            ASM_VOLATILE_CASE(10, 7);
            ASM_VOLATILE_CASE(11, 7);
            ASM_VOLATILE_CASE(12, 7);
            ASM_VOLATILE_CASE(13, 7);
            ASM_VOLATILE_CASE(14, 7);
            ASM_VOLATILE_CASE(15, 7);
            ASM_VOLATILE_CASE(16, 7);
            ASM_VOLATILE_CASE(17, 7);
            ASM_VOLATILE_CASE(18, 7);
            ASM_VOLATILE_CASE(19, 7);
            ASM_VOLATILE_CASE(20, 7);
            ASM_VOLATILE_CASE(21, 7);
            ASM_VOLATILE_CASE(22, 7);
            ASM_VOLATILE_CASE(23, 7);
            ASM_VOLATILE_CASE(24, 7);
            ASM_VOLATILE_CASE(25, 7);
            ASM_VOLATILE_CASE(26, 7);
            ASM_VOLATILE_CASE(27, 7);
            ASM_VOLATILE_CASE(28, 7);
            ASM_VOLATILE_CASE(29, 7);
            ASM_VOLATILE_CASE(30, 7);
            ASM_VOLATILE_CASE(31, 7);
         default:
            break;
         }
      break;

   default:
      break;
   }
#endif
   return x;
}

#undef ASM_VOLATILE_CASE

#define ASM_VOLATILE_CASE(rd, sel) \
         case rd: \
            asm volatile ("dmfc0 %0, $" #rd ", "#sel"\n\t" :"=r" (x) ); \
            break;

ULong mips64_dirtyhelper_dmfc0 ( UInt rd, UInt sel )
{
   ULong x = 0;
#if defined(VGP_mips64_linux)
   switch (sel) {
     case 0:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 0);
           ASM_VOLATILE_CASE (1, 0);
           ASM_VOLATILE_CASE (2, 0);
           ASM_VOLATILE_CASE (3, 0);
           ASM_VOLATILE_CASE (4, 0);
           ASM_VOLATILE_CASE (5, 0);
           ASM_VOLATILE_CASE (6, 0);
           ASM_VOLATILE_CASE (7, 0);
           ASM_VOLATILE_CASE (8, 0);
           ASM_VOLATILE_CASE (9, 0);
           ASM_VOLATILE_CASE (10, 0);
           ASM_VOLATILE_CASE (11, 0);
           ASM_VOLATILE_CASE (12, 0);
           ASM_VOLATILE_CASE (13, 0);
           ASM_VOLATILE_CASE (14, 0);
           ASM_VOLATILE_CASE (15, 0);
           ASM_VOLATILE_CASE (16, 0);
           ASM_VOLATILE_CASE (17, 0);
           ASM_VOLATILE_CASE (18, 0);
           ASM_VOLATILE_CASE (19, 0);
           ASM_VOLATILE_CASE (20, 0);
           ASM_VOLATILE_CASE (21, 0);
           ASM_VOLATILE_CASE (22, 0);
           ASM_VOLATILE_CASE (23, 0);
           ASM_VOLATILE_CASE (24, 0);
           ASM_VOLATILE_CASE (25, 0);
           ASM_VOLATILE_CASE (26, 0);
           ASM_VOLATILE_CASE (27, 0);
           ASM_VOLATILE_CASE (28, 0);
           ASM_VOLATILE_CASE (29, 0);
           ASM_VOLATILE_CASE (30, 0);
           ASM_VOLATILE_CASE (31, 0);
         default:
           break;
        }
        break;
     case 1:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 1);
           ASM_VOLATILE_CASE (1, 1);
           ASM_VOLATILE_CASE (2, 1);
           ASM_VOLATILE_CASE (3, 1);
           ASM_VOLATILE_CASE (4, 1);
           ASM_VOLATILE_CASE (5, 1);
           ASM_VOLATILE_CASE (6, 1);
           ASM_VOLATILE_CASE (7, 1);
           ASM_VOLATILE_CASE (8, 1);
           ASM_VOLATILE_CASE (9, 1);
           ASM_VOLATILE_CASE (10, 1);
           ASM_VOLATILE_CASE (11, 1);
           ASM_VOLATILE_CASE (12, 1);
           ASM_VOLATILE_CASE (13, 1);
           ASM_VOLATILE_CASE (14, 1);
           ASM_VOLATILE_CASE (15, 1);
           ASM_VOLATILE_CASE (16, 1);
           ASM_VOLATILE_CASE (17, 1);
           ASM_VOLATILE_CASE (18, 1);
           ASM_VOLATILE_CASE (19, 1);
           ASM_VOLATILE_CASE (20, 1);
           ASM_VOLATILE_CASE (21, 1);
           ASM_VOLATILE_CASE (22, 1);
           ASM_VOLATILE_CASE (23, 1);
           ASM_VOLATILE_CASE (24, 1);
           ASM_VOLATILE_CASE (25, 1);
           ASM_VOLATILE_CASE (26, 1);
           ASM_VOLATILE_CASE (27, 1);
           ASM_VOLATILE_CASE (28, 1);
           ASM_VOLATILE_CASE (29, 1);
           ASM_VOLATILE_CASE (30, 1);
           ASM_VOLATILE_CASE (31, 1);
        default:
           break;
        }
        break;
     case 2:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 2);
           ASM_VOLATILE_CASE (1, 2);
           ASM_VOLATILE_CASE (2, 2);
           ASM_VOLATILE_CASE (3, 1);
           ASM_VOLATILE_CASE (4, 2);
           ASM_VOLATILE_CASE (5, 2);
           ASM_VOLATILE_CASE (6, 2);
           ASM_VOLATILE_CASE (7, 2);
           ASM_VOLATILE_CASE (8, 2);
           ASM_VOLATILE_CASE (9, 2);
           ASM_VOLATILE_CASE (10, 2);
           ASM_VOLATILE_CASE (11, 2);
           ASM_VOLATILE_CASE (12, 2);
           ASM_VOLATILE_CASE (13, 2);
           ASM_VOLATILE_CASE (14, 2);
           ASM_VOLATILE_CASE (15, 2);
           ASM_VOLATILE_CASE (16, 2);
           ASM_VOLATILE_CASE (17, 2);
           ASM_VOLATILE_CASE (18, 2);
           ASM_VOLATILE_CASE (19, 2);
           ASM_VOLATILE_CASE (20, 2);
           ASM_VOLATILE_CASE (21, 2);
           ASM_VOLATILE_CASE (22, 2);
           ASM_VOLATILE_CASE (23, 2);
           ASM_VOLATILE_CASE (24, 2);
           ASM_VOLATILE_CASE (25, 2);
           ASM_VOLATILE_CASE (26, 2);
           ASM_VOLATILE_CASE (27, 2);
           ASM_VOLATILE_CASE (28, 2);
           ASM_VOLATILE_CASE (29, 2);
           ASM_VOLATILE_CASE (30, 2);
           ASM_VOLATILE_CASE (31, 2);
         default:
           break;
         }
         break;
     case 3:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 3);
           ASM_VOLATILE_CASE (1, 3);
           ASM_VOLATILE_CASE (2, 3);
           ASM_VOLATILE_CASE (3, 3);
           ASM_VOLATILE_CASE (4, 3);
           ASM_VOLATILE_CASE (5, 3);
           ASM_VOLATILE_CASE (6, 3);
           ASM_VOLATILE_CASE (7, 3);
           ASM_VOLATILE_CASE (8, 3);
           ASM_VOLATILE_CASE (9, 3);
           ASM_VOLATILE_CASE (10, 3);
           ASM_VOLATILE_CASE (11, 3);
           ASM_VOLATILE_CASE (12, 3);
           ASM_VOLATILE_CASE (13, 3);
           ASM_VOLATILE_CASE (14, 3);
           ASM_VOLATILE_CASE (15, 3);
           ASM_VOLATILE_CASE (16, 3);
           ASM_VOLATILE_CASE (17, 3);
           ASM_VOLATILE_CASE (18, 3);
           ASM_VOLATILE_CASE (19, 3);
           ASM_VOLATILE_CASE (20, 3);
           ASM_VOLATILE_CASE (21, 3);
           ASM_VOLATILE_CASE (22, 3);
           ASM_VOLATILE_CASE (23, 3);
           ASM_VOLATILE_CASE (24, 3);
           ASM_VOLATILE_CASE (25, 3);
           ASM_VOLATILE_CASE (26, 3);
           ASM_VOLATILE_CASE (27, 3);
           ASM_VOLATILE_CASE (28, 3);
           ASM_VOLATILE_CASE (29, 3);
           ASM_VOLATILE_CASE (30, 3);
           ASM_VOLATILE_CASE (31, 3);
        default:
           break;
        }
        break;
     case 4:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 4);
           ASM_VOLATILE_CASE (1, 4);
           ASM_VOLATILE_CASE (2, 4);
           ASM_VOLATILE_CASE (3, 4);
           ASM_VOLATILE_CASE (4, 4);
           ASM_VOLATILE_CASE (5, 4);
           ASM_VOLATILE_CASE (6, 4);
           ASM_VOLATILE_CASE (7, 4);
           ASM_VOLATILE_CASE (8, 4);
           ASM_VOLATILE_CASE (9, 4);
           ASM_VOLATILE_CASE (10, 4);
           ASM_VOLATILE_CASE (11, 4);
           ASM_VOLATILE_CASE (12, 4);
           ASM_VOLATILE_CASE (13, 4);
           ASM_VOLATILE_CASE (14, 4);
           ASM_VOLATILE_CASE (15, 4);
           ASM_VOLATILE_CASE (16, 4);
           ASM_VOLATILE_CASE (17, 4);
           ASM_VOLATILE_CASE (18, 4);
           ASM_VOLATILE_CASE (19, 4);
           ASM_VOLATILE_CASE (20, 4);
           ASM_VOLATILE_CASE (21, 4);
           ASM_VOLATILE_CASE (22, 4);
           ASM_VOLATILE_CASE (23, 4);
           ASM_VOLATILE_CASE (24, 4);
           ASM_VOLATILE_CASE (25, 4);
           ASM_VOLATILE_CASE (26, 4);
           ASM_VOLATILE_CASE (27, 4);
           ASM_VOLATILE_CASE (28, 4);
           ASM_VOLATILE_CASE (29, 4);
           ASM_VOLATILE_CASE (30, 4);
           ASM_VOLATILE_CASE (31, 4);
           default:
              break;
           }
        break;
     case 5:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 5);
           ASM_VOLATILE_CASE (1, 5);
           ASM_VOLATILE_CASE (2, 5);
           ASM_VOLATILE_CASE (3, 5);
           ASM_VOLATILE_CASE (4, 5);
           ASM_VOLATILE_CASE (5, 5);
           ASM_VOLATILE_CASE (6, 5);
           ASM_VOLATILE_CASE (7, 5);
           ASM_VOLATILE_CASE (8, 5);
           ASM_VOLATILE_CASE (9, 5);
           ASM_VOLATILE_CASE (10, 5);
           ASM_VOLATILE_CASE (11, 5);
           ASM_VOLATILE_CASE (12, 5);
           ASM_VOLATILE_CASE (13, 5);
           ASM_VOLATILE_CASE (14, 5);
           ASM_VOLATILE_CASE (15, 5);
           ASM_VOLATILE_CASE (16, 5);
           ASM_VOLATILE_CASE (17, 5);
           ASM_VOLATILE_CASE (18, 5);
           ASM_VOLATILE_CASE (19, 5);
           ASM_VOLATILE_CASE (20, 5);
           ASM_VOLATILE_CASE (21, 5);
           ASM_VOLATILE_CASE (22, 5);
           ASM_VOLATILE_CASE (23, 5);
           ASM_VOLATILE_CASE (24, 5);
           ASM_VOLATILE_CASE (25, 5);
           ASM_VOLATILE_CASE (26, 5);
           ASM_VOLATILE_CASE (27, 5);
           ASM_VOLATILE_CASE (28, 5);
           ASM_VOLATILE_CASE (29, 5);
           ASM_VOLATILE_CASE (30, 5);
           ASM_VOLATILE_CASE (31, 5);
           default:
              break;
        }
        break;
     case 6:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 6);
           ASM_VOLATILE_CASE (1, 6);
           ASM_VOLATILE_CASE (2, 6);
           ASM_VOLATILE_CASE (3, 6);
           ASM_VOLATILE_CASE (4, 6);
           ASM_VOLATILE_CASE (5, 6);
           ASM_VOLATILE_CASE (6, 6);
           ASM_VOLATILE_CASE (7, 6);
           ASM_VOLATILE_CASE (8, 6);
           ASM_VOLATILE_CASE (9, 6);
           ASM_VOLATILE_CASE (10, 6);
           ASM_VOLATILE_CASE (11, 6);
           ASM_VOLATILE_CASE (12, 6);
           ASM_VOLATILE_CASE (13, 6);
           ASM_VOLATILE_CASE (14, 6);
           ASM_VOLATILE_CASE (15, 6);
           ASM_VOLATILE_CASE (16, 6);
           ASM_VOLATILE_CASE (17, 6);
           ASM_VOLATILE_CASE (18, 6);
           ASM_VOLATILE_CASE (19, 6);
           ASM_VOLATILE_CASE (20, 6);
           ASM_VOLATILE_CASE (21, 6);
           ASM_VOLATILE_CASE (22, 6);
           ASM_VOLATILE_CASE (23, 6);
           ASM_VOLATILE_CASE (24, 6);
           ASM_VOLATILE_CASE (25, 6);
           ASM_VOLATILE_CASE (26, 6);
           ASM_VOLATILE_CASE (27, 6);
           ASM_VOLATILE_CASE (28, 6);
           ASM_VOLATILE_CASE (29, 6);
           ASM_VOLATILE_CASE (30, 6);
           ASM_VOLATILE_CASE (31, 6);
        default:
           break;
        }
        break;
     case 7:
        
        switch (rd) {
           ASM_VOLATILE_CASE (0, 7);
           ASM_VOLATILE_CASE (1, 7);
           ASM_VOLATILE_CASE (2, 7);
           ASM_VOLATILE_CASE (3, 7);
           ASM_VOLATILE_CASE (4, 7);
           ASM_VOLATILE_CASE (5, 7);
           ASM_VOLATILE_CASE (6, 7);
           ASM_VOLATILE_CASE (7, 7);
           ASM_VOLATILE_CASE (8, 7);
           ASM_VOLATILE_CASE (9, 7);
           ASM_VOLATILE_CASE (10, 7);
           ASM_VOLATILE_CASE (11, 7);
           ASM_VOLATILE_CASE (12, 7);
           ASM_VOLATILE_CASE (13, 7);
           ASM_VOLATILE_CASE (14, 7);
           ASM_VOLATILE_CASE (15, 7);
           ASM_VOLATILE_CASE (16, 7);
           ASM_VOLATILE_CASE (17, 7);
           ASM_VOLATILE_CASE (18, 7);
           ASM_VOLATILE_CASE (19, 7);
           ASM_VOLATILE_CASE (20, 7);
           ASM_VOLATILE_CASE (21, 7);
           ASM_VOLATILE_CASE (22, 7);
           ASM_VOLATILE_CASE (23, 7);
           ASM_VOLATILE_CASE (24, 7);
           ASM_VOLATILE_CASE (25, 7);
           ASM_VOLATILE_CASE (26, 7);
           ASM_VOLATILE_CASE (27, 7);
           ASM_VOLATILE_CASE (28, 7);
           ASM_VOLATILE_CASE (29, 7);
           ASM_VOLATILE_CASE (30, 7);
           ASM_VOLATILE_CASE (31, 7);
         default:
           break;
         }
       break;

     default:
       break;
     }
#endif
   return x;
}

#if defined(__mips__) && ((defined(__mips_isa_rev) && __mips_isa_rev >= 2))
UInt mips32_dirtyhelper_rdhwr ( UInt rt, UInt rd )
{
   UInt x = 0;
   switch (rd) {
      case 1:  
         __asm__ __volatile__("rdhwr %0, $1\n\t" : "=r" (x) );
         break;

      default:
         vassert(0);
         break;
   }
   return x;
}

ULong mips64_dirtyhelper_rdhwr ( ULong rt, ULong rd )
{
   ULong x = 0;
   switch (rd) {
      case 1:  
         __asm__ __volatile__("rdhwr %0, $1\n\t" : "=r" (x) );
         break;

      default:
         vassert(0);
         break;
   }
   return x;
}
#endif

#define ASM_VOLATILE_UNARY32(inst)                                  \
   __asm__ volatile("cfc1  $t0,  $31"   "\n\t"                      \
                    "ctc1  %2,   $31"   "\n\t"                      \
                    "mtc1  %1,   $f20"  "\n\t"                      \
                    #inst" $f20, $f20"  "\n\t"                      \
                    "cfc1  %0,   $31"   "\n\t"                      \
                    "ctc1  $t0,  $31"   "\n\t"                      \
                    : "=r" (ret)                                    \
                    : "r" (loFsVal), "r" (fcsr)                     \
                    : "t0", "$f20"                                  \
                   );

#define ASM_VOLATILE_UNARY32_DOUBLE(inst)                           \
   __asm__ volatile("cfc1  $t0,  $31"   "\n\t"                      \
                    "ctc1  %3,   $31"   "\n\t"                      \
                    "mtc1  %1,   $f20"  "\n\t"                      \
                    "mtc1  %2,   $f21"  "\n\t"                      \
                    #inst" $f20, $f20"  "\n\t"                      \
                    "cfc1  %0,   $31"   "\n\t"                      \
                    "ctc1  $t0,  $31"   "\n\t"                      \
                    : "=r" (ret)                                    \
                    : "r" (loFsVal), "r" (hiFsVal), "r" (fcsr)      \
                    : "t0", "$f20", "$f21"                          \
                   );

#define ASM_VOLATILE_UNARY64(inst)                                  \
   __asm__ volatile("cfc1  $t0,  $31"    "\n\t"                     \
                    "ctc1  %2,   $31"    "\n\t"                     \
                    "ldc1  $f24, 0(%1)"  "\n\t"                     \
                    #inst" $f24, $f24"   "\n\t"                     \
                    "cfc1  %0,   $31"    "\n\t"                     \
                    "ctc1  $t0,  $31"    "\n\t"                     \
                    : "=r" (ret)                                    \
                    : "r" (&(addr[fs])), "r" (fcsr)                 \
                    : "t0", "$f24"                                  \
                   );

#define ASM_VOLATILE_BINARY32(inst)                                 \
   __asm__ volatile("cfc1  $t0,  $31"         "\n\t"                \
                    "ctc1  %3,   $31"         "\n\t"                \
                    "mtc1  %1,   $f20"        "\n\t"                \
                    "mtc1  %2,   $f22"        "\n\t"                \
                    #inst" $f20, $f20, $f22"  "\n\t"                \
                    "cfc1  %0,   $31"         "\n\t"                \
                    "ctc1  $t0,  $31"         "\n\t"                \
                    : "=r" (ret)                                    \
                    : "r" (loFsVal), "r" (loFtVal), "r" (fcsr)      \
                    : "t0", "$f20", "$f22"                          \
                   );

#define ASM_VOLATILE_BINARY32_DOUBLE(inst)                          \
   __asm__ volatile("cfc1  $t0,  $31"         "\n\t"                \
                    "ctc1  %5,   $31"         "\n\t"                \
                    "mtc1  %1,   $f20"        "\n\t"                \
                    "mtc1  %2,   $f21"        "\n\t"                \
                    "mtc1  %3,   $f22"        "\n\t"                \
                    "mtc1  %4,   $f23"        "\n\t"                \
                    #inst" $f20, $f20, $f22"  "\n\t"                \
                    "cfc1  %0,   $31"         "\n\t"                \
                    "ctc1  $t0,  $31"         "\n\t"                \
                    : "=r" (ret)                                    \
                    : "r" (loFsVal), "r" (hiFsVal), "r" (loFtVal),  \
                      "r" (hiFtVal), "r" (fcsr)                     \
                    : "t0", "$f20", "$f21", "$f22", "$f23"          \
                   );

#define ASM_VOLATILE_BINARY64(inst)                                     \
   __asm__ volatile("cfc1  $t0,  $31"         "\n\t"                    \
                    "ctc1  %3,   $31"         "\n\t"                    \
                    "ldc1  $f24, 0(%1)"       "\n\t"                    \
                    "ldc1  $f26, 0(%2)"       "\n\t"                    \
                    #inst" $f24, $f24, $f26"  "\n\t"                    \
                    "cfc1  %0,   $31"         "\n\t"                    \
                    "ctc1  $t0,  $31"         "\n\t"                    \
                    : "=r" (ret)                                        \
                    : "r" (&(addr[fs])), "r" (&(addr[ft])), "r" (fcsr)  \
                    : "t0", "$f24", "$f26"                              \
                   );

extern UInt mips_dirtyhelper_calculate_FCSR_fp32 ( void* gs, UInt fs, UInt ft,
                                                   flt_op inst )
{
   UInt ret = 0;
#if defined(__mips__)
   VexGuestMIPS32State* guest_state = (VexGuestMIPS32State*)gs;
   UInt loFsVal, hiFsVal, loFtVal, hiFtVal;
#if defined (_MIPSEL)
   ULong *addr = (ULong *)&guest_state->guest_f0;
   loFsVal     = (UInt)addr[fs];
   hiFsVal     = (UInt)addr[fs+1];
   loFtVal     = (UInt)addr[ft];
   hiFtVal     = (UInt)addr[ft+1];
#elif defined (_MIPSEB)
   UInt *addr = (UInt *)&guest_state->guest_f0;
   loFsVal    = (UInt)addr[fs*2];
   hiFsVal    = (UInt)addr[fs*2+2];
   loFtVal    = (UInt)addr[ft*2];
   hiFtVal    = (UInt)addr[ft*2+2];
#endif
   UInt fcsr     = guest_state->guest_FCSR;
   switch (inst) {
      case ROUNDWD:
         ASM_VOLATILE_UNARY32_DOUBLE(round.w.d)
         break;
      case FLOORWS:
         ASM_VOLATILE_UNARY32(floor.w.s)
         break;
      case FLOORWD:
         ASM_VOLATILE_UNARY32_DOUBLE(floor.w.d)
         break;
      case TRUNCWS:
         ASM_VOLATILE_UNARY32(trunc.w.s)
         break;
      case TRUNCWD:
         ASM_VOLATILE_UNARY32_DOUBLE(trunc.w.d)
         break;
      case CEILWS:
         ASM_VOLATILE_UNARY32(ceil.w.s)
         break;
      case CEILWD:
         ASM_VOLATILE_UNARY32_DOUBLE(ceil.w.d)
         break;
      case CVTDS:
         ASM_VOLATILE_UNARY32(cvt.d.s)
         break;
      case CVTDW:
         ASM_VOLATILE_UNARY32(cvt.d.w)
         break;
      case CVTSW:
         ASM_VOLATILE_UNARY32(cvt.s.w)
         break;
      case CVTSD:
         ASM_VOLATILE_UNARY32_DOUBLE(cvt.s.d)
         break;
      case CVTWS:
         ASM_VOLATILE_UNARY32(cvt.w.s)
         break;
      case CVTWD:
         ASM_VOLATILE_UNARY32_DOUBLE(cvt.w.d)
         break;
      case ROUNDWS:
         ASM_VOLATILE_UNARY32(round.w.s)
         break;
#if ((__mips == 32) && defined(__mips_isa_rev) && (__mips_isa_rev >= 2)) \
    || (__mips == 64)
      case CEILLS:
         ASM_VOLATILE_UNARY32(ceil.l.s)
         break;
      case CEILLD:
         ASM_VOLATILE_UNARY32_DOUBLE(ceil.l.d)
         break;
      case CVTDL:
         ASM_VOLATILE_UNARY32_DOUBLE(cvt.d.l)
         break;
      case CVTLS:
         ASM_VOLATILE_UNARY32(cvt.l.s)
         break;
      case CVTLD:
         ASM_VOLATILE_UNARY32_DOUBLE(cvt.l.d)
         break;
      case CVTSL:
         ASM_VOLATILE_UNARY32_DOUBLE(cvt.s.l)
         break;
      case FLOORLS:
         ASM_VOLATILE_UNARY32(floor.l.s)
         break;
      case FLOORLD:
         ASM_VOLATILE_UNARY32_DOUBLE(floor.l.d)
         break;
      case ROUNDLS:
         ASM_VOLATILE_UNARY32(round.l.s)
         break;
      case ROUNDLD:
         ASM_VOLATILE_UNARY32_DOUBLE(round.l.d)
         break;
      case TRUNCLS:
         ASM_VOLATILE_UNARY32(trunc.l.s)
         break;
      case TRUNCLD:
         ASM_VOLATILE_UNARY32_DOUBLE(trunc.l.d)
         break;
#endif
      case ADDS:
          ASM_VOLATILE_BINARY32(add.s)
          break;
      case ADDD:
          ASM_VOLATILE_BINARY32_DOUBLE(add.d)
          break;
      case SUBS:
          ASM_VOLATILE_BINARY32(sub.s)
          break;
      case SUBD:
          ASM_VOLATILE_BINARY32_DOUBLE(sub.d)
          break;
      case DIVS:
          ASM_VOLATILE_BINARY32(div.s)
          break;
      default:
         vassert(0);
         break;
   }
#endif
   return ret;
}

extern UInt mips_dirtyhelper_calculate_FCSR_fp64 ( void* gs, UInt fs, UInt ft,
                                                   flt_op inst )
{
   UInt ret = 0;
#if defined(__mips__)
#if defined(VGA_mips32)
   VexGuestMIPS32State* guest_state = (VexGuestMIPS32State*)gs;
#else
   VexGuestMIPS64State* guest_state = (VexGuestMIPS64State*)gs;
#endif
   ULong *addr = (ULong *)&guest_state->guest_f0;
   UInt fcsr   = guest_state->guest_FCSR;
   switch (inst) {
      case ROUNDWD:
         ASM_VOLATILE_UNARY64(round.w.d)
         break;
      case FLOORWS:
         ASM_VOLATILE_UNARY64(floor.w.s)
         break;
      case FLOORWD:
         ASM_VOLATILE_UNARY64(floor.w.d)
         break;
      case TRUNCWS:
         ASM_VOLATILE_UNARY64(trunc.w.s)
         break;
      case TRUNCWD:
         ASM_VOLATILE_UNARY64(trunc.w.d)
         break;
      case CEILWS:
         ASM_VOLATILE_UNARY64(ceil.w.s)
         break;
      case CEILWD:
         ASM_VOLATILE_UNARY64(ceil.w.d)
         break;
      case CVTDS:
         ASM_VOLATILE_UNARY64(cvt.d.s)
         break;
      case CVTDW:
         ASM_VOLATILE_UNARY64(cvt.d.w)
         break;
      case CVTSW:
         ASM_VOLATILE_UNARY64(cvt.s.w)
         break;
      case CVTSD:
         ASM_VOLATILE_UNARY64(cvt.s.d)
         break;
      case CVTWS:
         ASM_VOLATILE_UNARY64(cvt.w.s)
         break;
      case CVTWD:
         ASM_VOLATILE_UNARY64(cvt.w.d)
         break;
      case ROUNDWS:
         ASM_VOLATILE_UNARY64(round.w.s)
         break;
#if ((__mips == 32) && defined(__mips_isa_rev) && (__mips_isa_rev >= 2)) \
    || (__mips == 64)
      case CEILLS:
         ASM_VOLATILE_UNARY64(ceil.l.s)
         break;
      case CEILLD:
         ASM_VOLATILE_UNARY64(ceil.l.d)
         break;
      case CVTDL:
         ASM_VOLATILE_UNARY64(cvt.d.l)
         break;
      case CVTLS:
         ASM_VOLATILE_UNARY64(cvt.l.s)
         break;
      case CVTLD:
         ASM_VOLATILE_UNARY64(cvt.l.d)
         break;
      case CVTSL:
         ASM_VOLATILE_UNARY64(cvt.s.l)
         break;
      case FLOORLS:
         ASM_VOLATILE_UNARY64(floor.l.s)
         break;
      case FLOORLD:
         ASM_VOLATILE_UNARY64(floor.l.d)
         break;
      case ROUNDLS:
         ASM_VOLATILE_UNARY64(round.l.s)
         break;
      case ROUNDLD:
         ASM_VOLATILE_UNARY64(round.l.d)
         break;
      case TRUNCLS:
         ASM_VOLATILE_UNARY64(trunc.l.s)
         break;
      case TRUNCLD:
         ASM_VOLATILE_UNARY64(trunc.l.d)
         break;
#endif
      case ADDS:
          ASM_VOLATILE_BINARY64(add.s)
          break;
      case ADDD:
          ASM_VOLATILE_BINARY64(add.d)
          break;
      case SUBS:
          ASM_VOLATILE_BINARY64(sub.s)
          break;
      case SUBD:
          ASM_VOLATILE_BINARY64(sub.d)
          break;
      case DIVS:
          ASM_VOLATILE_BINARY64(div.s)
          break;
      default:
         vassert(0);
         break;
   }
#endif
   return ret;
}

