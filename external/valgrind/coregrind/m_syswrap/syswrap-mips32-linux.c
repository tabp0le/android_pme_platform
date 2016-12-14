

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

#if defined(VGP_mips32_linux)
#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_sigframe.h"     
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"
#include "pub_core_transtab.h"      
#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"   
#include "priv_syswrap-linux.h"     
#include "priv_syswrap-main.h"

#include "pub_core_debuginfo.h"     
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"   
#include "pub_core_errormgr.h"
#include "pub_core_gdbserver.h"     
#include "pub_core_libcfile.h"
#include "pub_core_machine.h"       
#include "pub_core_mallocfree.h"
#include "pub_core_stacktrace.h"    
#include "pub_core_ume.h"

#include "priv_syswrap-generic.h"

#include "config.h"

#include <errno.h>

 
 

__attribute__ ((noreturn)) 
void ML_ (call_on_new_stack_0_1) (Addr stack, Addr retaddr, 
                                  void (*f) (Word), Word arg1);
asm (
".text\n" 
".globl vgModuleLocal_call_on_new_stack_0_1\n" 
"vgModuleLocal_call_on_new_stack_0_1:\n" 
"   move	$29, $4\n\t"	
"   move	$25, $6\n\t"	
"   move 	$4, $7\n\t"	
"   li 		$2, 0\n\t"	
"   li 		$3, 0\n\t" 
"   li 		$5, 0\n\t" 
"   li 		$6, 0\n\t" 
"   li 		$7, 0\n\t" 

"   li 		$12, 0\n\t" 
"   li 		$13, 0\n\t" 
"   li 		$14, 0\n\t" 
"   li 		$15, 0\n\t" 
"   li 		$16, 0\n\t" 
"   li 		$17, 0\n\t" 
"   li 		$18, 0\n\t" 
"   li 		$19, 0\n\t" 
"   li 		$20, 0\n\t" 
"   li 		$21, 0\n\t" 
"   li 		$22, 0\n\t" 
"   li 		$23, 0\n\t" 
"   li 		$24, 0\n\t" 
"   jr 		$25\n\t"	
"   break	0x7\n"	
".previous\n" 
);

 
#define __NR_CLONE        VG_STRINGIFY(__NR_clone)
#define __NR_EXIT         VG_STRINGIFY(__NR_exit)

UInt do_syscall_clone_mips_linux (Word (*fn) (void *), 
                                   void *stack,         
                                   Int flags,           
                                   void *arg,           
                                   Int * child_tid,     
                                   Int * parent_tid,    
                                   Int tls);          
asm (
".text\n" 
"   .globl   do_syscall_clone_mips_linux\n" 
"   do_syscall_clone_mips_linux:\n"
"   subu    $29,$29,32\n\t"
"   sw $31, 0($29)\n\t"
"   sw $2, 4($29)\n\t"
"   sw $3, 8($29)\n\t"
"   sw $30, 12($29)\n\t"
"   sw $28, 28($29)\n\t"
    
    
"   subu $5, $5, 32\n\t" 
"   sw $4, 0($5)\n\t" 
"   sw $7, 4($5)\n\t" 
"   sw $6, 8($5)\n\t"
    

"   move $4, $a2\n\t" 
"   lw $6,  52($29)\n\t" 
"   lw $7,  48($29)\n\t" 
"   sw $7,  16($29)\n\t" 
"   lw $7,  56($29)\n\t"   
    

"   li $2, " __NR_CLONE "\n\t" 
"   syscall\n\t"
"   nop\n\t"

"   bnez    $7, .Lerror\n\t" 
"   nop\n\t" 
"   beqz    $2, .Lstart\n\t" 
"   nop\n\t" 

"   lw      $31, 0($sp)\n\t" 
"   nop\n\t" 
"   lw      $30, 12($sp)\n\t" 
"   nop\n\t" 
"   addu    $29,$29,32\n\t"   
"   nop\n\t" 
"   jr      $31\n\t" 
"   nop\n\t" 

".Lerror:\n\t" 
"   li      $31, 5\n\t" 
"   jr      $31\n\t" 
"   nop\n\t" 

".Lstart:\n\t" 
"   lw      $4,  4($29)\n\t" 
"   nop\n\t" 
"   lw      $25, 0($29)\n\t" 
"   nop\n\t" 
"   jalr    $25\n\t" 
"   nop\n\t" 

"   move $4, $2\n\t"   
"   li $2, " __NR_EXIT "\n\t"   
"   syscall\n\t" 
"   nop\n\t" 
"   .previous\n" 
);

#undef __NR_CLONE
#undef __NR_EXIT


static void setup_child (ThreadArchState *, ThreadArchState *);
static SysRes sys_set_tls (ThreadId tid, Addr tlsptr);
static SysRes mips_PRE_sys_mmap (ThreadId tid,
                                 UWord arg1, UWord arg2, UWord arg3,
                                 UWord arg4, UWord arg5, Off64T arg6);
 

static SysRes do_clone (ThreadId ptid, 
                        UInt flags, Addr sp, 
                        Int * parent_tidptr,
                        Int * child_tidptr, 
                        Addr child_tls) 
{
   const Bool debug = False;
   ThreadId ctid = VG_ (alloc_ThreadState) ();
   ThreadState * ptst = VG_ (get_ThreadState) (ptid);
   ThreadState * ctst = VG_ (get_ThreadState) (ctid);
   UInt ret = 0;
   UWord * stack;
   SysRes res;
   vki_sigset_t blockall, savedmask;

   VG_ (sigfillset) (&blockall);
   vg_assert (VG_ (is_running_thread) (ptid));
   vg_assert (VG_ (is_valid_tid) (ctid));
   stack = (UWord *) ML_ (allocstack) (ctid);
   if (stack == NULL) {
      res = VG_ (mk_SysRes_Error) (VKI_ENOMEM);
      goto out;
   }
   setup_child (&ctst->arch, &ptst->arch);

    
   ctst->arch.vex.guest_r2 = 0;
   ctst->arch.vex.guest_r7 = 0;
   if (sp != 0)
      ctst->arch.vex.guest_r29 = sp;

   ctst->os_state.parent = ptid;
   ctst->sig_mask = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

 

   ctst->os_state.threadgroup = ptst->os_state.threadgroup;

   ML_(guess_and_register_stack) (sp, ctst);

   VG_TRACK (pre_thread_ll_create, ptid, ctid);
   if (flags & VKI_CLONE_SETTLS) {
      if (debug)
        VG_(printf)("clone child has SETTLS: tls at %#lx\n", child_tls);
      ctst->arch.vex.guest_r27 = child_tls;
      res = sys_set_tls(ctid, child_tls);
      if (sr_isError(res))
         goto out;
      ctst->arch.vex.guest_r27 = child_tls;
  }

   flags &= ~VKI_CLONE_SETTLS;
   VG_ (sigprocmask) (VKI_SIG_SETMASK, &blockall, &savedmask);
    
   ret = do_syscall_clone_mips_linux (ML_ (start_thread_NORETURN),
                                    stack, flags, &VG_ (threads)[ctid], 
                                    child_tidptr, parent_tidptr,
                                    0 );

 
   if (debug)
      VG_(printf)("ret: 0x%x\n", ret);

   res = VG_ (mk_SysRes_mips32_linux) ( ret, 0,  0);

   VG_ (sigprocmask) (VKI_SIG_SETMASK, &savedmask, NULL);

   out:
   if (sr_isError (res)) {
      VG_(cleanup_thread) (&ctst->arch);
      ctst->status = VgTs_Empty;
      VG_TRACK (pre_thread_ll_exit, ctid);
   }
   ptst->arch.vex.guest_r2 = 0;

   return res;
}

 

void
VG_ (cleanup_thread) (ThreadArchState * arch) { } 

void
setup_child (  ThreadArchState * child,
               ThreadArchState * parent) 
{
    
   child->vex = parent->vex;
   child->vex_shadow1 = parent->vex_shadow1;
   child->vex_shadow2 = parent->vex_shadow2;
}

SysRes sys_set_tls ( ThreadId tid, Addr tlsptr )
{
   VG_(threads)[tid].arch.vex.guest_ULR = tlsptr;
   return VG_(mk_SysRes_Success)( 0 );
}

static void notify_core_of_mmap(Addr a, SizeT len, UInt prot,
                                UInt flags, Int fd, Off64T offset)
{
   Bool d;

   
   vg_assert(VG_IS_PAGE_ALIGNED(a));
   
   len = VG_PGROUNDUP(len);

   d = VG_(am_notify_client_mmap)( a, len, prot, flags, fd, offset );

   if (d)
      VG_(discard_translations)( a, (ULong)len,
                                 "notify_core_of_mmap" );
}

static void notify_tool_of_mmap(Addr a, SizeT len, UInt prot, ULong di_handle)
{
   Bool rr, ww, xx;

   
   vg_assert(VG_IS_PAGE_ALIGNED(a));
   
   len = VG_PGROUNDUP(len);

   rr = toBool(prot & VKI_PROT_READ);
   ww = toBool(prot & VKI_PROT_WRITE);
   xx = toBool(prot & VKI_PROT_EXEC);

   VG_TRACK( new_mem_mmap, a, len, rr, ww, xx, di_handle );
}

static SysRes mips_PRE_sys_mmap(ThreadId tid,
                                UWord arg1, UWord arg2, UWord arg3,
                                UWord arg4, UWord arg5, Off64T arg6)
{
   Addr       advised;
   SysRes     sres;
   MapRequest mreq;
   Bool       mreq_ok;

   if (arg2 == 0) {
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   if (!VG_IS_PAGE_ALIGNED(arg1)) {
      
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   if (!VG_IS_PAGE_ALIGNED(arg6)) {
      
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   mreq.start = arg1;
   mreq.len   = arg2;
   if (arg4 & VKI_MAP_FIXED) {
      mreq.rkind = MFixed;
   } else
   if (arg1 != 0) {
      mreq.rkind = MHint;
   } else {
      mreq.rkind = MAny;
   }

   if ((VKI_SHMLBA > VKI_PAGE_SIZE) && (VKI_MAP_SHARED & arg4)
       && !(VKI_MAP_FIXED & arg4))
      mreq.len = arg2 + VKI_SHMLBA - VKI_PAGE_SIZE;

   
   advised = VG_(am_get_advisory)( &mreq, True, &mreq_ok );

   if ((VKI_SHMLBA > VKI_PAGE_SIZE) && (VKI_MAP_SHARED & arg4)
       && !(VKI_MAP_FIXED & arg4))
      advised = VG_ROUNDUP(advised, VKI_SHMLBA);

   if (!mreq_ok) {
      
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   sres = VG_(am_do_mmap_NO_NOTIFY)(advised, arg2, arg3,
                                    arg4 | VKI_MAP_FIXED,
                                    arg5, arg6);

   if (mreq.rkind == MHint && sr_isError(sres)) {
      mreq.start = 0;
      mreq.len   = arg2;
      mreq.rkind = MAny;
      advised = VG_(am_get_advisory)( &mreq, True, &mreq_ok );
      if (!mreq_ok) {
         
         return VG_(mk_SysRes_Error)( VKI_EINVAL );
      }
      
      sres = VG_(am_do_mmap_NO_NOTIFY)(advised, arg2, arg3,
                                       arg4 | VKI_MAP_FIXED,
                                       arg5, arg6);
   }

   if (!sr_isError(sres)) {
      ULong di_handle;
      
      notify_core_of_mmap(
         (Addr)sr_Res(sres), 
         arg2, 
         arg3, 
         arg4, 
         arg5, 
         arg6  
      );
      
      di_handle = VG_(di_notify_mmap)( (Addr)sr_Res(sres), 
                                       False, (Int)arg5 );
      
      notify_tool_of_mmap(
         (Addr)sr_Res(sres), 
         arg2, 
         arg3, 
         di_handle 
      );
   }

   
   if (!sr_isError(sres) && (arg4 & VKI_MAP_FIXED))
      vg_assert(sr_Res(sres) == arg1);

   return sres;
}
 
#define PRE(name)       DEFN_PRE_TEMPLATE(mips_linux, name)
#define POST(name)      DEFN_POST_TEMPLATE(mips_linux, name)

 
DECL_TEMPLATE (mips_linux, sys_mmap);
DECL_TEMPLATE (mips_linux, sys_mmap2);
DECL_TEMPLATE (mips_linux, sys_stat64);
DECL_TEMPLATE (mips_linux, sys_lstat64);
DECL_TEMPLATE (mips_linux, sys_fstatat64);
DECL_TEMPLATE (mips_linux, sys_fstat64);
DECL_TEMPLATE (mips_linux, sys_clone);
DECL_TEMPLATE (mips_linux, sys_sigreturn);
DECL_TEMPLATE (mips_linux, sys_rt_sigreturn);
DECL_TEMPLATE (mips_linux, sys_cacheflush);
DECL_TEMPLATE (mips_linux, sys_set_thread_area);
DECL_TEMPLATE (mips_linux, sys_pipe);

PRE(sys_mmap2) 
{
  SysRes r;
  PRINT("sys_mmap2 ( %#lx, %llu, %ld, %ld, %ld, %ld )", ARG1, (ULong) ARG2,
                                                        ARG3, ARG4, ARG5, ARG6);
  PRE_REG_READ6(long, "mmap2", unsigned long, start, unsigned long, length,
                unsigned long, prot, unsigned long, flags,
                unsigned long, fd, unsigned long, offset);
  r = mips_PRE_sys_mmap(tid, ARG1, ARG2, ARG3, ARG4, ARG5,
                        VKI_PAGE_SIZE * (Off64T) ARG6);
  SET_STATUS_from_SysRes(r);
} 

PRE(sys_mmap) 
{
  SysRes r;
  PRINT("sys_mmap ( %#lx, %llu, %lu, %lu, %lu, %ld )", ARG1, (ULong) ARG2,
                                                       ARG3, ARG4, ARG5, ARG6);
  PRE_REG_READ6(long, "mmap", unsigned long, start, vki_size_t, length,
                int, prot, int, flags, int, fd, unsigned long, offset);
  r = mips_PRE_sys_mmap(tid, ARG1, ARG2, ARG3, ARG4, ARG5, (Off64T) ARG6);
  SET_STATUS_from_SysRes(r);
} 

 
PRE (sys_lstat64) 
{
  PRINT ("sys_lstat64 ( %#lx(%s), %#lx )", ARG1, (char *) ARG1, ARG2);
  PRE_REG_READ2 (long, "lstat64", char *, file_name, struct stat64 *, buf);
  PRE_MEM_RASCIIZ ("lstat64(file_name)", ARG1);
  PRE_MEM_WRITE ("lstat64(buf)", ARG2, sizeof (struct vki_stat64));
} 

POST (sys_lstat64) 
{
  vg_assert (SUCCESS);
  if (RES == 0)
    {
      POST_MEM_WRITE (ARG2, sizeof (struct vki_stat64));
    }
} 

PRE (sys_stat64) 
{
  PRINT ("sys_stat64 ( %#lx(%s), %#lx )", ARG1, (char *) ARG1, ARG2);
  PRE_REG_READ2 (long, "stat64", char *, file_name, struct stat64 *, buf);
  PRE_MEM_RASCIIZ ("stat64(file_name)", ARG1);
  PRE_MEM_WRITE ("stat64(buf)", ARG2, sizeof (struct vki_stat64));
}

POST (sys_stat64)
{
  POST_MEM_WRITE (ARG2, sizeof (struct vki_stat64));
}

PRE (sys_fstatat64)
{
  PRINT ("sys_fstatat64 ( %ld, %#lx(%s), %#lx )", ARG1, ARG2, (char *) ARG2,
                                                  ARG3);
  PRE_REG_READ3 (long, "fstatat64", int, dfd, char *, file_name,
                 struct stat64 *, buf);
  PRE_MEM_RASCIIZ ("fstatat64(file_name)", ARG2);
  PRE_MEM_WRITE ("fstatat64(buf)", ARG3, sizeof (struct vki_stat64));
}

POST (sys_fstatat64)
{
  POST_MEM_WRITE (ARG3, sizeof (struct vki_stat64));
}

PRE (sys_fstat64)
{
  PRINT ("sys_fstat64 ( %ld, %#lx )", ARG1, ARG2);
  PRE_REG_READ2 (long, "fstat64", unsigned long, fd, struct stat64 *, buf);
  PRE_MEM_WRITE ("fstat64(buf)", ARG2, sizeof (struct vki_stat64));
}

POST (sys_fstat64)
{
  POST_MEM_WRITE (ARG2, sizeof (struct vki_stat64));
} 

PRE (sys_clone) 
  {
    Bool badarg = False;
    UInt cloneflags;
    PRINT ("sys_clone ( %lx, %#lx, %#lx, %#lx, %#lx )", ARG1, ARG2, ARG3,
                                                        ARG4, ARG5);
    PRE_REG_READ2 (int, "clone", unsigned long, flags,  void *, child_stack);
    if (ARG1 & VKI_CLONE_PARENT_SETTID)
      {
        if (VG_ (tdict).track_pre_reg_read)
          {
            PRA3 ("clone", int *, parent_tidptr);
          }
        PRE_MEM_WRITE ("clone(parent_tidptr)", ARG3, sizeof (Int));
        if (!VG_ (am_is_valid_for_client)(ARG3, sizeof (Int), VKI_PROT_WRITE))
        {
          badarg = True;
        }
      }
    if (ARG1 & (VKI_CLONE_CHILD_SETTID | VKI_CLONE_CHILD_CLEARTID))
      {
        if (VG_ (tdict).track_pre_reg_read)
          {
            PRA5 ("clone", int *, child_tidptr);
          }
        PRE_MEM_WRITE ("clone(child_tidptr)", ARG5, sizeof (Int));
        if (!VG_ (am_is_valid_for_client)(ARG5, sizeof (Int), VKI_PROT_WRITE))
          {
            badarg = True;
          }
      }
    if (badarg)
      {
        SET_STATUS_Failure (VKI_EFAULT);
        return;
      }
    cloneflags = ARG1;
    if (!ML_ (client_signal_OK) (ARG1 & VKI_CSIGNAL))
      {
        SET_STATUS_Failure (VKI_EINVAL);
        return;
      }
     
    switch (cloneflags & (VKI_CLONE_VM | VKI_CLONE_FS
           |VKI_CLONE_FILES | VKI_CLONE_VFORK))
      {
        case VKI_CLONE_VM | VKI_CLONE_FS | VKI_CLONE_FILES:
         
        PRINT ("sys_clone1 ( %#lx, %#lx, %#lx, %#lx, %#lx )",
               ARG1, ARG2, ARG3, ARG4, ARG5);
        SET_STATUS_from_SysRes (do_clone (tid, 
                                          ARG1,  
                                          (Addr) ARG2,  
                                          (Int *) ARG3,  
                                          (Int *) ARG5,  
                                          (Addr) ARG4));	

        break;
        case VKI_CLONE_VFORK | VKI_CLONE_VM:	
           
          cloneflags &= ~(VKI_CLONE_VFORK | VKI_CLONE_VM);
        case 0:  
          SET_STATUS_from_SysRes (ML_ (do_fork_clone) (tid,
                                  cloneflags,  
                                  (Int *) ARG3,  
                                  (Int *) ARG5));	
        break;
        default:
           
          VG_ (message) (Vg_UserMsg, "Unsupported clone() flags: 0x%lx\n", ARG1);
          VG_ (message) (Vg_UserMsg, "\n");
          VG_ (message) (Vg_UserMsg, "The only supported clone() uses are:\n");
          VG_ (message) (Vg_UserMsg, 
                          " - via a threads library (LinuxThreads or NPTL)\n");
          VG_ (message) (Vg_UserMsg,
                          " - via the implementation of fork or vfork\n");
          VG_ (unimplemented)("Valgrind does not support general clone().");
    }
    if (SUCCESS)
      {
        if (ARG1 & VKI_CLONE_PARENT_SETTID)
          POST_MEM_WRITE (ARG3, sizeof (Int));
        if (ARG1 & (VKI_CLONE_CHILD_SETTID | VKI_CLONE_CHILD_CLEARTID))
          POST_MEM_WRITE (ARG5, sizeof (Int));
        *flags |= SfYieldAfter;
      }
}

PRE (sys_sigreturn) 
{
  PRINT ("sys_sigreturn ( )");
  vg_assert (VG_ (is_valid_tid) (tid));
  vg_assert (tid >= 1 && tid < VG_N_THREADS);
  vg_assert (VG_ (is_running_thread) (tid));
  VG_ (sigframe_destroy) (tid, False);
 
  *flags |= SfNoWriteResult;
  SET_STATUS_Success (0);
    
  *flags |= SfPollAfter;
}

PRE (sys_rt_sigreturn) 
{
  PRINT ("rt_sigreturn ( )");
  vg_assert (VG_ (is_valid_tid) (tid));
  vg_assert (tid >= 1 && tid < VG_N_THREADS);
  vg_assert (VG_ (is_running_thread) (tid));
   
  VG_ (sigframe_destroy) (tid, True);
 
  *flags |= SfNoWriteResult;
  SET_STATUS_Success (0);
   
  *flags |= SfPollAfter;
}

PRE (sys_set_thread_area) 
{
   PRINT ("set_thread_area (%lx)", ARG1);
   PRE_REG_READ1(long, "set_thread_area", unsigned long, addr);
   SET_STATUS_from_SysRes( sys_set_tls( tid, ARG1 ) );
}

PRE (sys_cacheflush)
{
  PRINT ("cacheflush (%lx, %lx, %lx)", ARG1, ARG2, ARG3);
  PRE_REG_READ3(long, "cacheflush", unsigned long, addr,
                int, nbytes, int, cache);
  VG_ (discard_translations) ((Addr)ARG1, (ULong) ARG2,
                              "PRE(sys_cacheflush)");
  SET_STATUS_Success (0);
}

PRE(sys_pipe)
{
   PRINT("sys_pipe ( %#lx )", ARG1);
   PRE_REG_READ1(int, "pipe", int *, filedes);
   PRE_MEM_WRITE( "pipe(filedes)", ARG1, 2*sizeof(int) );
}

POST(sys_pipe)
{
   Int p0, p1;
   vg_assert(SUCCESS);
   p0 = RES;
   p1 = sr_ResEx(status->sres);

   if (!ML_(fd_allowed)(p0, "pipe", tid, True) ||
       !ML_(fd_allowed)(p1, "pipe", tid, True)) {
      VG_(close)(p0);
      VG_(close)(p1);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds)) {
         ML_(record_fd_open_nameless)(tid, p0);
         ML_(record_fd_open_nameless)(tid, p1);
      }
   }
}

#undef PRE
#undef POST

 
#define PLAX_(sysno, name)    WRAPPER_ENTRY_X_(mips_linux, sysno, name) 
#define PLAXY(sysno, name)    WRAPPER_ENTRY_XY(mips_linux, sysno, name)



static SyscallTableEntry syscall_main_table[] = {
   
   GENX_ (__NR_exit,                   sys_exit),                    
   GENX_ (__NR_fork,                   sys_fork),                    
   GENXY (__NR_read,                   sys_read),                    
   GENX_ (__NR_write,                  sys_write),                   
   GENXY (__NR_open,                   sys_open),                    
   GENXY (__NR_close,                  sys_close),                   
   GENXY (__NR_waitpid,                sys_waitpid),                 
   GENXY (__NR_creat,                  sys_creat),                   
   GENX_ (__NR_link,                   sys_link),                    
   GENX_ (__NR_unlink,                 sys_unlink),                  
   GENX_ (__NR_execve,                 sys_execve),                  
   GENX_ (__NR_chdir,                  sys_chdir),                   
   GENXY (__NR_time,                   sys_time),                    
   GENX_ (__NR_mknod,                  sys_mknod),                   
   GENX_ (__NR_chmod,                  sys_chmod),                   
   GENX_ (__NR_lchown,                 sys_lchown),                  
   
   LINX_ (__NR_lseek,                  sys_lseek),                   
   GENX_ (__NR_getpid,                 sys_getpid),                  
   LINX_ (__NR_mount,                  sys_mount),                   
   LINX_ (__NR_umount,                 sys_oldumount),               
   GENX_ (__NR_setuid,                 sys_setuid),                  
   GENX_ (__NR_getuid,                 sys_getuid),                  
   LINX_ (__NR_stime,                  sys_stime),                   
   
   GENX_ (__NR_alarm,                  sys_alarm),                   
   
   GENX_ (__NR_pause,                  sys_pause),                   
   LINX_ (__NR_utime,                  sys_utime),                   
   
   
   GENX_ (__NR_access,                 sys_access),                  
   
   
   
   GENX_ (__NR_kill,                   sys_kill),                    
   GENX_ (__NR_rename,                 sys_rename),                  
   GENX_ (__NR_mkdir,                  sys_mkdir),                   
   GENX_ (__NR_rmdir,                  sys_rmdir),                   
   GENXY (__NR_dup,                    sys_dup),                     
   PLAXY (__NR_pipe,                   sys_pipe),                    
   GENXY (__NR_times,                  sys_times),                   
   
   GENX_ (__NR_brk,                    sys_brk),                     
   GENX_ (__NR_setgid,                 sys_setgid),                  
   GENX_ (__NR_getgid,                 sys_getgid),                  
   
   GENX_ (__NR_geteuid,                sys_geteuid),                 
   GENX_ (__NR_getegid,                sys_getegid),                 
   
   LINX_ (__NR_umount2,                sys_umount),                  
   
   LINXY (__NR_ioctl,                  sys_ioctl),                   
   LINXY (__NR_fcntl,                  sys_fcntl),                   
   
   GENX_ (__NR_setpgid,                sys_setpgid),                 
   
   
   GENX_ (__NR_umask,                  sys_umask),                   
   GENX_ (__NR_chroot,                 sys_chroot),                  
   
   GENXY (__NR_dup2,                   sys_dup2),                    
   GENX_ (__NR_getppid,                sys_getppid),                 
   GENX_ (__NR_getpgrp,                sys_getpgrp),                 
   GENX_ (__NR_setsid,                 sys_setsid),                  
   LINXY (__NR_sigaction,              sys_sigaction),               
   
   
   GENX_ (__NR_setreuid,               sys_setreuid),                
   GENX_ (__NR_setregid,               sys_setregid),                
   
   LINXY (__NR_sigpending,             sys_sigpending),              
   
   GENX_ (__NR_setrlimit,              sys_setrlimit),               
   GENXY (__NR_getrlimit,              sys_getrlimit),               
   GENXY (__NR_getrusage,              sys_getrusage),               
   GENXY (__NR_gettimeofday,           sys_gettimeofday),            
   GENX_ (__NR_settimeofday,           sys_settimeofday),            
   GENXY (__NR_getgroups,              sys_getgroups),               
   GENX_ (__NR_setgroups,              sys_setgroups),               
   
   GENX_ (__NR_symlink,                sys_symlink),                 
   
   GENX_ (__NR_readlink,               sys_readlink),                
   
   
   
   
   PLAX_ (__NR_mmap,                   sys_mmap),                    
   GENXY (__NR_munmap,                 sys_munmap),                  
   GENX_ (__NR_truncate,               sys_truncate),                
   GENX_ (__NR_ftruncate,              sys_ftruncate),               
   GENX_ (__NR_fchmod,                 sys_fchmod),                  
   GENX_ (__NR_fchown,                 sys_fchown),                  
   GENX_ (__NR_getpriority,            sys_getpriority),             
   GENX_ (__NR_setpriority,            sys_setpriority),             
   
   GENXY (__NR_statfs,                 sys_statfs),                  
   GENXY (__NR_fstatfs,                sys_fstatfs),                 
   
   LINXY (__NR_socketcall,             sys_socketcall),              
   LINXY (__NR_syslog,                 sys_syslog),                  
   GENXY (__NR_setitimer,              sys_setitimer),               
   
   GENXY (__NR_stat,                   sys_newstat),                 
   GENXY (__NR_lstat,                  sys_newlstat),                
   GENXY (__NR_fstat,                  sys_newfstat),                
   
   
   
   
   
   GENXY (__NR_wait4,                  sys_wait4),                   
   
   LINXY (__NR_sysinfo,                sys_sysinfo),                 
   LINXY (__NR_ipc,                    sys_ipc),                     
   GENX_ (__NR_fsync,                  sys_fsync),                   
   PLAX_ (__NR_sigreturn,              sys_sigreturn),               
   PLAX_ (__NR_clone,                  sys_clone),                   
   
   GENXY (__NR_uname,                  sys_newuname),                
   
   
   GENXY (__NR_mprotect,               sys_mprotect),                
   LINXY (__NR_sigprocmask,            sys_sigprocmask),             
   
   
   
   
   
   GENX_ (__NR_getpgid,                sys_getpgid),                 
   GENX_ (__NR_fchdir,                 sys_fchdir),                  
   
   
   LINX_ (__NR_personality,            sys_personality),            
   
   LINX_ (__NR_setfsuid,               sys_setfsuid),                
   LINX_ (__NR_setfsgid,               sys_setfsgid),                
   LINXY (__NR__llseek,                sys_llseek),                  
   GENXY (__NR_getdents,               sys_getdents),                
   GENX_ (__NR__newselect,             sys_select),                  
   GENX_ (__NR_flock,                  sys_flock),                   
   GENX_ (__NR_msync,                  sys_msync),                   
   GENXY (__NR_readv,                  sys_readv),                   
   GENX_ (__NR_writev,                 sys_writev),                  
   PLAX_ (__NR_cacheflush,             sys_cacheflush),              
   GENX_ (__NR_getsid,                 sys_getsid),                  
   GENX_ (__NR_fdatasync,              sys_fdatasync),               
   LINXY (__NR__sysctl,                sys_sysctl),                  
   GENX_ (__NR_mlock,                  sys_mlock),                   
   GENX_ (__NR_munlock,                sys_munlock),                 
   GENX_ (__NR_mlockall,               sys_mlockall),                
   LINX_ (__NR_munlockall,             sys_munlockall),              
   
   LINXY (__NR_sched_getparam,         sys_sched_getparam),          
   LINX_ (__NR_sched_setscheduler,     sys_sched_setscheduler),      
   LINX_ (__NR_sched_getscheduler,     sys_sched_getscheduler),      
   LINX_ (__NR_sched_yield,            sys_sched_yield),             
   LINX_ (__NR_sched_get_priority_max, sys_sched_get_priority_max),  
   LINX_ (__NR_sched_get_priority_min, sys_sched_get_priority_min),  
   
   GENXY (__NR_nanosleep,              sys_nanosleep),               
   GENX_ (__NR_mremap,                 sys_mremap),                  
   LINXY (__NR_accept,                 sys_accept),                  
   LINX_ (__NR_bind,                   sys_bind),                    
   LINX_ (__NR_connect,                sys_connect),                 
   LINXY (__NR_getpeername,            sys_getpeername),             
   LINXY (__NR_getsockname,            sys_getsockname),             
   LINXY (__NR_getsockopt,             sys_getsockopt),              
   LINX_ (__NR_listen,                 sys_listen),                  
   LINXY (__NR_recv,                   sys_recv),                    
   LINXY (__NR_recvfrom,               sys_recvfrom),                
   LINXY (__NR_recvmsg,                sys_recvmsg),                 
   LINX_ (__NR_send,                   sys_send),                    
   LINX_ (__NR_sendmsg,                sys_sendmsg),                 
   LINX_ (__NR_sendto,                 sys_sendto),                  
   LINX_ (__NR_setsockopt,             sys_setsockopt),              
   LINX_ (__NR_shutdown,               sys_shutdown),                
   LINXY (__NR_socket,                 sys_socket),                  
   LINXY (__NR_socketpair,             sys_socketpair),              
   LINX_ (__NR_setresuid,              sys_setresuid),               
   LINXY (__NR_getresuid,              sys_getresuid),               
   
   GENXY (__NR_poll,                   sys_poll),                    
   
   LINX_ (__NR_setresgid,              sys_setresgid),               
   LINXY (__NR_getresgid,              sys_getresgid),               
   LINXY (__NR_prctl,                  sys_prctl),                   
   PLAX_ (__NR_rt_sigreturn,           sys_rt_sigreturn),            
   LINXY (__NR_rt_sigaction,           sys_rt_sigaction),            
   LINXY (__NR_rt_sigprocmask,         sys_rt_sigprocmask),          
   LINXY (__NR_rt_sigpending,          sys_rt_sigpending),           
   LINXY (__NR_rt_sigtimedwait,        sys_rt_sigtimedwait),         
   LINXY (__NR_rt_sigqueueinfo,        sys_rt_sigqueueinfo),         
   LINX_ (__NR_rt_sigsuspend,          sys_rt_sigsuspend),           
   GENXY (__NR_pread64,                sys_pread64),                 
   GENX_ (__NR_pwrite64,               sys_pwrite64),                
   GENX_ (__NR_chown,                  sys_chown),                   
   GENXY (__NR_getcwd,                 sys_getcwd),                  
   LINXY (__NR_capget,                 sys_capget),                  
   
   GENXY (__NR_sigaltstack,            sys_sigaltstack),             
   LINXY (__NR_sendfile,               sys_sendfile),                
   
   
   PLAX_ (__NR_mmap2,                  sys_mmap2),                   
   
   GENX_ (__NR_ftruncate64,            sys_ftruncate64),             
   PLAXY (__NR_stat64,                 sys_stat64),                  
   PLAXY (__NR_lstat64,                sys_lstat64),                 
   PLAXY (__NR_fstat64,                sys_fstat64),                 
   
   GENXY (__NR_mincore,                sys_mincore),                 
   GENX_ (__NR_madvise,                sys_madvise),                 
   GENXY (__NR_getdents64,             sys_getdents64),              
   LINXY (__NR_fcntl64,                sys_fcntl64),                 
   
   LINX_ (__NR_gettid,                 sys_gettid),                  
   
   LINXY (__NR_getxattr,               sys_getxattr),                
   LINXY (__NR_lgetxattr,              sys_lgetxattr),               
   LINXY (__NR_fgetxattr,              sys_fgetxattr),               
   LINXY (__NR_listxattr,              sys_listxattr),               
   LINXY (__NR_llistxattr,             sys_llistxattr),              
   LINXY (__NR_flistxattr,             sys_flistxattr),              
   LINX_ (__NR_removexattr,            sys_removexattr),             
   LINX_ (__NR_lremovexattr,           sys_lremovexattr),            
   LINX_ (__NR_fremovexattr,           sys_fremovexattr),            
   
   LINXY (__NR_sendfile64,             sys_sendfile64),              
   LINXY (__NR_futex,                  sys_futex),                   
   LINX_ (__NR_sched_setaffinity,      sys_sched_setaffinity),       
   LINXY (__NR_sched_getaffinity,      sys_sched_getaffinity),       
   LINX_ (__NR_io_setup,               sys_io_setup),                
   LINX_ (__NR_io_destroy,             sys_io_destroy),              
   LINXY (__NR_io_getevents,           sys_io_getevents),            
   LINX_ (__NR_io_submit,              sys_io_submit),               
   LINXY (__NR_io_cancel,              sys_io_cancel),               
   LINX_ (__NR_exit_group,             sys_exit_group),              
   
   LINXY (__NR_epoll_create,           sys_epoll_create),            
   LINX_ (__NR_epoll_ctl,              sys_epoll_ctl),               
   LINXY (__NR_epoll_wait,             sys_epoll_wait),              
   
   LINX_ (__NR_set_tid_address,        sys_set_tid_address),         
   LINX_ (__NR_fadvise64,              sys_fadvise64),               
   GENXY (__NR_statfs64,               sys_statfs64),                
   GENXY (__NR_fstatfs64,              sys_fstatfs64),               
   
   LINXY (__NR_timer_create,           sys_timer_create),            
   LINXY (__NR_timer_settime,          sys_timer_settime),           
   LINXY (__NR_timer_gettime,          sys_timer_gettime),           
   LINX_ (__NR_timer_getoverrun,       sys_timer_getoverrun),        
   LINX_ (__NR_timer_delete,           sys_timer_delete),            
   LINX_ (__NR_clock_settime,          sys_clock_settime),           
   LINXY (__NR_clock_gettime,          sys_clock_gettime),           
   LINXY (__NR_clock_getres,           sys_clock_getres),            
   LINXY (__NR_clock_nanosleep,        sys_clock_nanosleep),         
   LINXY (__NR_tgkill,                 sys_tgkill),                  
   
   LINXY (__NR_get_mempolicy,          sys_get_mempolicy),           
   LINX_ (__NR_set_mempolicy,          sys_set_mempolicy),           
   LINXY (__NR_mq_open,                sys_mq_open),                 
   LINX_ (__NR_mq_unlink,              sys_mq_unlink),               
   LINX_ (__NR_mq_timedsend,           sys_mq_timedsend),            
   LINXY (__NR_mq_timedreceive,        sys_mq_timedreceive),         
   LINX_ (__NR_mq_notify,              sys_mq_notify),               
   LINXY (__NR_mq_getsetattr,          sys_mq_getsetattr),           
   LINX_ (__NR_inotify_init,           sys_inotify_init),            
   LINX_ (__NR_inotify_add_watch,      sys_inotify_add_watch),       
   LINX_ (__NR_inotify_rm_watch,       sys_inotify_rm_watch),        
   
   PLAX_ (__NR_set_thread_area,        sys_set_thread_area),         
   
   LINXY (__NR_openat,                 sys_openat),                  
   LINX_ (__NR_mkdirat,                sys_mkdirat),                 
   LINX_ (__NR_mknodat,                sys_mknodat),                 
   LINX_ (__NR_fchownat,               sys_fchownat),                
   LINX_ (__NR_futimesat,              sys_futimesat),               
   PLAXY (__NR_fstatat64,              sys_fstatat64),               
   LINX_ (__NR_unlinkat,               sys_unlinkat),                
   LINX_ (__NR_renameat,               sys_renameat),                
   LINX_ (__NR_linkat,                 sys_linkat),                  
   LINX_ (__NR_symlinkat,              sys_symlinkat),               
   LINX_ (__NR_readlinkat,             sys_readlinkat),              
   LINX_ (__NR_fchmodat,               sys_fchmodat),                
   LINX_ (__NR_faccessat,              sys_faccessat),               
   
   LINXY (__NR_ppoll,                  sys_ppoll),                   
   
   LINX_ (__NR_set_robust_list,        sys_set_robust_list),         
   LINXY (__NR_get_robust_list,        sys_get_robust_list),         
   
   LINXY (__NR_epoll_pwait,            sys_epoll_pwait),             
   
   LINX_ (__NR_utimensat,              sys_utimensat),               
   
   LINX_ (__NR_fallocate,              sys_fallocate),               
   LINXY (__NR_timerfd_create,         sys_timerfd_create),          
   LINXY (__NR_timerfd_gettime,        sys_timerfd_gettime),         
   LINXY (__NR_timerfd_settime,        sys_timerfd_settime),         
   LINXY (__NR_signalfd4,              sys_signalfd4),               
   LINXY (__NR_eventfd2,               sys_eventfd2),                
   
   LINXY (__NR_pipe2,                  sys_pipe2),                   
   LINXY (__NR_inotify_init1,          sys_inotify_init1),           
   
   LINXY (__NR_prlimit64,              sys_prlimit64),               
   
   LINXY (__NR_clock_adjtime,          sys_clock_adjtime),           
   LINX_ (__NR_syncfs,                 sys_syncfs),                  
   
   LINXY (__NR_process_vm_readv,       sys_process_vm_readv),        
   LINX_ (__NR_process_vm_writev,      sys_process_vm_writev),       
   
   LINXY(__NR_getrandom,               sys_getrandom),               
   LINXY(__NR_memfd_create,            sys_memfd_create)             
};

SyscallTableEntry* ML_(get_linux_syscall_entry) (UInt sysno)
{
   const UInt syscall_main_table_size
               = sizeof (syscall_main_table) / sizeof (syscall_main_table[0]);
   
   if (sysno < syscall_main_table_size) {
      SyscallTableEntry * sys = &syscall_main_table[sysno];
      if (sys->before == NULL)
         return NULL;  
      else
         return sys;
   }
   
   return NULL;
}

#endif 

 
 
 
