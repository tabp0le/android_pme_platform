/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ***   To edit the content of this header, modify the corresponding
 ***   source file (e.g. under external/kernel-headers/original/) then
 ***   run bionic/libc/kernel/tools/update_all.py
 ***
 ***   Any manual change here will be lost the next time this script will
 ***   be run. You've been warned!
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _ASM_X86_SIGCONTEXT32_H
#define _ASM_X86_SIGCONTEXT32_H
#include <linux/types.h>
#define X86_FXSR_MAGIC 0x0000
struct _fpreg {
 unsigned short significand[4];
 unsigned short exponent;
};
struct _fpxreg {
 unsigned short significand[4];
 unsigned short exponent;
 unsigned short padding[3];
};
struct _xmmreg {
 __u32 element[4];
};
struct _fpstate_ia32 {
 __u32 cw;
 __u32 sw;
 __u32 tag;
 __u32 ipoff;
 __u32 cssel;
 __u32 dataoff;
 __u32 datasel;
 struct _fpreg _st[8];
 unsigned short status;
 unsigned short magic;
 __u32 _fxsr_env[6];
 __u32 mxcsr;
 __u32 reserved;
 struct _fpxreg _fxsr_st[8];
 struct _xmmreg _xmm[8];
 __u32 padding[44];
 union {
 __u32 padding2[12];
 struct _fpx_sw_bytes sw_reserved;
 };
};
struct sigcontext_ia32 {
 unsigned short gs, __gsh;
 unsigned short fs, __fsh;
 unsigned short es, __esh;
 unsigned short ds, __dsh;
 unsigned int di;
 unsigned int si;
 unsigned int bp;
 unsigned int sp;
 unsigned int bx;
 unsigned int dx;
 unsigned int cx;
 unsigned int ax;
 unsigned int trapno;
 unsigned int err;
 unsigned int ip;
 unsigned short cs, __csh;
 unsigned int flags;
 unsigned int sp_at_signal;
 unsigned short ss, __ssh;
 unsigned int fpstate;
 unsigned int oldmask;
 unsigned int cr2;
};
#endif
