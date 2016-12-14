#ifndef __ASM_PTRACE_H
#define __ASM_PTRACE_H

#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#define PTRACE_GETFPREGS 14
#define PTRACE_SETFPREGS 15

#define PTRACE_GETWMMXREGS 18
#define PTRACE_SETWMMXREGS 19

#define PTRACE_OLDSETOPTIONS 21

#define PTRACE_GET_THREAD_AREA 22

#define PTRACE_SET_SYSCALL 23

#define PTRACE_GETCRUNCHREGS 25
#define PTRACE_SETCRUNCHREGS 26

#define USR26_MODE 0x00000000
#define FIQ26_MODE 0x00000001
#define IRQ26_MODE 0x00000002
#define SVC26_MODE 0x00000003
#define USR_MODE 0x00000010
#define FIQ_MODE 0x00000011
#define IRQ_MODE 0x00000012
#define SVC_MODE 0x00000013
#define ABT_MODE 0x00000017
#define UND_MODE 0x0000001b
#define SYSTEM_MODE 0x0000001f
#define MODE32_BIT 0x00000010
#define MODE_MASK 0x0000001f
#define PSR_T_BIT 0x00000020
#define PSR_F_BIT 0x00000040
#define PSR_I_BIT 0x00000080
#define PSR_J_BIT 0x01000000
#define PSR_Q_BIT 0x08000000
#define PSR_V_BIT 0x10000000
#define PSR_C_BIT 0x20000000
#define PSR_Z_BIT 0x40000000
#define PSR_N_BIT 0x80000000
#define PCMASK 0

#define PSR_f 0xff000000
#define PSR_s 0x00ff0000
#define PSR_x 0x0000ff00
#define PSR_c 0x000000ff

#ifndef __ASSEMBLY__

struct pt_regs {
 long uregs[44];   
};

#define ARM_cpsr uregs[16]
#define ARM_pc uregs[15]
#define ARM_lr uregs[14]
#define ARM_sp uregs[13]
#define ARM_ip uregs[12]
#define ARM_fp uregs[11]
#define ARM_r10 uregs[10]
#define ARM_r9 uregs[9]
#define ARM_r8 uregs[8]
#define ARM_r7 uregs[7]
#define ARM_r6 uregs[6]
#define ARM_r5 uregs[5]
#define ARM_r4 uregs[4]
#define ARM_r3 uregs[3]
#define ARM_r2 uregs[2]
#define ARM_r1 uregs[1]
#define ARM_r0 uregs[0]
#define ARM_ORIG_r0 uregs[17]

#define x86_r15 uregs[0]
#define x86_r14 uregs[1]
#define x86_r13 uregs[2]
#define x86_r12 uregs[3]
#define x86_rbp uregs[4]
#define x86_rbx uregs[5]
#define x86_r11 uregs[6]
#define x86_r10 uregs[7]
#define x86_r9 uregs[8]
#define x86_r8 uregs[9]
#define x86_rax uregs[10]
#define x86_rcx uregs[11]
#define x86_rdx uregs[12]
#define x86_rsi uregs[13]
#define x86_rdi uregs[14]
#define x86_orig_rax uregs[15]
#define x86_rip uregs[16]
#define x86_cs uregs[17]
#define x86_eflags uregs[18]
#define x86_rsp uregs[19]
#define x86_ss uregs[20]

#define pc_pointer(v)   ((v) & ~PCMASK)

#define instruction_pointer(regs)   (pc_pointer((regs)->ARM_pc))

#define profile_pc(regs) instruction_pointer(regs)

#endif

#endif
