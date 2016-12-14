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
#ifndef _ASM_CPU_H
#define _ASM_CPU_H
#define PRID_COMP_LEGACY 0x000000
#define PRID_COMP_MIPS 0x010000
#define PRID_COMP_BROADCOM 0x020000
#define PRID_COMP_ALCHEMY 0x030000
#define PRID_COMP_SIBYTE 0x040000
#define PRID_COMP_SANDCRAFT 0x050000
#define PRID_COMP_NXP 0x060000
#define PRID_COMP_TOSHIBA 0x070000
#define PRID_COMP_LSI 0x080000
#define PRID_COMP_LEXRA 0x0b0000
#define PRID_IMP_R2000 0x0100
#define PRID_IMP_AU1_REV1 0x0100
#define PRID_IMP_AU1_REV2 0x0200
#define PRID_IMP_R3000 0x0200  
#define PRID_IMP_R6000 0x0300  
#define PRID_IMP_R4000 0x0400
#define PRID_IMP_R6000A 0x0600
#define PRID_IMP_R10000 0x0900
#define PRID_IMP_R4300 0x0b00
#define PRID_IMP_VR41XX 0x0c00
#define PRID_IMP_R12000 0x0e00
#define PRID_IMP_R14000 0x0f00
#define PRID_IMP_R8000 0x1000
#define PRID_IMP_PR4450 0x1200
#define PRID_IMP_R4600 0x2000
#define PRID_IMP_R4700 0x2100
#define PRID_IMP_TX39 0x2200
#define PRID_IMP_R4640 0x2200
#define PRID_IMP_R4650 0x2200  
#define PRID_IMP_R5000 0x2300
#define PRID_IMP_TX49 0x2d00
#define PRID_IMP_SONIC 0x2400
#define PRID_IMP_MAGIC 0x2500
#define PRID_IMP_RM7000 0x2700
#define PRID_IMP_NEVADA 0x2800  
#define PRID_IMP_RM9000 0x3400
#define PRID_IMP_LOONGSON1 0x4200
#define PRID_IMP_R5432 0x5400
#define PRID_IMP_R5500 0x5500
#define PRID_IMP_LOONGSON2 0x6300
#define PRID_IMP_UNKNOWN 0xff00
#define PRID_IMP_4KC 0x8000
#define PRID_IMP_5KC 0x8100
#define PRID_IMP_20KC 0x8200
#define PRID_IMP_4KEC 0x8400
#define PRID_IMP_4KSC 0x8600
#define PRID_IMP_25KF 0x8800
#define PRID_IMP_5KE 0x8900
#define PRID_IMP_4KECR2 0x9000
#define PRID_IMP_4KEMPR2 0x9100
#define PRID_IMP_4KSD 0x9200
#define PRID_IMP_24K 0x9300
#define PRID_IMP_34K 0x9500
#define PRID_IMP_24KE 0x9600
#define PRID_IMP_74K 0x9700
#define PRID_IMP_1004K 0x9900
#define PRID_IMP_SB1 0x0100
#define PRID_IMP_SB1A 0x1100
#define PRID_IMP_SR71000 0x0400
#define PRID_IMP_BCM4710 0x4000
#define PRID_IMP_BCM3302 0x9000
#define PRID_REV_MASK 0x00ff
#define PRID_REV_TX4927 0x0022
#define PRID_REV_TX4937 0x0030
#define PRID_REV_R4400 0x0040
#define PRID_REV_R3000A 0x0030
#define PRID_REV_R3000 0x0020
#define PRID_REV_R2000A 0x0010
#define PRID_REV_TX3912 0x0010
#define PRID_REV_TX3922 0x0030
#define PRID_REV_TX3927 0x0040
#define PRID_REV_VR4111 0x0050
#define PRID_REV_VR4181 0x0050  
#define PRID_REV_VR4121 0x0060
#define PRID_REV_VR4122 0x0070
#define PRID_REV_VR4181A 0x0070  
#define PRID_REV_VR4130 0x0080
#define PRID_REV_34K_V1_0_2 0x0022
#define PRID_REV_ENCODE_44(ver, rev)   ((ver) << 4 | (rev))
#define PRID_REV_ENCODE_332(ver, rev, patch)   ((ver) << 5 | (rev) << 2 | (patch))
#define FPIR_IMP_NONE 0x0000
enum cpu_type_enum {
 CPU_UNKNOWN,
 CPU_R2000, CPU_R3000, CPU_R3000A, CPU_R3041, CPU_R3051, CPU_R3052,
 CPU_R3081, CPU_R3081E,
 CPU_R6000, CPU_R6000A,
 CPU_R4000PC, CPU_R4000SC, CPU_R4000MC, CPU_R4200, CPU_R4300, CPU_R4310,
 CPU_R4400PC, CPU_R4400SC, CPU_R4400MC, CPU_R4600, CPU_R4640, CPU_R4650,
 CPU_R4700, CPU_R5000, CPU_R5000A, CPU_R5500, CPU_NEVADA, CPU_R5432,
 CPU_R10000, CPU_R12000, CPU_R14000, CPU_VR41XX, CPU_VR4111, CPU_VR4121,
 CPU_VR4122, CPU_VR4131, CPU_VR4133, CPU_VR4181, CPU_VR4181A, CPU_RM7000,
 CPU_SR71000, CPU_RM9000, CPU_TX49XX,
 CPU_R8000,
 CPU_TX3912, CPU_TX3922, CPU_TX3927,
 CPU_4KC, CPU_4KEC, CPU_4KSC, CPU_24K, CPU_34K, CPU_1004K, CPU_74K,
 CPU_AU1000, CPU_AU1100, CPU_AU1200, CPU_AU1210, CPU_AU1250, CPU_AU1500,
 CPU_AU1550, CPU_PR4450, CPU_BCM3302, CPU_BCM4710,
 CPU_5KC, CPU_20KC, CPU_25KF, CPU_SB1, CPU_SB1A, CPU_LOONGSON2,
 CPU_LAST
};
#define MIPS_CPU_ISA_I 0x00000001
#define MIPS_CPU_ISA_II 0x00000002
#define MIPS_CPU_ISA_III 0x00000004
#define MIPS_CPU_ISA_IV 0x00000008
#define MIPS_CPU_ISA_V 0x00000010
#define MIPS_CPU_ISA_M32R1 0x00000020
#define MIPS_CPU_ISA_M32R2 0x00000040
#define MIPS_CPU_ISA_M64R1 0x00000080
#define MIPS_CPU_ISA_M64R2 0x00000100
#define MIPS_CPU_ISA_32BIT (MIPS_CPU_ISA_I | MIPS_CPU_ISA_II |   MIPS_CPU_ISA_M32R1 | MIPS_CPU_ISA_M32R2 )
#define MIPS_CPU_ISA_64BIT (MIPS_CPU_ISA_III | MIPS_CPU_ISA_IV |   MIPS_CPU_ISA_V | MIPS_CPU_ISA_M64R1 | MIPS_CPU_ISA_M64R2)
#define MIPS_CPU_TLB 0x00000001  
#define MIPS_CPU_4KEX 0x00000002  
#define MIPS_CPU_3K_CACHE 0x00000004  
#define MIPS_CPU_4K_CACHE 0x00000008  
#define MIPS_CPU_TX39_CACHE 0x00000010  
#define MIPS_CPU_FPU 0x00000020  
#define MIPS_CPU_32FPR 0x00000040  
#define MIPS_CPU_COUNTER 0x00000080  
#define MIPS_CPU_WATCH 0x00000100  
#define MIPS_CPU_DIVEC 0x00000200  
#define MIPS_CPU_VCE 0x00000400  
#define MIPS_CPU_CACHE_CDEX_P 0x00000800  
#define MIPS_CPU_CACHE_CDEX_S 0x00001000  
#define MIPS_CPU_MCHECK 0x00002000  
#define MIPS_CPU_EJTAG 0x00004000  
#define MIPS_CPU_NOFPUEX 0x00008000  
#define MIPS_CPU_LLSC 0x00010000  
#define MIPS_CPU_INCLUSIVE_CACHES 0x00020000  
#define MIPS_CPU_PREFETCH 0x00040000  
#define MIPS_CPU_VINT 0x00080000  
#define MIPS_CPU_VEIC 0x00100000  
#define MIPS_CPU_ULRI 0x00200000  
#define MIPS_ASE_MIPS16 0x00000001  
#define MIPS_ASE_MDMX 0x00000002  
#define MIPS_ASE_MIPS3D 0x00000004  
#define MIPS_ASE_SMARTMIPS 0x00000008  
#define MIPS_ASE_DSP 0x00000010  
#define MIPS_ASE_MIPSMT 0x00000020  
#endif
