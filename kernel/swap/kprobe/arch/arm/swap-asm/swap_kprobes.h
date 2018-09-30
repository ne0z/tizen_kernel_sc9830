/**
 * @file kprobe/arch/asm-arm/swap_kprobes.h
 * @author Ekaterina Gorelkina <e.gorelkina@samsung.com>:
 *		initial implementation for ARM/MIPS
 * @author Alexey Gerenkov <a.gerenkov@samsung.com>:
 *		User-Space Probes initial implementation;
 *		Support x86/ARM/MIPS for both user and kernel spaces.
 * @author Ekaterina Gorelkina <e.gorelkina@samsung.com>:
 *		redesign module for separating core and arch parts
 * @author Alexander Shirshikov <a.shirshikov@samsung.com>:
 *		 initial implementation for Thumb
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * @section COPYRIGHT
 *
 * Copyright (C) Samsung Electronics, 2006-2010
 *
 * @section DESCRIPTION
 *
 * ARM arch-dependent kprobes interface declaration.
 */


#ifndef _SWAP_ASM_ARM_KPROBES_H
#define _SWAP_ASM_ARM_KPROBES_H

#include <linux/sched.h>
#include <linux/compiler.h>

typedef unsigned long kprobe_opcode_t;

#ifdef CONFIG_CPU_S3C2443
/** Breakpoint instruction */
#define BREAKPOINT_INSTRUCTION          0xe1200070
#else
/** Breakpoint instruction */
#define BREAKPOINT_INSTRUCTION          0xffffdeff
#endif /* CONFIG_CPU_S3C2443 */

#ifndef KPROBES_RET_PROBE_TRAMP

#ifdef CONFIG_CPU_S3C2443
/** Undefined instruction */
#define UNDEF_INSTRUCTION               0xe1200071
#else
/** Undefined instruction */
#define UNDEF_INSTRUCTION               0xfffffffe
#endif /* CONFIG_CPU_S3C2443 */

#endif /* KPROBES_RET_PROBE_TRAMP */

/** Maximum insn size */
#define MAX_INSN_SIZE                   1

/** Uprobes trampoline length */
#define UPROBES_TRAMP_LEN              (9 * 4)
/** Uprobes trampoline insn idx */
#define UPROBES_TRAMP_INSN_IDX         2
/** Uprobes trampoline ss break idx */
#define UPROBES_TRAMP_SS_BREAK_IDX     4
/** Uprobes trampoline ret break idx */
#define UPROBES_TRAMP_RET_BREAK_IDX    5
/** Kprobes trampoline length */
#define KPROBES_TRAMP_LEN              (9 * 4)
/** Kprobes trampoline insn idx */
#define KPROBES_TRAMP_INSN_IDX         UPROBES_TRAMP_INSN_IDX
/** Kprobes trampoline ss break idx */
#define KPROBES_TRAMP_SS_BREAK_IDX     UPROBES_TRAMP_SS_BREAK_IDX

/* TODO: remove (not needed for kprobe) */
#define KPROBES_TRAMP_RET_BREAK_IDX	UPROBES_TRAMP_RET_BREAK_IDX

/** User register offset */
#define UREGS_OFFSET 8

/**
 * @struct prev_kprobe
 * @brief Stores previous kprobe.
 * @var prev_kprobe::kp
 * Pointer to kprobe struct.
 * @var prev_kprobe::status
 * Kprobe status.
 */
struct prev_kprobe {
	struct kprobe *kp;
	unsigned long status;
};

/**
 * @brief Gets task pc.
 *
 * @param p Pointer to task_struct
 * @return Value in pc.
 */
static inline unsigned long arch_get_task_pc(struct task_struct *p)
{
	return task_thread_info(p)->cpu_context.pc;
}

/**
 * @brief Sets task pc.
 *
 * @param p Pointer to task_struct.
 * @param val Value that should be set.
 * @return Void.
 */
static inline void arch_set_task_pc(struct task_struct *p, unsigned long val)
{
	task_thread_info(p)->cpu_context.pc = val;
}

/**
 * @brief Gets syscall registers.
 *
 * @param sp Pointer to stack.
 * @return Pointer to CPU regs data.
 */
static inline struct pt_regs *swap_get_syscall_uregs(unsigned long sp)
{
	return (struct pt_regs *)(sp + UREGS_OFFSET);
}

/**
 * @brief Gets stack pointer.
 *
 * @param regs Pointer to CPU registers data.
 * @return Stack address.
 */
static inline unsigned long swap_get_stack_ptr(struct pt_regs *regs)
{
	return regs->ARM_sp;
}

/**
 * @brief Sets stack pointer.
 *
 * @param regs Pointer to CPU registers data.
 * @param sp New stack pointer value.
 * @return Void
 */
static inline void swap_set_stack_ptr(struct pt_regs *regs, unsigned long sp)
{
	regs->ARM_sp = sp;
}

/**
 * @brief Gets instruction pointer.
 *
 * @param regs Pointer to CPU registers data.
 * @return Pointer to pc.
 */
static inline unsigned long swap_get_instr_ptr(struct pt_regs *regs)
{
	return regs->ARM_pc;
}

/**
 * @brief Sets instruction pointer.
 *
 * @param regs Pointer to CPU registers data.
 * @param val Address that should be stored in pc.
 * @return Void.
 */
static inline void swap_set_instr_ptr(struct pt_regs *regs, unsigned long val)
{
	regs->ARM_pc = val;
}

/**
 * @brief Gets return address.
 *
 * @param regs Pointer to CPU registers data.
 * @return Return address.
 */
static inline unsigned long swap_get_ret_addr(struct pt_regs *regs)
{
	return regs->ARM_lr;
}

/**
 * @brief Sets return address.
 *
 * @param regs Pointer to CPU registers data.
 * @param val New return address.
 * @return Void.
 */
static inline void swap_set_ret_addr(struct pt_regs *regs, unsigned long val)
{
	regs->ARM_lr = val;
}

/**
 * @brief Gets specified argument.
 *
 * @param regs Pointer to CPU registers data.
 * @param num Number of the argument.
 * @return Argument value.
 */
static inline unsigned long swap_get_arg(struct pt_regs *regs, int num)
{
	return regs->uregs[num];
}

/**
 * @brief Sets specified argument.
 *
 * @param regs Pointer to CPU registers data.
 * @param num Number of the argument.
 * @param val New argument value.
 * @return Void.
 */
static inline void swap_set_arg(struct pt_regs *regs, int num,
				unsigned long val)
{
	regs->uregs[num] = val;
}

/*  undefined */
#define MASK_ARM_INSN_UNDEF		0x0FF00000
#define PTRN_ARM_INSN_UNDEF		0x03000000

#define MASK_THUMB_INSN_UNDEF		0xFE00
#define PTRN_THUMB_INSN_UNDEF		0xDE00

/*  architecturally undefined */
#define MASK_ARM_INSN_AUNDEF		0x0FF000F0
#define PTRN_ARM_INSN_AUNDEF		0x07F000F0

/*  branches */
#define MASK_ARM_INSN_B			0x0F000000
#define PTRN_ARM_INSN_B			0x0A000000

#define MASK_THUMB_INSN_B1		0xF000
#define PTRN_THUMB_INSN_B1		0xD000		/* b<cond> label */

#define MASK_THUMB_INSN_B2		0xF800
#define PTRN_THUMB_INSN_B2		0xE000		/* b label */

#define MASK_THUMB_INSN_CBZ		0xF500
#define PTRN_THUMB_INSN_CBZ		0xB100		/* CBZ/CBNZ */

#define MASK_THUMB2_INSN_B1		0xD000F800
#define PTRN_THUMB2_INSN_B1		0x8000F000

#define MASK_THUMB2_INSN_B2		0xD000F800
#define PTRN_THUMB2_INSN_B2		0x9000F000

#define MASK_ARM_INSN_BL		0x0F000000
#define PTRN_ARM_INSN_BL		0x0B000000

/* #define MASK_THUMB_INSN_BL		0xF800 */
/* #define PTRN_THUMB_INSN_BL		0xF000	shared between BL and BLX */
/* #define PTRN_THUMB_INSN_BL		0xF800 */

#define MASK_THUMB2_INSN_BL		0xD000F800
#define PTRN_THUMB2_INSN_BL		0xD000F000	/* bl imm  swapped */

#define MASK_ARM_INSN_BLX1		0xFE000000
#define PTRN_ARM_INSN_BLX1		0xFA000000

/* #define MASK_THUMB_INSN_BLX1		0xF800 */
/* #define PTRN_THUMB_INSN_BLX1		0xF000 */

#define MASK_THUMB2_INSN_BLX1		0xD001F800
#define PTRN_THUMB2_INSN_BLX1		0xC000F000

#define MASK_ARM_INSN_BLX2		0x0FF000F0
#define PTRN_ARM_INSN_BLX2		0x01200030

#define MASK_THUMB_INSN_BLX2		0xFF80		/* blx reg */
#define PTRN_THUMB_INSN_BLX2		0x4780

#define MASK_ARM_INSN_BX		0x0FF000F0
#define PTRN_ARM_INSN_BX		0x01200010

#define MASK_THUMB_INSN_BX		0xFF80
#define PTRN_THUMB_INSN_BX		0x4700

#define MASK_ARM_INSN_BXJ		0x0FF000F0
#define PTRN_ARM_INSN_BXJ		0x01200020

#define MASK_THUMB2_INSN_BXJ		0xD000FFF0
#define PTRN_THUMB2_INSN_BXJ		0x8000F3C0


/*  software interrupts */
#define MASK_ARM_INSN_SWI		0x0F000000
#define PTRN_ARM_INSN_SWI		0x0F000000

#define MASK_THUMB_INSN_SWI		0xFF00
#define PTRN_THUMB_INSN_SWI		0xDF00

/*  break */
#define MASK_ARM_INSN_BREAK		0xFFF000F0
#define PTRN_ARM_INSN_BREAK		0xE1200070
/* A8-56 ARM DDI 046B if cond != ‘1110’ then UNPREDICTABLE; */

#define MASK_THUMB_INSN_BREAK		0xFF00
#define PTRN_THUMB_INSN_BREAK		0xBE00

/*  CLZ */
#define MASK_ARM_INSN_CLZ		0x0FFF0FF0
#define PTRN_ARM_INSN_CLZ		0x016F0F10

/*  Data processing immediate shift */
#define MASK_ARM_INSN_DPIS		0x0E000010
#define PTRN_ARM_INSN_DPIS		0x00000000
/*  Data processing register shift */
#define MASK_ARM_INSN_DPRS		0x0E000090
#define PTRN_ARM_INSN_DPRS		0x00000010

#define MASK_THUMB2_INSN_DPRS		0xFFE00000
#define PTRN_THUMB2_INSN_DPRS		0xEA000000

/*  Data processing immediate */
#define MASK_ARM_INSN_DPI		0x0E000000
#define PTRN_ARM_INSN_DPI		0x02000000

#define MASK_THUMB_INSN_DP		0xFC00
#define PTRN_THUMB_INSN_DP		0x4000

#define MASK_THUMB_INSN_APC		0xF800
#define PTRN_THUMB_INSN_APC		0xA000 /* ADD Rd, [PC, #<imm8> * 4] */

#define MASK_THUMB2_INSN_DPI		0xFBE08000
/* #define PTRN_THUMB2_INSN_DPI		0xF0000000 */
/* A6-19 ARM DDI 0406B */
#define PTRN_THUMB2_INSN_DPI		0xF2000000
/* A6-19 ARM DDI 0406B */

#define MASK_THUMB_INSN_MOV3	 0xFF00
#define PTRN_THUMB_INSN_MOV3	 0x4600	/* MOV Rd, PC */

#define MASK_THUMB2_INSN_RSBW	 0x8000fbe0
#define PTRN_THUMB2_INSN_RSBW	 0x0000f1c0 /* RSB{S}.W Rd,Rn,#<const> */

#define MASK_THUMB2_INSN_RORW	 0xf0f0ffe0
#define PTRN_THUMB2_INSN_RORW	 0xf000fa60 /* ROR{S}.W Rd, Rn, Rm */

#define MASK_THUMB2_INSN_ROR	 0x0030ffef
#define PTRN_THUMB2_INSN_ROR	 0x0030ea4f /* ROR{S} Rd, Rm, #<imm> */

#define MASK_THUMB2_INSN_LSLW1	 0xf0f0ffe0
#define PTRN_THUMB2_INSN_LSLW1	 0xf000fa00 /* LSL{S}.W Rd, Rn, Rm */

#define MASK_THUMB2_INSN_LSLW2	 0x0030ffef
#define PTRN_THUMB2_INSN_LSLW2	 0x0000ea4f /* LSL{S}.W Rd, Rm, #<imm5>*/

#define MASK_THUMB2_INSN_LSRW1	 0xf0f0ffe0
#define PTRN_THUMB2_INSN_LSRW1	 0xf000fa20 /* LSR{S}.W Rd, Rn, Rm */

#define MASK_THUMB2_INSN_LSRW2	 0x0030ffef
#define PTRN_THUMB2_INSN_LSRW2	 0x0010ea4f /* LSR{S}.W Rd, Rm, #<imm5> */

#define MASK_THUMB2_INSN_TEQ1	 0x8f00fbf0
#define PTRN_THUMB2_INSN_TEQ1	 0x0f00f090 /* TEQ Rn, #<const> */

#define MASK_THUMB2_INSN_TEQ2	 0x0f00fff0
#define PTRN_THUMB2_INSN_TEQ2	 0x0f00ea90 /* TEQ Rn, Rm{,<shift>} */

#define MASK_THUMB2_INSN_TST1	 0x8f00fbf0
#define PTRN_THUMB2_INSN_TST1	 0x0f00f010 /* TST Rn, #<const> */

#define MASK_THUMB2_INSN_TST2	 0x0f00fff0
#define PTRN_THUMB2_INSN_TST2	 0x0f00ea10 /* TST Rn, Rm{,<shift>} */


/*  Load immediate offset */
#define MASK_ARM_INSN_LIO	 0x0E100000
#define PTRN_ARM_INSN_LIO	 0x04100000

#define MASK_THUMB_INSN_LIO1	 0xF800
#define PTRN_THUMB_INSN_LIO1	 0x6800	    /* LDR */

#define MASK_THUMB_INSN_LIO2	 MASK_THUMB_INSN_LIO1
#define PTRN_THUMB_INSN_LIO2	 0x7800	    /* LDRB */

#define MASK_THUMB_INSN_LIO3	 MASK_THUMB_INSN_LIO1
#define PTRN_THUMB_INSN_LIO3	 0x8800	    /* LDRH */

#define MASK_THUMB_INSN_LIO4	 MASK_THUMB_INSN_LIO1
#define PTRN_THUMB_INSN_LIO4	 0x9800	    /* LDR SP relative */

#define MASK_THUMB2_INSN_LDRW	 0x0000fff0
#define PTRN_THUMB2_INSN_LDRW	 0x0000f850 /* LDR.W Rt, [Rn, #-<imm12>] */

#define MASK_THUMB2_INSN_LDRW1	 MASK_THUMB2_INSN_LDRW
#define PTRN_THUMB2_INSN_LDRW1	 0x0000f8d0 /* LDR.W Rt, [Rn, #<imm12>] */

#define MASK_THUMB2_INSN_LDRBW	 MASK_THUMB2_INSN_LDRW
#define PTRN_THUMB2_INSN_LDRBW	 0x0000f810 /* LDRB.W Rt, [Rn, #-<imm8>] */

#define MASK_THUMB2_INSN_LDRBW1 MASK_THUMB2_INSN_LDRW
#define PTRN_THUMB2_INSN_LDRBW1 0x0000f890 /* LDRB.W Rt, [Rn, #<imm12>] */

#define MASK_THUMB2_INSN_LDRHW	 MASK_THUMB2_INSN_LDRW
#define PTRN_THUMB2_INSN_LDRHW	 0x0000f830 /* LDRH.W Rt, [Rn, #-<imm8>] */

#define MASK_THUMB2_INSN_LDRHW1 MASK_THUMB2_INSN_LDRW
#define PTRN_THUMB2_INSN_LDRHW1 0x0000f8b0 /* LDRH.W Rt, [Rn, #<imm12>] */

#define MASK_THUMB2_INSN_LDRD	 0x0000fed0
#define PTRN_THUMB2_INSN_LDRD	 0x0000e850 /* LDRD Rt, Rt2, [Rn, #-<imm8>] */

#define MASK_THUMB2_INSN_LDRD1	 MASK_THUMB2_INSN_LDRD
#define PTRN_THUMB2_INSN_LDRD1	 0x0000e8d0 /* LDRD Rt, Rt2, [Rn, #<imm8>] */

#define MASK_THUMB2_INSN_LDRWL	 0x0fc0fff0
#define PTRN_THUMB2_INSN_LDRWL	 0x0000f850 /* LDR.W Rt, [Rn,Rm,LSL #<imm2>] */

#define MASK_THUMB2_INSN_LDREX	 0x0f00ffff
#define PTRN_THUMB2_INSN_LDREX	 0x0f00e85f /* LDREX Rt, [PC, #<imm8>] */

#define MASK_THUMB2_INSN_MUL	 0xf0f0fff0
#define PTRN_THUMB2_INSN_MUL	 0xf000fb00 /* MUL Rd, Rn, Rm */

#define MASK_THUMB2_INSN_DP 0x0000ff00
#define PTRN_THUMB2_INSN_DP 0x0000eb00 /* ADD/SUB/SBC/...Rd,Rn,Rm{,<shift>} */




/*  Store immediate offset */
#define MASK_ARM_INSN_SIO	MASK_ARM_INSN_LIO
#define PTRN_ARM_INSN_SIO	0x04000000

#define MASK_THUMB_INSN_SIO1	MASK_THUMB_INSN_LIO1
#define PTRN_THUMB_INSN_SIO1	0x6000	/* STR */

#define MASK_THUMB_INSN_SIO2	MASK_THUMB_INSN_LIO1
#define PTRN_THUMB_INSN_SIO2	0x7000	/* STRB */

#define MASK_THUMB_INSN_SIO3	MASK_THUMB_INSN_LIO1
#define PTRN_THUMB_INSN_SIO3	0x8000	/* STRH */

#define MASK_THUMB_INSN_SIO4	MASK_THUMB_INSN_LIO1
#define PTRN_THUMB_INSN_SIO4	0x9000	/* STR SP relative */

#define MASK_THUMB2_INSN_STRW	0x0fc0fff0
#define PTRN_THUMB2_INSN_STRW	0x0000f840 /* STR.W Rt,[Rn,Rm,{LSL #<imm2>}] */

#define MASK_THUMB2_INSN_STRW1	0x0000fff0
#define PTRN_THUMB2_INSN_STRW1	0x0000f8c0 /* STR.W Rt, [Rn, #imm12]
					    * STR.W Rt, [PC, #imm12] shall be
					    * skipped, because it hangs
					    * on Tegra. WTF */

#define MASK_THUMB2_INSN_STRHW	MASK_THUMB2_INSN_STRW
#define PTRN_THUMB2_INSN_STRHW	0x0000f820 /* STRH.W Rt,[Rn,Rm,{LSL #<imm2>}] */

#define MASK_THUMB2_INSN_STRHW1	0x0000fff0
#define PTRN_THUMB2_INSN_STRHW1	0x0000f8a0 /* STRH.W Rt, [Rn, #<imm12>] */

#define MASK_THUMB2_INSN_STRHT	0x0f00fff0 /*  strht r1, [pc, #imm] illegal
					    * instruction on Tegra. WTF */
#define PTRN_THUMB2_INSN_STRHT	0x0e00f820 /* STRHT Rt, [Rn, #<imm8>] */

#define MASK_THUMB2_INSN_STRT	0x0f00fff0
#define PTRN_THUMB2_INSN_STRT	0x0e00f840 /* STRT Rt, [Rn, #<imm8>] */

#define MASK_THUMB2_INSN_STRBW	MASK_THUMB2_INSN_STRW
#define PTRN_THUMB2_INSN_STRBW	0x0000f800 /* STRB.W Rt,[Rn,Rm,{LSL #<imm2>}] */

#define MASK_THUMB2_INSN_STRBW1	0x0000fff0
#define PTRN_THUMB2_INSN_STRBW1	0x0000f880 /* STRB.W Rt, [Rn, #<imm12>]
					    * STRB.W Rt, [PC, #imm12] shall be
					    * skipped, because it hangs
					    * on Tegra. WTF */

#define MASK_THUMB2_INSN_STRBT	0x0f00fff0
#define PTRN_THUMB2_INSN_STRBT	0x0e00f800 /* STRBT Rt, [Rn, #<imm8>}] */

#define MASK_THUMB2_INSN_STRD	0x0000fe50
/* STR{D,EX,EXB,EXH,EXD} Rt, Rt2, [Rn, #<imm8>] */
#define PTRN_THUMB2_INSN_STRD	0x0000e840


/*  Load register offset */
#define MASK_ARM_INSN_LRO	0x0E100010
#define PTRN_ARM_INSN_LRO	0x06100000

#define MASK_THUMB_INSN_LRO1	0xFE00
#define PTRN_THUMB_INSN_LRO1	0x5600		/* LDRSB */

#define MASK_THUMB_INSN_LRO2	MASK_THUMB_INSN_LRO1
#define PTRN_THUMB_INSN_LRO2	0x5800		/* LDR */

#define MASK_THUMB_INSN_LRO3	0xf800
#define PTRN_THUMB_INSN_LRO3	0x4800		/* LDR Rd, [PC, #<imm8> * 4] */

#define MASK_THUMB_INSN_LRO4	MASK_THUMB_INSN_LRO1
#define PTRN_THUMB_INSN_LRO4	0x5A00		/* LDRH */

#define MASK_THUMB_INSN_LRO5	MASK_THUMB_INSN_LRO1
#define PTRN_THUMB_INSN_LRO5	0x5C00		/* LDRB */

#define MASK_THUMB_INSN_LRO6	MASK_THUMB_INSN_LRO1
#define PTRN_THUMB_INSN_LRO6	0x5E00		/* LDRSH */

#define MASK_THUMB2_INSN_ADR	0x8000fa1f
#define PTRN_THUMB2_INSN_ADR	0x0000f20f



/*  Store register offset */
#define MASK_ARM_INSN_SRO	MASK_ARM_INSN_LRO
#define PTRN_ARM_INSN_SRO	0x06000000

#define MASK_THUMB_INSN_SRO1	MASK_THUMB_INSN_LRO1
#define PTRN_THUMB_INSN_SRO1	0x5000		/* STR */

#define MASK_THUMB_INSN_SRO2	MASK_THUMB_INSN_LRO1
#define PTRN_THUMB_INSN_SRO2	0x5200		/* STRH */

#define MASK_THUMB_INSN_SRO3	MASK_THUMB_INSN_LRO1
#define PTRN_THUMB_INSN_SRO3	0x5400		/* STRB */

/*  Load multiple */
#define MASK_ARM_INSN_LM	0x0E100000
#define PTRN_ARM_INSN_LM	0x08100000

#define MASK_THUMB2_INSN_LDMIA	0x8000ffd0
#define PTRN_THUMB2_INSN_LDMIA	0x8000e890	/* LDMIA(.W) Rn(!),{Rx-PC} */

#define MASK_THUMB2_INSN_LDMDB	0x8000ffd0
#define PTRN_THUMB2_INSN_LDMDB	0x8000e910	/* LDMDB(.W) Rn(!), {Rx-PC} */

/*  Store multiple */
#define MASK_ARM_INSN_SM	MASK_ARM_INSN_LM
#define PTRN_ARM_INSN_SM	0x08000000


/*  Coprocessor load/store and double register transfers */
#define MASK_ARM_INSN_CLS	0x0E000000
#define PTRN_ARM_INSN_CLS	0x0C000000
/*  Coprocessor register transfers */
#define MASK_ARM_INSN_CRT	0x0F000010
#define PTRN_ARM_INSN_CRT	0x0E000010

#define ARM_INSN_MATCH(name, insn) \
	((insn & MASK_ARM_INSN_##name) == PTRN_ARM_INSN_##name)
#define THUMB_INSN_MATCH(name, insn) \
	(((insn & 0x0000FFFF) & MASK_THUMB_INSN_##name) == \
	 PTRN_THUMB_INSN_##name)
#define THUMB2_INSN_MATCH(name, insn) \
	((insn & MASK_THUMB2_INSN_##name) == PTRN_THUMB2_INSN_##name)

#define ARM_INSN_REG_RN(insn) \
	((insn & 0x000F0000)>>16)

#define ARM_INSN_REG_SET_RN(insn, nreg) \
	{ insn &= ~0x000F0000; insn |= nreg<<16; }

#define ARM_INSN_REG_RD(insn) \
	((insn & 0x0000F000)>>12)

#define ARM_INSN_REG_SET_RD(insn, nreg) \
	{ insn &= ~0x0000F000; insn |= nreg<<12; }

#define ARM_INSN_REG_RS(insn) \
	((insn & 0x00000F00)>>8)

#define ARM_INSN_REG_SET_RS(insn, nreg) \
	{ insn &= ~0x00000F00; insn |= nreg<<8; }

#define ARM_INSN_REG_RM(insn) \
	(insn & 0x0000000F)

#define ARM_INSN_REG_SET_RM(insn, nreg) \
	{ insn &= ~0x0000000F; insn |= nreg; }

#define ARM_INSN_REG_MR(insn, nreg) \
	(insn & (1 << nreg))

#define ARM_INSN_REG_SET_MR(insn, nreg) \
	{ insn |= (1 << nreg); }

#define ARM_INSN_REG_CLEAR_MR(insn, nreg) \
	{ insn &= ~(1 << nreg); }

#define THUMB2_INSN_REG_RT(insn)  ((insn & 0xf0000000) >> 28)
#define THUMB2_INSN_REG_RT2(insn) ((insn & 0x0f000000) >> 24)
#define THUMB2_INSN_REG_RN(insn)  (insn & 0x0000000f)
#define THUMB2_INSN_REG_RD(insn)  ((insn & 0x0f000000) >> 24)
#define THUMB2_INSN_REG_RM(insn)  ((insn & 0x000f0000) >> 16)




/**
 * @struct kprobe_ctlblk
 * @brief Per-cpu kprobe control block.
 * @var kprobe_ctlblk::kprobe_status
 * Kprobe status.
 * @var kprobe_ctlblk::prev_kprobe
 * Previous kprobe.
 */
struct kprobe_ctlblk {
	unsigned long kprobe_status;
	struct prev_kprobe prev_kprobe;
};

/**
 * @struct arch_specific_insn
 * @brief Architecture specific copy of original instruction.
 * @var arch_specific_insn::insn
 * Copy of the original instruction.
 */
struct arch_specific_insn {
	kprobe_opcode_t *insn;
};

typedef kprobe_opcode_t (*entry_point_t) (unsigned long, unsigned long,
					  unsigned long, unsigned long,
					  unsigned long, unsigned long);

struct undef_hook;

void swap_register_undef_hook(struct undef_hook *hook);
void swap_unregister_undef_hook(struct undef_hook *hook);

int arch_init_module_deps(void);

int arch_make_trampoline_arm(unsigned long addr, unsigned long insn,
			     unsigned long *tramp);

struct slot_manager;
struct kretprobe;
struct kretprobe_instance;
int swap_arch_prepare_kprobe(struct kprobe *p, struct slot_manager *sm);
void swap_arch_prepare_kretprobe(struct kretprobe_instance *ri,
				 struct pt_regs *regs);

void swap_arch_arm_kprobe(struct kprobe *p);
void swap_arch_disarm_kprobe(struct kprobe *p);

int swap_setjmp_pre_handler(struct kprobe *p, struct pt_regs *regs);
int swap_longjmp_break_handler(struct kprobe *p, struct pt_regs *regs);

void save_previous_kprobe(struct kprobe_ctlblk *kcb, struct kprobe *cur_p);
void restore_previous_kprobe(struct kprobe_ctlblk *kcb);
void set_current_kprobe(struct kprobe *p,
			struct pt_regs *regs,
			struct kprobe_ctlblk *kcb);

void __naked swap_kretprobe_trampoline(void);

/**
 * @brief Gets arguments of kernel functions.
 *
 * @param regs Pointer to CPU registers data.
 * @param n Number of the argument.
 * @return Argument value.
 */
static inline unsigned long swap_get_karg(struct pt_regs *regs, unsigned long n)
{
	switch (n) {
	case 0:
		return regs->ARM_r0;
	case 1:
		return regs->ARM_r1;
	case 2:
		return regs->ARM_r2;
	case 3:
		return regs->ARM_r3;
	}

	return *((unsigned long *)regs->ARM_sp + n - 4);
}

/**
 * @brief swap_get_karg wrapper.
 *
 * @param regs Pointer to CPU registers data.
 * @param n Number of the argument.
 * @return Argument value.
 */
static inline unsigned long swap_get_sarg(struct pt_regs *regs, unsigned long n)
{
	return swap_get_karg(regs, n);
}

/* jumper */
typedef unsigned long (*jumper_cb_t)(void *);

int set_kjump_cb(struct pt_regs *regs, jumper_cb_t cb,
		 void *data, size_t size);

unsigned long get_jump_addr(void);
int set_jump_cb(unsigned long ret_addr, struct pt_regs *regs,
		jumper_cb_t cb, void *data, size_t size);

int swap_arch_init_kprobes(void);
void swap_arch_exit_kprobes(void);

/* void gen_insn_execbuf (void); */
/* void pc_dep_insn_execbuf (void); */
/* void gen_insn_execbuf_holder (void); */
/* void pc_dep_insn_execbuf_holder (void); */

#endif /* _SWAP_ASM_ARM_KPROBES_H */
