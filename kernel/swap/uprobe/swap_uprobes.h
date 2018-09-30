/**
 * @file uprobe/swap_uprobes.h
 * @author Alexey Gerenkov <a.gerenkov@samsung.com> User-Space Probes initial
 * implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * @author Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for
 * separating core and arch parts
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
 * Uprobes interface declaration.
 */

#ifndef _SWAP_UPROBES_H
#define _SWAP_UPROBES_H


#include <kprobe/swap_kprobes.h>

#include <swap-asm/swap_uprobes.h>


/**
 * @struct uprobe
 * @brief Stores uprobe data, based on kprobe.
 */
struct uprobe {
	struct kprobe kp;                   /**< Kprobe for this uprobe */
	struct task_struct *task;           /**< Pointer to the task struct */
	struct slot_manager *sm;            /**< Pointer to slot manager */
	struct arch_specific_tramp atramp;  /**< Stores trampoline */
	bool atomic_ctx;                    /**< Handler context */
};

struct uinst_info {
	struct hlist_node hlist;

	unsigned long vaddr;
	kprobe_opcode_t	opcode;
};

struct urinst_info {
	struct hlist_node hlist;

	struct task_struct *task;
	unsigned long sp;
	unsigned long tramp;
	unsigned long ret_addr;
};

struct uinst_info *uinst_info_create(unsigned long vaddr,
				     kprobe_opcode_t opcode);
void uinst_info_destroy(struct uinst_info *uinst);
void uinst_info_disarm(struct uinst_info *uinst, struct task_struct *task);


void urinst_info_get_current_hlist(struct hlist_head *head, bool recycle);
void urinst_info_put_current_hlist(struct hlist_head *head,
				  struct task_struct *task);


/**
 * @brief Uprobe pre-entry handler.
 */
typedef unsigned long (*uprobe_pre_entry_handler_t)(void *priv_arg,
						    struct pt_regs *regs);

/**
 * @struct ujprobe
 * @brief Stores ujprobe data, based on uprobe.
 */
struct ujprobe {
	struct uprobe up;       /**< Uprobe for this ujprobe */
	void *entry;		/**< Probe handling code to jump to */
	/** Handler which will be called before 'entry' */
	uprobe_pre_entry_handler_t pre_entry;
	void *priv_arg;         /**< Private args for handler */
	char *args;             /**< Function args format string */
};

struct uretprobe_instance;

/**
 * @brief Uretprobe handler.
 */
typedef int (*uretprobe_handler_t)(struct uretprobe_instance *,
				   struct pt_regs *);

/**
 * @strict uretprobe
 * @brief Function-return probe.
 *
 * Note:
 * User needs to provide a handler function, and initialize maxactive.
 */
struct uretprobe {
	struct uprobe up;                   /**< Uprobe for this uretprobe */
	uretprobe_handler_t handler;        /**< Uretprobe handler */
	uretprobe_handler_t entry_handler;  /**< Uretprobe entry handler */
	/** Maximum number of instances of the probed function that can be
	 * active concurrently. */
	int maxactive;
	/** Tracks the number of times the probed function's return was
	 * ignored, due to maxactive being too low. */
	int nmissed;
	size_t data_size;                   /**< Instance data size */
	struct hlist_head free_instances;   /**< Free instances list */
	struct hlist_head used_instances;   /**< Used instances list */

#ifdef CONFIG_ARM
	unsigned arm_noret:1;               /**< No-return flag for ARM */
	unsigned thumb_noret:1;             /**< No-return flag for Thumb */
#endif
};

/**
 * @struct uretprobe_instance
 * @brief Structure for each uretprobe instance.
 */
struct uretprobe_instance {
	/* either on free list or used list */
	struct hlist_node uflist;           /**< Free list */
	struct hlist_node hlist;            /**< Used list */
	struct uretprobe *rp;               /**< Pointer to the parent uretprobe */
	kprobe_opcode_t *ret_addr;          /**< Return address */
	kprobe_opcode_t *sp;                /**< Pointer to stack */
	struct task_struct *task;           /**< Pointer to the task struct */
#ifdef CONFIG_ARM
	/* FIXME Preload: if this flag is set then ignore the thumb_mode(regs)
	 * check in arch_prepare_uretprobe and use thumb trampoline. For the
	 * moment we have to explicitly force arm mode when jumping to preload
	 * handlers but we need the correct (i.e. original) retprobe tramp set
	 * anyway. */
	int preload_thumb;
#endif
	char data[0];                       /**< Custom data */
};

int swap_register_uprobe(struct uprobe *p);
void swap_unregister_uprobe(struct uprobe *p);
void __swap_unregister_uprobe(struct uprobe *up, int disarm);

int swap_register_ujprobe(struct ujprobe *jp);
void swap_unregister_ujprobe(struct ujprobe *jp);
void __swap_unregister_ujprobe(struct ujprobe *jp, int disarm);

int swap_register_uretprobe(struct uretprobe *rp);
void swap_unregister_uretprobe(struct uretprobe *rp);
void __swap_unregister_uretprobe(struct uretprobe *rp, int disarm);

void swap_unregister_all_uprobes(struct task_struct *task);

void swap_ujprobe_return(void);
struct kprobe *get_ukprobe(void *addr, pid_t tgid);
struct kprobe *get_ukprobe_by_insn_slot(void *addr,
					pid_t tgid,
					struct pt_regs *regs);

static inline struct uprobe *kp2up(struct kprobe *p)
{
	return container_of(p, struct uprobe, kp);
}

static inline struct kprobe *up2kp(struct uprobe *p)
{
	return &p->kp;
}

void disarm_uprobe(struct kprobe *p, struct task_struct *task);

int trampoline_uprobe_handler(struct kprobe *p, struct pt_regs *regs);

void add_uprobe_table(struct kprobe *p);

#endif /*  _SWAP_UPROBES_H */
