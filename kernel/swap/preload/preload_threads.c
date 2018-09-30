#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/list.h>
#include <task_data/task_data.h>
#include "preload.h"
#include "preload_threads.h"
#include "preload_debugfs.h"
#include "preload_pd.h"

struct preload_td {
	struct list_head slots;
	unsigned long flags;
};

struct thread_slot {
	struct list_head list;
	struct list_head disabled_addrs;

	unsigned long caller;
	unsigned char call_type;
	bool drop;   /* TODO Workaround, remove when will be possible to install
		      * several us probes at the same addr. */
};

struct disabled_addr {
	struct list_head list;
	unsigned long addr;
};

static inline struct preload_td *get_preload_td(struct task_struct *task)
{
	struct preload_td *td = NULL;
	int ok;

	td = swap_task_data_get(task, &ok);
	WARN(!ok, "Preload td[%d/%d] seems corrupted", task->tgid, task->pid);

	if (!td) {
		td = kzalloc(sizeof(*td), GFP_ATOMIC);
		WARN(!td, "Failed to allocate preload_td");

		if (td) {
			INIT_LIST_HEAD(&td->slots);
			/* We use SWAP_TD_FREE flag, i.e. the data will be
			 * kfree'd by task_data module. */
			swap_task_data_set(task, td, SWAP_TD_FREE);
		}
	}

	return td;
}

unsigned long get_preload_flags(struct task_struct *task)
{
	struct preload_td *td = get_preload_td(task);

	if (td == NULL)
		return 0;

	return td->flags;
}

void set_preload_flags(struct task_struct *task,
		       unsigned long flags)
{
	struct preload_td *td = get_preload_td(task);

	if (td == NULL) {
		printk(KERN_ERR "%s: invalid arguments\n", __FUNCTION__);
		return;
	}

	td->flags = flags;
}


static inline bool __is_addr_found(struct disabled_addr *da,
				   unsigned long addr)
{
	if (da->addr == addr)
		return true;

	return false;
}

static inline void __remove_from_disable_list(struct disabled_addr *da)
{
	list_del(&da->list);
	kfree(da);
}

static inline void __remove_whole_disable_list(struct thread_slot *slot)
{
	struct disabled_addr *da, *n;

	list_for_each_entry_safe(da, n, &slot->disabled_addrs, list)
		__remove_from_disable_list(da);
}

static inline void __init_slot(struct thread_slot *slot)
{
	slot->caller = 0;
	slot->call_type = 0;
	slot->drop = false;
	INIT_LIST_HEAD(&slot->disabled_addrs);
}

static inline void __reinit_slot(struct thread_slot *slot)
{
	__remove_whole_disable_list(slot);
	__init_slot(slot);
}

static inline void __set_slot(struct thread_slot *slot,
			      struct task_struct *task, unsigned long caller,
			      unsigned char call_type, bool drop)
{
	slot->caller = caller;
	slot->call_type = call_type;
	slot->drop = drop;
}

static inline int __add_to_disable_list(struct thread_slot *slot,
					unsigned long disable_addr)
{
	struct disabled_addr *da = kmalloc(sizeof(*da), GFP_ATOMIC);

	if (da == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&da->list);
	da->addr = disable_addr;
	list_add_tail(&da->list, &slot->disabled_addrs);

	return 0;
}

static inline struct disabled_addr *__find_disabled_addr(struct thread_slot *slot,
							 unsigned long addr)
{
	struct disabled_addr *da;

	list_for_each_entry(da, &slot->disabled_addrs, list)
		if (__is_addr_found(da, addr))
			return da;

	return NULL;
}

/* Adds a new slot */
static inline struct thread_slot *__grow_slot(void)
{
	struct thread_slot *tmp = kmalloc(sizeof(*tmp), GFP_ATOMIC);

	if (tmp == NULL)
		return NULL;

	INIT_LIST_HEAD(&tmp->list);
	__init_slot(tmp);

	return tmp;
}

/* Free slot */
static void __clean_slot(struct thread_slot *slot)
{
	list_del(&slot->list);
	kfree(slot);
}

/* There is no list_last_entry in Linux 3.10 */
#ifndef list_last_entry
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)
#endif /* list_last_entry */

static inline struct thread_slot *__get_task_slot(struct task_struct *task)
{
	struct preload_td *td = get_preload_td(task);

	if (td == NULL)
		return NULL;

	return list_empty(&td->slots) ? NULL :
		list_last_entry(&td->slots, struct thread_slot, list);
}




int preload_threads_set_data(struct task_struct *task, unsigned long caller,
			     unsigned char call_type,
			     unsigned long disable_addr, bool drop)
{
	struct preload_td *td = get_preload_td(task);
	struct thread_slot *slot;
	int ret = 0;

	slot = __grow_slot();
	if (slot == NULL) {
		ret = -ENOMEM;
		goto set_data_done;
	}

	if ((disable_addr != 0) &&
	    (__add_to_disable_list(slot, disable_addr) != 0)) {
		printk(KERN_ERR PRELOAD_PREFIX "Cannot alloc memory!\n");
		ret = -ENOMEM;
		goto set_data_done;
	}

	__set_slot(slot, task, caller, call_type, drop);
	list_add_tail(&slot->list, &td->slots);

set_data_done:
	return ret;
}

int preload_threads_get_caller(struct task_struct *task, unsigned long *caller)
{
	struct thread_slot *slot;
	int ret = 0;

	slot = __get_task_slot(task);
	if (slot != NULL) {
		*caller = slot->caller;
		goto get_caller_done;
	}

	/* If we're here - slot was not found */
	ret = -EINVAL;

get_caller_done:
	return ret;
}

int preload_threads_get_call_type(struct task_struct *task,
				  unsigned char *call_type)
{
	struct thread_slot *slot;
	int ret = 0;

	slot = __get_task_slot(task);
	if (slot != NULL) {
		*call_type = slot->call_type;
		goto get_call_type_done;
	}

	/* If we're here - slot was not found */
	ret = -EINVAL;

get_call_type_done:
	return ret;
}

int preload_threads_get_drop(struct task_struct *task)
{
	struct thread_slot *slot;
	int ret = 0;

	slot = __get_task_slot(task);
	if (slot != NULL) {
		ret = (int) slot->drop;
		goto get_drop_done;
	}

	/* If we're here - slot was not found */
	ret = -EINVAL;

get_drop_done:
	return ret;
}

bool preload_threads_check_disabled_probe(struct task_struct *task,
					  unsigned long addr)
{
	struct thread_slot *slot;
	bool ret = false;

	slot = __get_task_slot(task);
	if (slot != NULL)
		ret = __find_disabled_addr(slot, addr) == NULL ? false : true;

	return ret;
}

void preload_threads_enable_probe(struct task_struct *task, unsigned long addr)
{
	struct thread_slot *slot;
	struct disabled_addr *da;

	slot = __get_task_slot(task);
	if (slot == NULL) {
		printk(KERN_ERR PRELOAD_PREFIX "Error! Slot not found!\n");
		goto enable_probe_failed;
	}

	da = __find_disabled_addr(slot, addr);
	if (da != NULL)
		__remove_from_disable_list(da);

enable_probe_failed:
	return; /* make gcc happy: cannot place label right before '}' */
}

int preload_threads_put_data(struct task_struct *task)
{
	struct thread_slot *slot;
	int ret = 0;

	slot = __get_task_slot(task);
	if (slot != NULL) {
		__reinit_slot(slot);
		__clean_slot(slot); /* remove from list */
		goto put_data_done;
	}

put_data_done:
	return ret;
}

int preload_threads_init(void)
{
	return 0;
}

void preload_threads_exit(void)
{
}
