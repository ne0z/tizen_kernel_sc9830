#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <kprobe/swap_kprobes.h>
#include <ksyms/ksyms.h>
#include <master/swap_initializer.h>
#include <us_manager/callbacks.h>
#include "task_data.h"

/* lower bits are used as flags */
#define TD_MAGIC_MASK 0xfffffff0
#define TD_FLAGS_MASK (~TD_MAGIC_MASK)

#define __DEFINE_TD_MAGIC(m) ((m) & TD_MAGIC_MASK)

#define TD_MAGIC __DEFINE_TD_MAGIC(0xbebebebe)
#define TD_OFFSET 1  /* skip STACK_END_MAGIC */
#define TD_PREFIX "[TASK_DATA] "

struct task_data {
	void *data;
	unsigned long magic;
} __attribute__((packed));

#define get_magic(td) ((td)->magic & TD_MAGIC_MASK)
#define get_flags(td) ((td)->magic & TD_FLAGS_MASK)

static int __task_data_cbs_start_h = -1;
static int __task_data_cbs_stop_h = -1;

static inline struct task_data *__td(struct task_struct *task)
{
	return (struct task_data *)(end_of_stack(task) + TD_OFFSET);
}

static inline bool __td_check(struct task_data *td)
{
	return (get_magic(td) == TD_MAGIC);
}

static inline void __td_init(struct task_data *td, void *data,
			     unsigned long flags)
{
	td->magic = TD_MAGIC | (flags & TD_FLAGS_MASK);
	td->data = data;
}

static inline void __td_free(struct task_data *td)
{
	unsigned long flags = get_flags(td);
	bool ok = __td_check(td);

	/* freeing the data if consistency check fails is dangerous:
	 * better leave it as a memory leak instead */
	if (ok) {
		if ((flags & SWAP_TD_FREE) && td->data)
			kfree(td->data);
		td->magic = 0;
		td->data = NULL;
		return;
	}
}

void *swap_task_data_get(struct task_struct *task, int *ok)
{
	struct task_data *td = __td(task);

	if (ok)
		*ok = __td_check(td);

	return td->data;
}
EXPORT_SYMBOL_GPL(swap_task_data_get);

void swap_task_data_set(struct task_struct *task, void *data,
			unsigned long flags)
{
	struct task_data *td = __td(task);

	__td_init(td, data, flags);
}
EXPORT_SYMBOL_GPL(swap_task_data_set);


static atomic_t start_flag = ATOMIC_INIT(0);

static int copy_process_ret_handler(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct task_struct *task;

	if (atomic_read(&start_flag) == 0)
		return 0;

	task = (struct task_struct *)regs_return_value(regs);
	if (!IS_ERR(task))
		swap_task_data_clean(task);

	return 0;
}

static int do_exit_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct task_data *td;

	if (atomic_read(&start_flag) == 0)
		return 0;

	td = __td(current);
	__td_free(td);

	return 0;
}

static struct kretprobe copy_process_rp = {
	.handler = copy_process_ret_handler
};

static struct kprobe do_exit_probe = {
	.pre_handler = do_exit_handler
};

static int __task_data_init(void *data)
{
	struct task_struct *g, *t;

	/* set start_flags */
	atomic_set(&start_flag, 1);

	do_each_thread(g, t) {
		swap_task_data_clean(t);
	} while_each_thread(g, t);

	return 0;
}

static int __task_data_exit(void *data)
{
	struct task_struct *g, *t;
	struct task_data *td;

	do_each_thread(g, t) {
		td = __td(t);
		__td_free(td);
	} while_each_thread(g, t);

	/* reset start_flags */
	atomic_set(&start_flag, 0);

	return 0;
}

static void task_data_start(void)
{
	int ret;

	ret = swap_register_kprobe(&do_exit_probe);
	if (ret) {
		pr_err(TD_PREFIX "register on 'do_exit' failed: ret=%d\n", ret);
		return;
	}

	ret = swap_register_kretprobe(&copy_process_rp);
	if (ret) {
		swap_unregister_kprobe(&do_exit_probe);
		pr_err(TD_PREFIX "register on 'copy_process' failed: ret=%d\n", ret);
		return;
	}

	/* stop_machine: cannot get tasklist_lock from module */
	ret = stop_machine(__task_data_init, NULL, NULL);
	if (ret)
		printk(TD_PREFIX "task data initialization failed: %d\n", ret);
}

static void task_data_stop(void)
{
	int ret;

	/* stop_machine: the same here */
	ret = stop_machine(__task_data_exit, NULL, NULL);
	if (ret) {
		printk(TD_PREFIX "task data cleanup failed: %d\n", ret);
		/* something went wrong: at least make sure we unregister
		 * all the installed probes */
		swap_unregister_kprobe(&do_exit_probe);
	}

	swap_unregister_kretprobe(&copy_process_rp);
	swap_unregister_kprobe(&do_exit_probe);
}

static int task_data_once(void)
{
	const char *sym;

	sym = "copy_process";
	copy_process_rp.kp.addr = (kprobe_opcode_t *)swap_ksyms_substr(sym);
	if (copy_process_rp.kp.addr == NULL)
		goto not_found;

	sym = "do_exit";
	do_exit_probe.addr = (kprobe_opcode_t *)swap_ksyms_substr(sym);
	if (do_exit_probe.addr == NULL)
		goto not_found;

	return 0;

not_found:
	pr_err(TD_PREFIX "ERROR: symbol %s(...) not found\n", sym);
	return -ESRCH;
}

static int task_data_init(void)
{
	int ret = 0;

	__task_data_cbs_start_h = us_manager_reg_cb(START_CB, task_data_start);
	if (__task_data_cbs_start_h < 0) {
		ret = __task_data_cbs_start_h;
		printk(KERN_ERR TD_PREFIX "start_cb registration failed\n");
		goto out;
	}

	__task_data_cbs_stop_h = us_manager_reg_cb(STOP_CB_TD, task_data_stop);
	if (__task_data_cbs_stop_h < 0) {
		ret = __task_data_cbs_stop_h;
		us_manager_unreg_cb(__task_data_cbs_start_h);
		printk(KERN_ERR TD_PREFIX "stop_cb registration failed\n");
	}

out:
	return ret;
}

static void task_data_exit(void)
{
	us_manager_unreg_cb(__task_data_cbs_start_h);
	us_manager_unreg_cb(__task_data_cbs_stop_h);
}

SWAP_LIGHT_INIT_MODULE(task_data_once, task_data_init, task_data_exit,
		       NULL, NULL);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP Task Data Module");
