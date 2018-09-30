#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <kprobe/swap_kprobes.h>
#include <kprobe/swap_kprobes_deps.h>
#include <us_manager/us_manager_common.h>
#include <us_manager/pf/pf_group.h>
#include <us_manager/sspt/sspt_page.h>
#include <us_manager/sspt/sspt_file.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/sspt/ip.h>
#include <us_manager/callbacks.h>
#include <us_manager/probes/probe_info_new.h>
#include <writer/kernel_operations.h>
#include <master/swap_initializer.h>
#include <writer/swap_msg.h>
#include "uihv.h"
#include "preload.h"
#include "preload_probe.h"
#include "preload_debugfs.h"
#include "preload_module.h"
#include "preload_storage.h"
#include "preload_control.h"
#include "preload_threads.h"
#include "preload_pd.h"

#define page_to_proc(page) ((page)->file->proc)
#define page_to_dentry(page) ((page)->file->dentry)
#define ip_to_proc(ip) page_to_proc((ip)->page)

struct us_priv {
	struct pt_regs regs;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long raddr;
	unsigned long origin;
};

static atomic_t dentry_balance = ATOMIC_INIT(0);

enum preload_status_t {
	SWAP_PRELOAD_NOT_READY = 0,
	SWAP_PRELOAD_READY = 1,
	SWAP_PRELOAD_RUNNING = 2
};

enum {
	/* task preload flags */
	HANDLER_RUNNING = 0x1
};

static enum preload_status_t __preload_status = SWAP_PRELOAD_NOT_READY;

static int __preload_cbs_start_h = -1;
static int __preload_cbs_stop_h = -1;

static inline struct process_data *__get_process_data(struct uretprobe *rp)
{
	struct us_ip *ip = to_us_ip(rp);
	struct sspt_proc *proc = ip_to_proc(ip);

	return preload_pd_get(proc);
}

static struct dentry *__get_dentry(struct dentry *dentry)
{
	atomic_inc(&dentry_balance);
	return dget(dentry);
}



bool preload_module_is_running(void)
{
	if (__preload_status == SWAP_PRELOAD_RUNNING)
		return true;

	return false;
}

bool preload_module_is_ready(void)
{
	if (__preload_status == SWAP_PRELOAD_READY)
		return true;

	return false;
}

bool preload_module_is_not_ready(void)
{
	if (__preload_status == SWAP_PRELOAD_NOT_READY)
		return true;

	return false;
}

void preload_module_set_ready(void)
{
	__preload_status = SWAP_PRELOAD_READY;
}

void preload_module_set_running(void)
{
	__preload_status = SWAP_PRELOAD_RUNNING;
}

void preload_module_set_not_ready(void)
{
	__preload_status = SWAP_PRELOAD_NOT_READY;
}

struct dentry *get_dentry(const char *filepath)
{
	struct path path;
	struct dentry *dentry = NULL;

	if (kern_path(filepath, LOOKUP_FOLLOW, &path) == 0) {
		dentry = __get_dentry(path.dentry);
		path_put(&path);
	}

	return dentry;
}

void put_dentry(struct dentry *dentry)
{
	atomic_dec(&dentry_balance);
	dput(dentry);
}

static inline void __prepare_ujump(struct uretprobe_instance *ri,
				   struct pt_regs *regs,
				   unsigned long vaddr)
{
	ri->rp->up.kp.ss_addr[smp_processor_id()] = (kprobe_opcode_t *)vaddr;

#ifdef CONFIG_ARM
	if (thumb_mode(regs)) {
		regs->ARM_cpsr &= ~PSR_T_BIT;
		ri->preload_thumb = 1;
	}
#endif /* CONFIG_ARM */
}

static inline int __push(struct pt_regs *regs, void *buf, size_t len)
{
	unsigned long sp = swap_get_stack_ptr(regs) - len;

	sp = PTR_ALIGN(sp, sizeof(unsigned long));
	if (copy_to_user((void __user *)sp, buf, len))
		return -EIO;
	swap_set_stack_ptr(regs, sp);

	return 0;
}

static inline void __save_uregs(struct uretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct us_priv *priv = (struct us_priv *)ri->data;

	memcpy(ri->data, regs, sizeof(*regs));
	priv->arg0 = swap_get_arg(regs, 0);
	priv->arg1 = swap_get_arg(regs, 1);
	priv->raddr = swap_get_ret_addr(regs);
}

static inline void __restore_uregs(struct uretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct us_priv *priv = (struct us_priv *)ri->data;

	memcpy(regs, ri->data, sizeof(*regs));
	swap_set_arg(regs, 0, priv->arg0);
	swap_set_arg(regs, 1, priv->arg1);
	swap_set_ret_addr(regs, priv->raddr);
#ifndef CONFIG_ARM
	/* need to do it only on x86 */
	regs->EREG(ip) -= 1;
#endif /* !CONFIG_ARM */
	/* we have just restored the registers => no need to do it in
	 * trampoline_uprobe_handler */
	ri->ret_addr = NULL;
}

static inline void print_regs(const char *prefix, struct pt_regs *regs,
			      struct uretprobe_instance *ri)
{
#ifdef CONFIG_ARM
	printk(PRELOAD_PREFIX "%s[%d/%d] (%d) %s addr(%08lx), "
	       "r0(%08lx), r1(%08lx), r2(%08lx), r3(%08lx), "
	       "r4(%08lx), r5(%08lx), r6(%08lx), r7(%08lx), "
	       "sp(%08lx), lr(%08lx), pc(%08lx)\n",
	       current->comm, current->tgid, current->pid,
	       (int)preload_pd_get_state(__get_process_data(ri->rp)),
	       prefix, (unsigned long)ri->rp->up.kp.addr,
	       regs->ARM_r0, regs->ARM_r1, regs->ARM_r2, regs->ARM_r3,
	       regs->ARM_r4, regs->ARM_r5, regs->ARM_r6, regs->ARM_r7,
	       regs->ARM_sp, regs->ARM_lr, regs->ARM_pc);
#else /* !CONFIG_ARM */
	printk(PRELOAD_PREFIX "%s[%d/%d] (%d) %s addr(%08lx), "
	       "ip(%08lx), arg0(%08lx), arg1(%08lx), raddr(%08lx)\n",
	       current->comm, current->tgid, current->pid,
	       (int)preload_pd_get_state(__get_process_data(ri->rp)),
	       prefix, (unsigned long)ri->rp->up.kp.addr,
	       regs->EREG(ip), swap_get_arg(regs, 0), swap_get_arg(regs, 1),
	       swap_get_ret_addr(regs));
#endif /* CONFIG_ARM */
}

static inline unsigned long __get_r_debug_off(struct vm_area_struct *linker_vma)
{
	unsigned long start_addr;
	unsigned long offset = preload_debugfs_r_debug_offset();

	if (linker_vma == NULL)
		return 0;

	start_addr = linker_vma->vm_start;

	return (offset ? start_addr + offset : 0);
}

static struct vm_area_struct *__get_linker_vma(struct task_struct *task)
{
	struct vm_area_struct *vma = NULL;
	struct bin_info *ld_info;

	ld_info = preload_storage_get_linker_info();
	if (ld_info == NULL) {
		printk(PRELOAD_PREFIX "Cannot get linker info [%u %u %s]!\n",
		       task->tgid, task->pid, task->comm);
		return NULL;
	}

	for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file && vma->vm_flags & VM_EXEC
		    && vma->vm_file->f_dentry == ld_info->dentry) {
				preload_storage_put_linker_info(ld_info);
				return vma;
		}
	}

	preload_storage_put_linker_info(ld_info);
	return NULL;
}

static struct vm_area_struct *__get_libc_vma(struct task_struct *task)
{
	struct vm_area_struct *vma = NULL;
	struct bin_info *libc_info;

	libc_info = preload_storage_get_libc_info();

	if (!libc_info) {
		printk(PRELOAD_PREFIX "Cannot get libc info [%u %u %s]!\n",
		       task->tgid, task->pid, task->comm);
		return NULL;
	}

	for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file && vma->vm_flags & VM_EXEC
		    && vma->vm_file->f_dentry == libc_info->dentry) {
			preload_storage_put_libc_info(libc_info);
			return vma;
		}
	}

	preload_storage_put_libc_info(libc_info);
	return NULL;
}

static struct vm_area_struct *__get_libpthread_vma(struct task_struct *task)
{
	struct vm_area_struct *vma = NULL;
	struct bin_info *libpthread_info;

	libpthread_info = preload_storage_get_libpthread_info();

	if (!libpthread_info) {
		printk(PRELOAD_PREFIX "Cannot get libpthread info [%u %u %s]!\n",
		       task->tgid, task->pid, task->comm);
		return NULL;
	}

	for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file && vma->vm_flags & VM_EXEC
		    && vma->vm_file->f_dentry == libpthread_info->dentry) {
			preload_storage_put_libpthread_info(libpthread_info);
			return vma;
		}
	}

	preload_storage_put_libpthread_info(libpthread_info);
	return NULL;
}

static struct vm_area_struct *__get_libsmack_vma(struct task_struct *task)
{
	struct vm_area_struct *vma = NULL;
	struct bin_info *libsmack_info;

	libsmack_info = preload_storage_get_libsmack_info();

	if (!libsmack_info) {
		printk(PRELOAD_PREFIX "Cannot get libsmack info [%u %u %s]!\n",
		       task->tgid, task->pid, task->comm);
		return NULL;
	}

	for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file && vma->vm_flags & VM_EXEC
		    && vma->vm_file->f_dentry == libsmack_info->dentry) {
			preload_storage_put_libsmack_info(libsmack_info);
			return vma;
		}
	}

	preload_storage_put_libsmack_info(libsmack_info);
	return NULL;
}

static inline struct vm_area_struct *__get_vma_by_addr(struct task_struct *task,
						        unsigned long caller_addr)
{
	struct vm_area_struct *vma = NULL;

	if (task->mm == NULL)
		return NULL;
	vma = find_vma_intersection(task->mm, caller_addr, caller_addr + 1);

	return vma;
}

static inline bool __inverted(struct us_ip *ip)
{
	unsigned long flags = ip->info->pl_i.flags;

	if (flags & SWAP_PRELOAD_INVERTED_PROBE)
		return true;

	return false;
}

static inline bool __should_drop(struct us_ip *ip, enum preload_call_type ct)
{
	if (ct == NOT_INSTRUMENTED)
		return true;

	return false;
}

static inline bool __check_flag_and_call_type(struct us_ip *ip,
					      enum preload_call_type ct)
{
	bool inverted = __inverted(ip);

	if (ct != NOT_INSTRUMENTED || inverted)
		return true;

	return false;
}

static inline bool __is_probe_non_block(struct us_ip *ip)
{
	if (ip->info->pl_i.flags & SWAP_PRELOAD_NON_BLOCK_PROBE)
		return true;

	return false;
}

static inline bool __is_handlers_call(struct vm_area_struct *caller)
{
	/* TODO Optimize using start/stop callbacks */

	struct bin_info *hi = preload_storage_get_handlers_info();
	bool res = false;

	if (hi == NULL) {
		printk(PRELOAD_PREFIX "Cannot get handlers dentry!\n");
		goto is_handlers_call_out;
	}

	if (caller == NULL || caller->vm_file == NULL ||
		caller->vm_file->f_dentry == NULL) {
		goto is_handlers_call_out;
	}

	if (hi->dentry == caller->vm_file->f_dentry)
		res = true;

is_handlers_call_out:

	preload_storage_put_handlers_info(hi);

	return res;
}

static inline int __msg_sanitization(char *user_msg, size_t len,
				     char *call_type_p, char *caller_p)
{
	if ((call_type_p < user_msg) || (call_type_p > user_msg + len) ||
	    (caller_p < user_msg) || (caller_p > user_msg + len))
		return -EINVAL;

	return 0;
}





static bool __is_proc_mmap_mappable(struct task_struct *task)
{
	struct vm_area_struct *linker_vma = __get_linker_vma(task);
	struct sspt_proc *proc;
	unsigned long r_debug_addr;
	unsigned int state;
	enum { r_state_offset = sizeof(int) + sizeof(void *) + sizeof(long) };

	if (linker_vma == NULL)
		return false;

	r_debug_addr = __get_r_debug_off(linker_vma);
	if (r_debug_addr == 0)
		return false;

	r_debug_addr += r_state_offset;
	proc = sspt_proc_get_by_task(task);
	if (proc)
		proc->r_state_addr = r_debug_addr;

	if (get_user(state, (unsigned long *)r_debug_addr))
		return false;

	return !state;
}

static bool __not_system_caller(struct task_struct *task,
				 struct vm_area_struct *caller)
{
	struct vm_area_struct *linker_vma = __get_linker_vma(task);
	struct vm_area_struct *libc_vma = __get_libc_vma(task);
	struct vm_area_struct *libpthread_vma = __get_libpthread_vma(task);
	struct vm_area_struct *libsmack_vma = __get_libsmack_vma(task);

	  if (caller == NULL ||
	    caller == linker_vma ||
	    caller == libc_vma ||
	    caller == libpthread_vma ||
	    caller == libsmack_vma)
		return false;

	return true;
}

static bool __should_we_preload_handlers(struct task_struct *task,
					 struct pt_regs *regs)
{
	unsigned long caller_addr = get_regs_ret_func(regs);
	struct vm_area_struct *cvma = __get_vma_by_addr(current, caller_addr);

	if (!__is_proc_mmap_mappable(task) ||
	    !__not_system_caller(task, cvma))
		return false;

	return true;
}

static inline void __write_data_to_msg(char *msg, size_t len,
				       unsigned long call_type_off,
				       unsigned long caller_off,
				       unsigned long caller_addr)
{
	unsigned char call_type = 0;
	unsigned long caller = 0;
	int ret;

	if (caller_addr != 0) {
		caller = caller_addr;
		call_type = preload_control_call_type_always_inst((void *)caller);
	} else {
		ret = preload_threads_get_caller(current, &caller);
		if (ret != 0) {
			caller = 0xbadbeef;
			printk(PRELOAD_PREFIX "Error! Cannot get caller address for %d/%d\n",
			       current->tgid, current->pid);
		}

		ret = preload_threads_get_call_type(current, &call_type);
		if (ret != 0) {
			call_type = 0xff;
			printk(PRELOAD_PREFIX "Error! Cannot get call type for %d/%d\n",
			       current->tgid, current->pid);
		}
	}

	/* Using the same types as in the library. */
	*(uint32_t *)(msg + call_type_off) = (uint32_t)call_type;
	*(uintptr_t *)(msg + caller_off) = (uintptr_t)caller;
}




enum mmap_type_t {
	MMAP_LOADER,
	MMAP_HANDLERS,
	MMAP_UI_VIEWER,
	MMAP_SKIP
};

struct mmap_priv {
	enum mmap_type_t type;
};

static inline bool check_prot(unsigned long prot)
{
	return !!((prot & PROT_READ) && (prot & PROT_EXEC));
}

static int mmap_entry_handler(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct file *file = (struct file *)swap_get_karg(regs, 0);
	unsigned long prot = swap_get_karg(regs, 3);
	struct mmap_priv *priv = (struct mmap_priv *)ri->data;
	struct dentry *dentry, *loader_dentry;
	struct bin_info *hi, *vi;

	priv->type = MMAP_SKIP;
	if (!check_prot(prot))
		return 0;

	if (!file)
		return 0;
	dentry = file->f_dentry;
	if (dentry == NULL)
		return 0;

	hi = preload_storage_get_handlers_info();
	if (hi == NULL) {
		printk(PRELOAD_PREFIX "Cannot get handlers info [%u %u %s]\n",
		       current->tgid, current->pid, current->comm);
		return 0;
	}

	vi = preload_storage_get_ui_viewer_info();
	if (vi == NULL) {
		printk(PRELOAD_PREFIX "Cannot get ui viewer info [%u %u %s]\n",
		       current->tgid, current->pid, current->comm);
		goto put_hi;
	}

	loader_dentry = preload_debugfs_get_loader_dentry();
	if (dentry == loader_dentry)
		priv->type = MMAP_LOADER;
	else if (hi->dentry != NULL && dentry == hi->dentry)
		priv->type = MMAP_HANDLERS;
	else if (vi->dentry != NULL && dentry == vi->dentry)
		priv->type = MMAP_UI_VIEWER;

	preload_storage_put_handlers_info(vi);
put_hi:
	preload_storage_put_handlers_info(hi);

	return 0;
}

static int mmap_ret_handler(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct mmap_priv *priv = (struct mmap_priv *)ri->data;
	struct task_struct *task = current->group_leader;
	struct process_data *pd;
	struct sspt_proc *proc;
	unsigned long vaddr;

	if (!task->mm)
		return 0;

	vaddr = (unsigned long)regs_return_value(regs);
	if (IS_ERR_VALUE(vaddr))
		return 0;

	proc = sspt_proc_get_by_task(task);
	if (!proc)
		return 0;

	pd = preload_pd_get(proc);
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n",
		       __LINE__, current->tgid, current->comm);
		return 0;
	}

	switch (priv->type) {
	case MMAP_LOADER:
		preload_pd_set_loader_base(pd, vaddr);
		break;
	case MMAP_HANDLERS:
		preload_pd_set_handlers_base(pd, vaddr);
		break;
	case MMAP_UI_VIEWER:
		preload_pd_set_ui_viewer_base(proc->private_data, vaddr);
		break;
	case MMAP_SKIP:
	default:
		break;
	}

	return 0;
}

static struct kretprobe mmap_rp = {
	.kp.symbol_name = "do_mmap_pgoff",
	.data_size = sizeof(struct mmap_priv),
	.entry_handler = mmap_entry_handler,
	.handler = mmap_ret_handler
};

static void preload_start_cb(void)
{
	int res;

	res = swap_register_kretprobe(&mmap_rp);
	if (res != 0)
		printk(KERN_ERR PRELOAD_PREFIX "Registering do_mmap_pgoff probe failed\n");
}

static void preload_stop_cb(void)
{
	swap_unregister_kretprobe(&mmap_rp);
}

static int preload_us_entry(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_data *pd = __get_process_data(ri->rp);
	struct us_ip *ip = container_of(ri->rp, struct us_ip, retprobe);
	struct us_priv *priv = (struct us_priv *)ri->data;
	unsigned long flags = get_preload_flags(current);
	unsigned long offset = ip->info->pl_i.handler;
	unsigned long vaddr = 0;
	unsigned long base;
	char __user *path = NULL;

	if ((flags & HANDLER_RUNNING) ||
	    preload_threads_check_disabled_probe(current, ip->orig_addr))
		goto out_set_origin;

	switch (preload_pd_get_state(pd)) {
	case NOT_LOADED:
		/* if linker is still doing its work, we do nothing */
		if (!__should_we_preload_handlers(current, regs))
			goto out_set_origin;

		base = preload_pd_get_loader_base(pd);
		if (base == 0)
			break;	/* loader isn't mapped */

		/* jump to loader code if ready */
		vaddr = base + preload_debugfs_get_loader_offset();
		if (vaddr) {
			/* save original regs state */
			__save_uregs(ri, regs);
			print_regs("PROBE ORIG", regs, ri);

			path = preload_pd_get_path(pd);

			/* set dlopen args: filename, flags */
			swap_set_arg(regs, 0, (unsigned long)path/*swap_get_stack_ptr(regs)*/);
			swap_set_arg(regs, 1, 2 /* RTLD_NOW */);

			/* do the jump to dlopen */
			__prepare_ujump(ri, regs, vaddr);
			/* set new state */
			preload_pd_set_state(pd, LOADING);
		}
		break;
	case LOADING:
		/* handlers have not yet been loaded... just ignore */
		break;
	case LOADED:
		base = preload_pd_get_handlers_base(pd);
		if (base == 0)
			break;	/* handlers isn't mapped */

		/* jump to preloaded handler */
		vaddr = base + offset;
		if (vaddr) {
			unsigned long disable_addr;
			unsigned long caddr = get_regs_ret_func(regs);
			struct vm_area_struct *cvma = __get_vma_by_addr(current, caddr);
			enum preload_call_type ct;

			ct = preload_control_call_type(ip, (void *)caddr);
			disable_addr = __is_probe_non_block(ip) ?
				       ip->orig_addr : 0;

			/* jump only if caller is instumented and it is not a system lib -
			 * this leads to some errors */
			if (__not_system_caller(current, cvma) &&
			    __check_flag_and_call_type(ip, ct) &&
			    !__is_handlers_call(cvma)) {
				if (preload_threads_set_data(current,
							     caddr, ct,
							     disable_addr,
							     __should_drop(ip,
							     ct)) != 0)
					printk(PRELOAD_PREFIX "Error! Failed to set caller 0x%lx"
					       " for %d/%d\n", caddr, current->tgid,
							       current->pid);
				/* args are not changed */
				__prepare_ujump(ri, regs, vaddr);
				if (disable_addr == 0)
					set_preload_flags(current, HANDLER_RUNNING);
			}
		}
		break;
	case FAILED:
	case ERROR:
	default:
		/* do nothing */
		break;
	}

out_set_origin:
	priv->origin = vaddr;
	return 0;
}

static int preload_us_ret(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_data *pd = __get_process_data(ri->rp);
	struct us_ip *ip = container_of(ri->rp, struct us_ip, retprobe);
	struct us_priv *priv = (struct us_priv *)ri->data;
	unsigned long flags = get_preload_flags(current);
	unsigned long offset = ip->info->pl_i.handler;
	unsigned long vaddr = 0;

	switch (preload_pd_get_state(pd)) {
	case NOT_LOADED:
		/* loader has not yet been mapped... just ignore */
		break;
	case LOADING:
		/* check if preloading has been completed */
		vaddr = preload_pd_get_loader_base(pd) + preload_debugfs_get_loader_offset();
		if (vaddr && (priv->origin == vaddr)) {
			preload_pd_set_handle(pd, (void __user *)regs_return_value(regs));

			/* restore original regs state */
			__restore_uregs(ri, regs);
			print_regs("PROBE REST", regs, ri);
			/* check if preloading done */

			if (preload_pd_get_handle(pd)) {
				preload_pd_set_state(pd, LOADED);
			} else {
				preload_pd_dec_attempts(pd);
				preload_pd_set_state(pd, FAILED);
			}
		}
		break;
	case LOADED:
		if ((flags & HANDLER_RUNNING) ||
		    preload_threads_check_disabled_probe(current, ip->orig_addr)) {
			bool non_blk_probe = __is_probe_non_block(ip);

			/* drop the flag if the handler has completed */
			vaddr = preload_pd_get_handlers_base(pd) + offset;
			if (vaddr && (priv->origin == vaddr)) {
				if (preload_threads_put_data(current) != 0)
					printk(PRELOAD_PREFIX "Error! Failed to put caller slot"
					       " for %d/%d\n", current->tgid, current->pid);
				if (!non_blk_probe) {
					flags &= ~HANDLER_RUNNING;
					set_preload_flags(current, flags);
				}
			}
		}
		break;
	case FAILED:
		if (preload_pd_get_attempts(pd)) {
			preload_pd_set_state(pd, NOT_LOADED);
		}
		break;
	case ERROR:
	default:
		break;
	}

	return 0;
}



static int get_caller_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long caller;
	int ret;

	ret = preload_threads_get_caller(current, &caller);
	if (ret != 0) {
		caller = 0xbadbeef;
		printk(PRELOAD_PREFIX "Error! Cannot get caller address for %d/%d\n",
		       current->tgid, current->pid);
	}

	swap_put_uarg(regs, 0, caller);

	return 0;
}

static int get_call_type_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned char call_type;
	int ret;

	ret = preload_threads_get_call_type(current, &call_type);
	if (ret != 0) {
		call_type = 0xff;
		printk(PRELOAD_PREFIX "Error! Cannot get call type for %d/%d\n",
		       current->tgid, current->pid);
	}

	swap_put_uarg(regs, 0, call_type);

	return 0;
}

static int write_msg_handler(struct kprobe *p, struct pt_regs *regs)
{
	char *user_buf;
	char *buf;
	char *caller_p;
	char *call_type_p;
	size_t len;
	unsigned long caller_offset;
	unsigned long call_type_offset;
	unsigned long caller_addr;
	int ret;

	/* FIXME: swap_get_uarg uses get_user(), it might sleep */
	user_buf = (char *)swap_get_uarg(regs, 0);
	len = swap_get_uarg(regs, 1);
	call_type_p = (char *)swap_get_uarg(regs, 2);
	caller_p = (char *)swap_get_uarg(regs, 3);
	caller_addr = swap_get_uarg(regs, 4);

	ret = __msg_sanitization(user_buf, len, call_type_p, caller_p);
	if (ret != 0) {
		printk(PRELOAD_PREFIX "Invalid message pointers!\n");
		return 0;
	}

	ret = preload_threads_get_drop(current);
	if (ret > 0)
		return 0;

	buf = kmalloc(len, GFP_ATOMIC);
	if (buf == NULL) {
		printk(PRELOAD_PREFIX "No mem for buffer! Size = %d\n", len);
		return 0;
	}

	ret = read_proc_vm_atomic(current, (unsigned long)user_buf, buf, len);
	if (ret < 0) {
		printk(PRELOAD_PREFIX "Cannot copy data from userspace! Size = %d"
				      " ptr 0x%lx ret %d\n", len, (unsigned long)user_buf, ret);
		goto write_msg_fail;
	}

	/* Evaluating call_type and caller offset in message:
	 * data offset = data pointer - beginning of the message.
	 */
	call_type_offset = (unsigned long)(call_type_p - user_buf);
	caller_offset = (unsigned long)(caller_p - user_buf);

	__write_data_to_msg(buf, len, call_type_offset, caller_offset, caller_addr);

	ret = swap_msg_raw(buf, len);
	if (ret != len)
		printk(PRELOAD_PREFIX "Error writing probe lib message\n");

write_msg_fail:
	kfree(buf);

	return 0;
}




int preload_module_get_caller_init(struct us_ip *ip)
{
	struct uprobe *up = &ip->uprobe;

	up->kp.pre_handler = get_caller_handler;

	return 0;
}

void preload_module_get_caller_exit(struct us_ip *ip)
{
}

int preload_module_get_call_type_init(struct us_ip *ip)
{
	struct uprobe *up = &ip->uprobe;

	up->kp.pre_handler = get_call_type_handler;

	return 0;
}

void preload_module_get_call_type_exit(struct us_ip *ip)
{
}

int preload_module_write_msg_init(struct us_ip *ip)
{
	struct uprobe *up = &ip->uprobe;

	up->kp.pre_handler = write_msg_handler;

	return 0;
}

void preload_module_write_msg_exit(struct us_ip *ip)
{
}


int preload_module_uprobe_init(struct us_ip *ip)
{
	struct uretprobe *rp = &ip->retprobe;

	rp->entry_handler = preload_us_entry;
	rp->handler = preload_us_ret;
	/* FIXME actually additional data_size is needed only when we jump
	 * to dlopen */
	rp->data_size = sizeof(struct us_priv);

	return 0;
}

void preload_module_uprobe_exit(struct us_ip *ip)
{
}

int preload_set(void)
{
	if (preload_module_is_running())
		return -EBUSY;

	return 0;
}

void preload_unset(void)
{
	swap_unregister_kretprobe(&mmap_rp);
	/*module_put(THIS_MODULE);*/
	preload_module_set_not_ready();

}


/* ============================================================================
 * =                               ui_viewer                                  =
 * ============================================================================
 */

/* main handler for ui viewer */
static int preload_ui_viewer_main_eh(struct uretprobe_instance *ri,
			       struct pt_regs *regs);
static int preload_ui_viewer_main_rh(struct uretprobe_instance *ri,
			       struct pt_regs *regs);
static struct probe_info_new pin_main = MAKE_URPROBE(preload_ui_viewer_main_eh,
						     preload_ui_viewer_main_rh,
						     0);

struct probe_info_new *uihv_pin_main(void)
{
	return &pin_main;
}


static int preload_ui_viewer_init(struct us_ip *ip)
{
	return 0;
}

static void preload_ui_viewer_exit(struct us_ip *ip)
{
	return;
}

/* ============================================================================
 * =                          ui viewer handlers                              =
 * ============================================================================
 */
static int preload_ui_viewer_main_eh(struct uretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct process_data *pd;
	struct us_ip *ip = container_of(ri->rp, struct us_ip, retprobe);
	unsigned long vaddr = 0;
	char __user *path = NULL;

	preload_ui_viewer_init(ip);

	pd = __get_process_data(ri->rp);

	switch (preload_pd_get_ui_viewer_state(pd)) {
	case NOT_LOADED:
		/* jump to loader code if ready */
		vaddr = preload_pd_get_loader_base(pd) +
			preload_debugfs_get_loader_offset();
		if (vaddr) {
			/* save original regs state */
			__save_uregs(ri, regs);
			print_regs("UI VIEWER ORIG", regs, ri);

			path = preload_pd_get_ui_viewer_path(pd);

			/* set dlopen args: filename, flags */
			swap_set_arg(regs, 0, (unsigned long)path);
			swap_set_arg(regs, 1, 2 /* RTLD_NOW */);

			/* do the jump to dlopen */
			__prepare_ujump(ri, regs, vaddr);
			/* set new state */
			preload_pd_set_ui_viewer_state(pd, LOADING);
		}
		break;
	default:
		break;
	}

	return 0;
}

static int preload_ui_viewer_main_rh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_data *pd = __get_process_data(ri->rp);
	struct us_ip *ip = container_of(ri->rp, struct us_ip, retprobe);
	unsigned long vaddr = 0;

	switch (preload_pd_get_ui_viewer_state(pd)) {
	case LOADING:
		vaddr = preload_pd_get_loader_base(pd) +
			preload_debugfs_get_loader_offset();
		if (vaddr) {
			preload_pd_set_handle(pd,
				(void __user *)regs_return_value(regs));
			/* restore original regs state */
			__restore_uregs(ri, regs);
			print_regs("UI VIEWER REST", regs, ri);

			/* check if preloading is done */
			if (preload_pd_get_handle(pd)) {
				preload_pd_set_ui_viewer_state(pd, LOADED);
			} else {
				preload_pd_set_ui_viewer_state(pd, FAILED);
			}
		}
	default:
		break;
	}

	preload_ui_viewer_exit(ip);

	return 0;
}


static int preload_module_init(void)
{
	int ret;

	ret = preload_debugfs_init();
	if (ret)
		goto out_err;

	ret = preload_storage_init();
	if (ret)
		goto exit_debugfs;

	ret = preload_pd_init();
	if (ret)
		goto exit_storage;

	/* TODO do not forget to remove set (it is just for debugging) */
	ret = preload_set();
	if (ret)
		goto exit_pd;

	ret = preload_control_init();
	if (ret)
		goto exit_set;

	ret = preload_threads_init();
	if (ret)
		goto exit_control;

	ret = register_preload_probes();
	if (ret)
		goto exit_threads;

	ret = uihv_init();
	if (ret)
		goto exit_reg_probes;

	__preload_cbs_start_h = us_manager_reg_cb(START_CB, preload_start_cb);
	if (__preload_cbs_start_h < 0)
		goto exit_uihv;

	__preload_cbs_stop_h = us_manager_reg_cb(STOP_CB, preload_stop_cb);
	if (__preload_cbs_stop_h < 0)
		goto exit_start_cb;

	return 0;

exit_start_cb:
	us_manager_unreg_cb(__preload_cbs_start_h);

exit_uihv:
	uihv_uninit();

exit_reg_probes:
	unregister_preload_probes();

exit_threads:
	preload_threads_exit();

exit_control:
	preload_control_exit();

exit_set:
	preload_unset();

exit_pd:
	preload_pd_uninit();

exit_storage:
	preload_storage_exit();

exit_debugfs:
	preload_debugfs_exit();

out_err:
	return ret;
}

static void preload_module_exit(void)
{
	int balance;

	us_manager_unreg_cb(__preload_cbs_start_h);
	us_manager_unreg_cb(__preload_cbs_stop_h);
	uihv_uninit();
	unregister_preload_probes();
	preload_threads_exit();
	preload_control_exit();
	preload_unset();
	preload_pd_uninit();
	preload_storage_exit();
	preload_debugfs_exit();

	balance = atomic_read(&dentry_balance);
	atomic_set(&dentry_balance, 0);

	WARN(balance, "Bad GET/PUT dentry balance: %d\n", balance);
}

SWAP_LIGHT_INIT_MODULE(NULL, preload_module_init, preload_module_exit,
		       NULL, NULL);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP Preload Module");
MODULE_AUTHOR("Vasiliy Ulyanov <v.ulyanov@samsung.com>"
              "Alexander Aksenov <a.aksenov@samsung.com>");
