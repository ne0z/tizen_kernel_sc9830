/*
 *  SWAP uprobe manager
 *  modules/us_manager/pf/pf_group.c
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
 * Copyright (C) Samsung Electronics, 2013
 *
 * 2013	 Vyacheslav Cherkashin: SWAP us_manager implement
 *
 */


#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include "pf_group.h"
#include "proc_filters.h"
#include "../sspt/sspt_filter.h"
#include "../us_manager_common.h"
#include <us_manager/img/img_proc.h>
#include <us_manager/img/img_file.h>
#include <us_manager/img/img_ip.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/helper.h>

struct pf_group {
	struct list_head list;
	struct img_proc *i_proc;
	struct proc_filter filter;
	struct pfg_msg_cb *msg_cb;
	atomic_t usage;

	spinlock_t pl_lock;	/* for proc_list */
	struct list_head proc_list;
};

struct pl_struct {
	struct list_head list;
	struct sspt_proc *proc;
};

static LIST_HEAD(pfg_list);
static DEFINE_RWLOCK(pfg_list_lock);

/* struct pl_struct */
static struct pl_struct *create_pl_struct(struct sspt_proc *proc)
{
	struct pl_struct *pls = kmalloc(sizeof(*pls), GFP_ATOMIC);

	if (pls) {
		INIT_LIST_HEAD(&pls->list);
		pls->proc = sspt_proc_get(proc);
	}

	return pls;
}

static void free_pl_struct(struct pl_struct *pls)
{
	sspt_proc_put(pls->proc);
	kfree(pls);
}
/* struct pl_struct */

static struct pf_group *pfg_create(void)
{
	struct pf_group *pfg = kmalloc(sizeof(*pfg), GFP_ATOMIC);

	if (pfg == NULL)
		return NULL;

	pfg->i_proc = create_img_proc();
	if (pfg->i_proc == NULL)
		goto create_pfg_fail;

	INIT_LIST_HEAD(&pfg->list);
	memset(&pfg->filter, 0, sizeof(pfg->filter));
	spin_lock_init(&pfg->pl_lock);
	INIT_LIST_HEAD(&pfg->proc_list);
	pfg->msg_cb = NULL;
	atomic_set(&pfg->usage, 1);

	return pfg;

create_pfg_fail:

	kfree(pfg);

	return NULL;
}

static void pfg_free(struct pf_group *pfg)
{
	struct pl_struct *pl, *n;

	free_img_proc(pfg->i_proc);
	free_pf(&pfg->filter);
	list_for_each_entry_safe(pl, n, &pfg->proc_list, list) {
		sspt_proc_del_filter(pl->proc, pfg);
		free_pl_struct(pl);
	}

	kfree(pfg);
}

static int pfg_add_proc(struct pf_group *pfg, struct sspt_proc *proc)
{
	struct pl_struct *pls;

	pls = create_pl_struct(proc);
	if (pls == NULL)
		return -ENOMEM;

	spin_lock(&pfg->pl_lock);
	list_add(&pls->list, &pfg->proc_list);
	spin_unlock(&pfg->pl_lock);

	return 0;
}


/* called with pfg_list_lock held */
static void pfg_add_to_list(struct pf_group *pfg)
{
	list_add(&pfg->list, &pfg_list);
}

/* called with pfg_list_lock held */
static void pfg_del_from_list(struct pf_group *pfg)
{
	list_del(&pfg->list);
}


static void msg_info(struct sspt_filter *f, void *data)
{
	if (f->pfg_is_inst == false) {
		struct pfg_msg_cb *cb;

		f->pfg_is_inst = true;

		cb = pfg_msg_cb_get(f->pfg);
		if (cb) {
			struct dentry *dentry;

			dentry = (struct dentry *)f->pfg->filter.priv;

			if (cb->msg_info)
				cb->msg_info(f->proc->task, dentry);

			if (cb->msg_status_info)
				cb->msg_status_info(f->proc->task);
		}
	}
}

static void first_install(struct task_struct *task, struct sspt_proc *proc)
{
	sspt_proc_priv_create(proc);

	down_write(&task->mm->mmap_sem);
	sspt_proc_on_each_filter(proc, msg_info, NULL);
	sspt_proc_install(proc);
	up_write(&task->mm->mmap_sem);
}

static void subsequent_install(struct task_struct *task,
			       struct sspt_proc *proc, unsigned long page_addr)
{
	down_write(&task->mm->mmap_sem);
	sspt_proc_install_page(proc, page_addr);
	up_write(&task->mm->mmap_sem);
}

/**
 * @brief Get dentry struct by path
 *
 * @param path Path to file
 * @return Pointer on dentry struct on NULL
 */
struct dentry *dentry_by_path(const char *path)
{
	struct dentry *dentry;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
	struct path st_path;
	if (kern_path(path, LOOKUP_FOLLOW, &st_path) != 0) {
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	struct nameidata nd;
	if (path_lookup(path, LOOKUP_FOLLOW, &nd) != 0) {
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
		printk("failed to lookup dentry for path %s!\n", path);
		return NULL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	dentry = nd.dentry;
	path_release(&nd);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
	dentry = nd.path.dentry;
	path_put(&nd.path);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	dentry = st_path.dentry;
	path_put(&st_path);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25) */
	return dentry;
}
EXPORT_SYMBOL_GPL(dentry_by_path);


int pfg_msg_cb_set(struct pf_group *pfg, struct pfg_msg_cb *msg_cb)
{
	if (pfg->msg_cb)
		return -EBUSY;

	pfg->msg_cb = msg_cb;

	return 0;
}
EXPORT_SYMBOL_GPL(pfg_msg_cb_set);

void pfg_msg_cb_reset(struct pf_group *pfg)
{
	pfg->msg_cb = NULL;
}
EXPORT_SYMBOL_GPL(pfg_msg_cb_reset);

struct pfg_msg_cb *pfg_msg_cb_get(struct pf_group *pfg)
{
	return pfg->msg_cb;
}

/**
 * @brief Get pf_group struct by dentry
 *
 * @param dentry Dentry of file
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_by_dentry(struct dentry *dentry, void *priv)
{
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_dentry(&pfg->filter, dentry)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = pfg_create();
	if (pfg == NULL)
		goto unlock;

	set_pf_by_dentry(&pfg->filter, dentry, priv);

	pfg_add_to_list(pfg);

unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_dentry);

/**
 * @brief Get pf_group struct by TGID
 *
 * @param tgid Thread group ID
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_by_tgid(pid_t tgid, void *priv)
{
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_tgid(&pfg->filter, tgid)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = pfg_create();
	if (pfg == NULL)
		goto unlock;

	set_pf_by_tgid(&pfg->filter, tgid, priv);

	pfg_add_to_list(pfg);

unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_tgid);

/**
 * @brief Get pf_group struct by comm
 *
 * @param comm Task comm
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_by_comm(char *comm, void *priv)
{
	int ret;
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_comm(&pfg->filter, comm)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = pfg_create();
	if (pfg == NULL)
		goto unlock;

	ret = set_pf_by_comm(&pfg->filter, comm, priv);
	if (ret) {
		printk(KERN_ERR "ERROR: set_pf_by_comm, ret=%d\n", ret);
		pfg_free(pfg);
		pfg = NULL;
		goto unlock;
	}

	pfg_add_to_list(pfg);
unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_comm);

/**
 * @brief Get pf_group struct for each process
 *
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_dumb(void *priv)
{
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_dumb(&pfg->filter)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = pfg_create();
	if (pfg == NULL)
		goto unlock;

	set_pf_dumb(&pfg->filter, priv);

	pfg_add_to_list(pfg);

unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_dumb);

/**
 * @brief Put pf_group struct
 *
 * @param pfg Pointer to the pf_group struct
 * @return Void
 */
void put_pf_group(struct pf_group *pfg)
{
	if (atomic_dec_and_test(&pfg->usage)) {
		write_lock(&pfg_list_lock);
		pfg_del_from_list(pfg);
		write_unlock(&pfg_list_lock);

		pfg_free(pfg);
	}
}
EXPORT_SYMBOL_GPL(put_pf_group);

/**
 * @brief Register prober for pf_grpup struct
 *
 * @param pfg Pointer to the pf_group struct
 * @param dentry Dentry of file
 * @param offset Function offset
 * @param probe_info Pointer to the related probe_info struct
 * @return Error code
 */
int pf_register_probe(struct pf_group *pfg, struct dentry *dentry,
		      unsigned long offset, struct probe_info *probe_i)
{
	return img_proc_add_ip(pfg->i_proc, dentry, offset, probe_i);
}
EXPORT_SYMBOL_GPL(pf_register_probe);

/**
 * @brief Unregister prober from pf_grpup struct
 *
 * @param pfg Pointer to the pf_group struct
 * @param dentry Dentry of file
 * @param offset Function offset
 * @return Error code
 */
int pf_unregister_probe(struct pf_group *pfg, struct dentry *dentry,
			unsigned long offset)
{
	return img_proc_del_ip(pfg->i_proc, dentry, offset);
}
EXPORT_SYMBOL_GPL(pf_unregister_probe);

/**
 * @brief Check the task, to meet the filter criteria
 *
 * @prarm task Pointer on the task_struct struct
 * @return
 *       - 0 - false
 *       - 1 - true
 */
int check_task_on_filters(struct task_struct *task)
{
	int ret = 0;
	struct pf_group *pfg;

	read_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_task_f(&pfg->filter, task)) {
			ret = 1;
			goto unlock;
		}
	}

unlock:
	read_unlock(&pfg_list_lock);
	return ret;
}

enum pf_inst_flag {
	PIF_NONE,
	PIF_FIRST,
	PIF_SECOND,
	PIF_ADD_PFG
};

static enum pf_inst_flag pfg_check_task(struct task_struct *task)
{
	struct pf_group *pfg;
	struct sspt_proc *proc = NULL;
	enum pf_inst_flag flag = PIF_NONE;

	read_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_task_f(&pfg->filter, task) == NULL)
			continue;

		if (proc == NULL)
			proc = sspt_proc_get_by_task(task);

		if (proc) {
			flag = flag == PIF_NONE ? PIF_SECOND : flag;
		} else if (task->tgid == task->pid) {
			proc = sspt_proc_get_by_task_or_new(task);
			if (proc == NULL) {
				printk(KERN_ERR "cannot create sspt_proc\n");
				break;
			}
			flag = PIF_FIRST;
		}

		if (proc) {
			write_lock(&proc->filter_lock);
				if (sspt_proc_is_filter_new(proc, pfg)) {
					img_proc_copy_to_sspt(pfg->i_proc, proc);
					sspt_proc_add_filter(proc, pfg);
					pfg_add_proc(pfg, proc);
					flag = flag == PIF_FIRST ? flag : PIF_ADD_PFG;
			}
			write_unlock(&proc->filter_lock);
		}
	}
	read_unlock(&pfg_list_lock);

	return flag;
}

/**
 * @brief Check task and install probes on demand
 *
 * @prarm task Pointer on the task_struct struct
 * @return Void
 */
void check_task_and_install(struct task_struct *task)
{
	struct sspt_proc *proc;
	enum pf_inst_flag flag;

	flag = pfg_check_task(task);
	switch (flag) {
	case PIF_FIRST:
	case PIF_ADD_PFG:
		proc = sspt_proc_get_by_task(task);
		if (proc)
			first_install(task, proc);
		break;

	case PIF_NONE:
	case PIF_SECOND:
		break;
	}
}

/**
 * @brief Check task and install probes on demand
 *
 * @prarm task Pointer on the task_struct struct
 * @param page_addr Page fault address
 * @return Void
 */
void call_page_fault(struct task_struct *task, unsigned long page_addr)
{
	struct sspt_proc *proc;
	enum pf_inst_flag flag;

	flag = pfg_check_task(task);
	switch (flag) {
	case PIF_FIRST:
	case PIF_ADD_PFG:
		proc = sspt_proc_get_by_task(task);
		if (proc)
			first_install(task, proc);
		break;

	case PIF_SECOND:
		proc = sspt_proc_get_by_task(task);
		if (proc)
			subsequent_install(task, proc, page_addr);
		break;

	case PIF_NONE:
		break;
	}
}

/**
 * @brief Uninstall probes from the sspt_proc struct
 *
 * @prarm proc Pointer on the sspt_proc struct
 * @return Void
 */

/* called with sspt_proc_write_lock() */
void uninstall_proc(struct sspt_proc *proc)
{
	struct task_struct *task = proc->task;

	sspt_proc_uninstall(proc, task, US_UNREGS_PROBE);
	sspt_proc_cleanup(proc);
}

/**
 * @brief Remove probes from the task on demand
 *
 * @prarm task Pointer on the task_struct struct
 * @return Void
 */
void call_mm_release(struct task_struct *task)
{
	struct sspt_proc *proc;

	sspt_proc_write_lock();
	proc = sspt_proc_get_by_task_no_lock(task);
	if (proc)
		list_del(&proc->list);
	sspt_proc_write_unlock();

	if (proc)
		uninstall_proc(proc);
}

/**
 * @brief Legacy code, it is need remove
 *
 * @param addr Page address
 * @return Void
 */
void uninstall_page(unsigned long addr)
{

}

/**
 * @brief Install probes on running processes
 *
 * @return Void
 */
void install_all(void)
{
	/* TODO: to be implemented */
}

/**
 * @brief Uninstall probes from all processes
 *
 * @return Void
 */
void uninstall_all(void)
{
	struct list_head *proc_list = sspt_proc_list();

	sspt_proc_write_lock();
	while (!list_empty(proc_list)) {
		struct sspt_proc *proc;
		proc = list_first_entry(proc_list, struct sspt_proc, list);

		list_del(&proc->list);

		sspt_proc_write_unlock();
		uninstall_proc(proc);
		sspt_proc_write_lock();
	}
	sspt_proc_write_unlock();
}

static void __do_get_proc(struct sspt_proc *proc, void *data)
{
	get_task_struct(proc->task);
	proc->__task = proc->task;
	proc->__mm = get_task_mm(proc->task);
}

static void __do_put_proc(struct sspt_proc *proc, void *data)
{
	if (proc->__mm) {
		mmput(proc->__mm);
		proc->__mm = NULL;
	}

	if (proc->__task) {
		put_task_struct(proc->__task);
		proc->__task = NULL;
	}
}

void get_all_procs(void)
{
	sspt_proc_read_lock();
	on_each_proc_no_lock(__do_get_proc, NULL);
	sspt_proc_read_unlock();
}

void put_all_procs(void)
{
	sspt_proc_read_lock();
	on_each_proc_no_lock(__do_put_proc, NULL);
	sspt_proc_read_unlock();
}

/**
 * @brief For debug
 *
 * @param pfg Pointer to the pf_group struct
 * @return Void
 */

/* debug */
void pfg_print(struct pf_group *pfg)
{
	img_proc_print(pfg->i_proc);
}
EXPORT_SYMBOL_GPL(pfg_print);
/* debug */
