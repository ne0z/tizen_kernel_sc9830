/*
 *  SWAP uprobe manager
 *  modules/us_manager/img/img_proc.c
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


#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/sspt/sspt_file.h>
#include "img_ip.h"
#include "img_proc.h"
#include "img_file.h"


struct img_proc {
	struct list_head file_list;
	rwlock_t rwlock;
};


static void img_del_file_by_list(struct img_file *file);

/**
 * @brief Create img_proc struct
 *
 * @return Pointer to the created img_proc struct
 */
struct img_proc *create_img_proc(void)
{
	struct img_proc *proc;

	proc = kmalloc(sizeof(*proc), GFP_ATOMIC);
	if (proc) {
		INIT_LIST_HEAD(&proc->file_list);
		rwlock_init(&proc->rwlock);
	}

	return proc;
}

/**
 * @brief Remove img_proc struct
 *
 * @param file remove object
 * @return Void
 */
void free_img_proc(struct img_proc *proc)
{
	struct img_file *file, *tmp;

	list_for_each_entry_safe(file, tmp, &proc->file_list, list) {
		img_del_file_by_list(file);
		free_img_file(file);
	}

	kfree(proc);
}

/* called with write_[lock/unlock](&proc->rwlock) */
static void img_add_file_by_list(struct img_proc *proc, struct img_file *file)
{
	list_add(&file->list, &proc->file_list);
}

/* called with write_[lock/unlock](&proc->rwlock) */
static void img_del_file_by_list(struct img_file *file)
{
	list_del(&file->list);
}

/* called with read_[lock/unlock](&proc->rwlock) */
static struct img_file *find_img_file(struct img_proc *proc,
				      struct dentry *dentry)
{
	struct img_file *file;

	list_for_each_entry(file, &proc->file_list, list) {
		if (file->dentry == dentry)
			return file;
	}

	return NULL;
}

/**
 * @brief Add instrumentation pointer
 *
 * @param proc Pointer to the img_proc struct
 * @param dentry Dentry of file
 * @param addr Function address
 * @param probe_i Pointer to a probe_info struct related with the probe
 * @return Error code
 */
int img_proc_add_ip(struct img_proc *proc, struct dentry *dentry,
		    unsigned long addr, struct probe_info *probe_i)
{
	int ret;
	struct img_file *file;

	write_lock(&proc->rwlock);
	file = find_img_file(proc, dentry);
	if (file) {
		ret = img_file_add_ip(file, addr, probe_i);
		goto unlock;
	}

	file = create_img_file(dentry);
	if (file == NULL) {
		ret = -ENOMEM;
		goto unlock;
	}

	ret = img_file_add_ip(file, addr, probe_i);
	if (ret) {
		printk(KERN_INFO "Cannot add ip to img file\n");
		free_img_file(file);
	} else {
		img_add_file_by_list(proc, file);
	}

unlock:
	write_unlock(&proc->rwlock);
	return ret;
}

/**
 * @brief Remove instrumentation pointer
 *
 * @param proc Pointer to the img_proc struct
 * @param dentry Dentry of file
 * @param args Function address
 * @return Error code
 */
int img_proc_del_ip(struct img_proc *proc,
		    struct dentry *dentry,
		    unsigned long addr)
{
	int ret;
	struct img_file *file;

	write_lock(&proc->rwlock);
	file = find_img_file(proc, dentry);
	if (file == NULL) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = img_file_del_ip(file, addr);
	if (ret == 0 && img_file_empty(file)) {
		img_del_file_by_list(file);
		free_img_file(file);
	}

unlock:
	write_unlock(&proc->rwlock);
	return ret;
}

void img_proc_copy_to_sspt(struct img_proc *i_proc, struct sspt_proc *proc)
{
	struct sspt_file *file;
	struct img_file *i_file;

	read_lock(&i_proc->rwlock);
	list_for_each_entry(i_file, &i_proc->file_list, list) {
		file = sspt_proc_find_file_or_new(proc, i_file->dentry);

		if (file) {
			struct img_ip *i_ip;

			list_for_each_entry(i_ip, &i_file->ip_list, list)
				sspt_file_add_ip(file, i_ip->addr, i_ip->info);
		}
	}
	read_unlock(&i_proc->rwlock);
}

/**
 * @brief For debug
 *
 * @param proc Pointer to the img_proc struct
 * @return Void
 */

/* debug */
void img_proc_print(struct img_proc *proc)
{
	struct img_file *file;

	printk(KERN_INFO "### img_proc_print:\n");

	read_lock(&proc->rwlock);
	list_for_each_entry(file, &proc->file_list, list) {
		img_file_print(file);
	}
	read_unlock(&proc->rwlock);
}
/* debug */
