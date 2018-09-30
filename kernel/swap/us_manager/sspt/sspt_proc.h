#ifndef __SSPT_PROC__
#define __SSPT_PROC__

/**
 * @file us_manager/sspt/sspt_proc.h
 * @author Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 * @section LICENSE
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
 * Copyright (C) Samsung Electronics, 2013
 */

#include <linux/types.h>
#include "sspt_file.h"

struct slot_manager;
struct task_struct;
struct pf_group;
struct sspt_filter;
struct us_ip;

/** Flags for sspt_*_uninstall() */
enum US_FLAGS {
	US_UNREGS_PROBE,	/**< probes remove and disarm */
	US_DISARM,		/**< probes disarm */
	US_UNINSTALL		/**< probes remove from list install */
};

/**
 * @struct sspt_proc
 * @breaf Image of process for specified process
 */
struct sspt_proc {
	struct list_head list;		/**< For global process list */
	pid_t tgid;			/**< Thread group ID */
	struct task_struct *task;	/**< Ptr to the task */
	struct mm_struct *__mm;
	struct task_struct *__task;
	unsigned long r_state_addr;	/**< address of r_state */
	struct slot_manager *sm;	/**< Ptr to the manager slot */
	struct list_head file_list;	/**< For sspt_file */
	rwlock_t filter_lock;
	struct list_head filter_list;	/**< Filter list */
	unsigned first_install:1;	/**< Install flag */
	struct sspt_feature *feature;	/**< Ptr to the feature */
	atomic_t usage;

	/* FIXME: for preload (remove those fields) */
	void *private_data;		/**< Process private data */
};

struct sspt_proc_cb {
	void *(*priv_create)(struct sspt_proc *);
	void (*priv_destroy)(struct sspt_proc *, void *);
};


struct list_head *sspt_proc_list(void);

struct sspt_proc *sspt_proc_create(struct task_struct *task);
void sspt_proc_cleanup(struct sspt_proc *proc);
struct sspt_proc *sspt_proc_get(struct sspt_proc *proc);
void sspt_proc_put(struct sspt_proc *proc);

void on_each_proc_no_lock(void (*func)(struct sspt_proc *, void *),
			  void *data);
void on_each_proc(void (*func)(struct sspt_proc *, void *), void *data);

struct sspt_proc *sspt_proc_get_by_task(struct task_struct *task);
struct sspt_proc *sspt_proc_get_by_task_no_lock(struct task_struct *task);
struct sspt_proc *sspt_proc_get_by_task_or_new(struct task_struct *task);
void sspt_proc_free_all(void);

struct sspt_file *sspt_proc_find_file(struct sspt_proc *proc,
				      struct dentry *dentry);
struct sspt_file *sspt_proc_find_file_or_new(struct sspt_proc *proc,
					     struct dentry *dentry);

void sspt_proc_install_probe(struct sspt_proc *proc, unsigned long vaddr,
			     struct probe_info *probe_i);
void sspt_proc_install_page(struct sspt_proc *proc, unsigned long page_addr);
void sspt_proc_install(struct sspt_proc *proc);
int sspt_proc_uninstall(struct sspt_proc *proc,
			struct task_struct *task,
			enum US_FLAGS flag);

int sspt_proc_get_files_by_region(struct sspt_proc *proc,
				  struct list_head *head,
				  unsigned long start, size_t len);
void sspt_proc_insert_files(struct sspt_proc *proc, struct list_head *head);

void sspt_proc_read_lock(void);
void sspt_proc_read_unlock(void);
void sspt_proc_write_lock(void);
void sspt_proc_write_unlock(void);

void sspt_proc_add_filter(struct sspt_proc *proc, struct pf_group *pfg);
void sspt_proc_del_filter(struct sspt_proc *proc, struct pf_group *pfg);
void sspt_proc_del_all_filters(struct sspt_proc *proc);
bool sspt_proc_is_filter_new(struct sspt_proc *proc, struct pf_group *pfg);

void sspt_proc_on_each_filter(struct sspt_proc *proc,
			      void (*func)(struct sspt_filter *, void *),
			      void *data);

void sspt_proc_on_each_ip(struct sspt_proc *proc,
			  void (*func)(struct us_ip *, void *), void *data);

bool sspt_proc_is_send_event(struct sspt_proc *proc);

int sspt_proc_cb_set(struct sspt_proc_cb *cb);
void sspt_proc_priv_create(struct sspt_proc *proc);
void sspt_proc_priv_destroy(struct sspt_proc *proc);

#endif /* __SSPT_PROC__ */
