/*
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
 * Copyright (C) Samsung Electronics, 2015
 *
 * 2015         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <writer/swap_msg.h>
#include <kprobe/swap_kprobes.h>
#include <ksyms/ksyms.h>
#include "nsp_tdata.h"
#include "nsp_print.h"


/* ============================================================================
 * =                                priv_tdata                                =
 * ============================================================================
 */
struct priv_tdata {
	struct list_head list;
	struct task_struct *task;

	struct tdata tdata;
};


static LIST_HEAD(task_list);
static DEFINE_SPINLOCK(task_list_lock);


/* called with task_list_lock held */
static struct priv_tdata *priv_tdata_create(struct task_struct *task)
{
	struct priv_tdata *p_tdata;

	p_tdata = kmalloc(sizeof(*p_tdata), GFP_ATOMIC);
	if (p_tdata) {
		INIT_LIST_HEAD(&p_tdata->list);
		p_tdata->task = task;

		/* add to list */
		list_add(&p_tdata->list, &task_list);
	}

	return p_tdata;
}

/* called with task_list_lock held */
static void priv_tdata_destroy(struct priv_tdata *p_tdata)
{
	/* delete from list */
	list_del(&p_tdata->list);

	kfree(p_tdata);
}

/* called with task_list_lock held */
static void __priv_tdata_destroy(struct tdata *tdata)
{
	struct priv_tdata *p_tdata;

	p_tdata = container_of(tdata, struct priv_tdata, tdata);
	priv_tdata_destroy(p_tdata);
}

/* called with task_list_lock held */
static void priv_tdata_destroy_all(void)
{
	struct priv_tdata *p_tdata, *n;

	list_for_each_entry_safe(p_tdata, n, &task_list, list)
		priv_tdata_destroy(p_tdata);
}





/* ============================================================================
 * =                                  tdata                                   =
 * ============================================================================
 */
struct tdata *tdata_create(struct task_struct *task)
{
	struct priv_tdata *p_tdata;

	spin_lock(&task_list_lock);
	p_tdata = priv_tdata_create(task);
	if (p_tdata)
		return &p_tdata->tdata;
	spin_unlock(&task_list_lock);

	return NULL;

}

void tdata_destroy(struct tdata *tdata)
{
	__priv_tdata_destroy(tdata);
	spin_unlock(&task_list_lock);
}

struct tdata *tdata_find(struct task_struct *task)
{
	struct priv_tdata *p_tdata;

	list_for_each_entry(p_tdata, &task_list, list) {
		if (p_tdata->task == task)
			return &p_tdata->tdata;
	}

	return NULL;
}

struct tdata *tdata_get(struct task_struct *task)
{
	struct tdata *tdata;

	spin_lock(&task_list_lock);
	tdata = tdata_find(task);
	if (tdata)
		return tdata;
	spin_unlock(&task_list_lock);

	return NULL;
}

void tdata_put(struct tdata *tdata)
{
	spin_unlock(&task_list_lock);
}





/* ============================================================================
 * =                                 do_exit                                  =
 * ============================================================================
 */
static int do_exit_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tdata *tdata;

	tdata = tdata_get(current);
	if (tdata)
		tdata_destroy(tdata);

	return 0;
}

struct kprobe do_exit_kp = {
	.pre_handler = do_exit_handler,
};

int tdata_enable(void)
{
	int ret;

	ret = swap_register_kprobe(&do_exit_kp);
	if (ret)
		return ret;

	return ret;
}

void tdata_disable(void)
{
	swap_unregister_kprobe(&do_exit_kp);

	spin_lock(&task_list_lock);
	priv_tdata_destroy_all();
	spin_unlock(&task_list_lock);
}

int tdata_once(void)
{
	const char *sym;

	sym = "do_exit";
	do_exit_kp.addr = (void *)swap_ksyms(sym);
	if (do_exit_kp.addr == NULL)
		goto not_found;

	return 0;

not_found:
	nsp_print("ERROR: symbol '%s' not found\n", sym);
	return -ESRCH;
}
