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

#ifndef _NSP_TDATA_H
#define _NSP_TDATA_H


#include <linux/types.h>
#include <us_manager/probes/probe_info_new.h>


enum nsp_proc_stat {
	NPS_OPEN_E,		/* mapping begin */
	NPS_OPEN_R,
	NPS_SYM_E,
	NPS_SYM_R,		/* mapping end   */
	NPS_MAIN_E,		/* main begin    */
	NPS_AC_EFL_MAIN_E,	/* main end      */
	NPS_AC_INIT_R,		/* create begin  */
	NPS_ELM_RUN_E,		/* create end    */
	NPS_DO_APP_E,		/* reset begin   */
	NPS_DO_APP_R		/* reset end     */
};


struct nsp_data;
struct task_struct;


struct tdata {
	enum nsp_proc_stat stat;
	struct nsp_data *nsp_data;
	u64 time;
	void *handle;
	struct probe_new p_main;
};


struct tdata *tdata_create(struct task_struct *task);
void tdata_destroy(struct tdata *tdata);

struct tdata *tdata_get(struct task_struct *task);
void tdata_put(struct tdata *tdata);

int tdata_enable(void);
void tdata_disable(void);

int tdata_once(void);


#endif /* _NSP_TDATA_H */
