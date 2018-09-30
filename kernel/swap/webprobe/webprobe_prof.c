/**
 *  webprobe/webprobe_prof.c
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
 * Copyright (C) Samsung Electronics, 2015
 *
 * 2015		 Anastasia Lyupa <a.lyupa@samsung.com>
 *
 */


#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>

#include <us_manager/pf/pf_group.h>
#include <us_manager/probes/probes.h>

#include "webprobe_prof.h"


static DEFINE_MUTEX(mutex_enable);

struct web_prof_data {
	struct dentry *app_dentry;
	struct dentry *lib_dentry;
	struct pf_group *pfg;
	u64 inspserver_addr;
	u64 willexecute_addr;
	u64 didexecute_addr;
	enum web_prof_state_t enabled;
};

static const char *LIBEWEBKIT2_PATH = "/usr/lib/libewebkit2.so.0";
static struct web_prof_data *web_data;


u64 *web_prof_addr_ptr(enum web_prof_addr_t type)
{
	u64 *addr_ptr;

	switch (type) {
	case INSPSERVER_START:
		addr_ptr = &web_data->inspserver_addr;
		break;
	case WILL_EXECUTE:
		addr_ptr = &web_data->willexecute_addr;
		break;
	case DID_EXECUTE:
		addr_ptr = &web_data->didexecute_addr;
		break;
	default:
		pr_err("ERROR: WEB_PROF_ADDR_PTR_TYPE=0x%x\n", type);
		addr_ptr = NULL;
	}

	return addr_ptr;
}

unsigned long web_prof_addr(enum web_prof_addr_t type)
{
	unsigned long addr;

	switch (type) {
	case INSPSERVER_START:
		addr = web_data->inspserver_addr;
		break;
	case WILL_EXECUTE:
		addr = web_data->willexecute_addr;
		break;
	case DID_EXECUTE:
		addr = web_data->didexecute_addr;
		break;
	default:
		pr_err("ERROR: WEB_PROF_ADDR_TYPE=0x%x\n", type);
		addr = 0;
	}

	return addr;
}

static int web_func_inst_add(unsigned long addr)
{
	int ret;
	struct probe_info probe;

	probe.probe_type = SWAP_WEBPROBE;
	probe.size = 0;

	ret = pf_register_probe(web_data->pfg, web_data->lib_dentry,
				addr, &probe);

	return ret;
}

int web_func_inst_remove(unsigned long addr)
{
	int ret;

	/* FIXME: check that address needs removing */
	ret = pf_unregister_probe(web_data->pfg, web_data->lib_dentry,
				  addr);

	return ret;
}

int web_prof_data_set(char *app_path, char *app_id)
{
	web_data->app_dentry = dentry_by_path(app_path);
	if (web_data->app_dentry == NULL)
		return -EFAULT;

	web_data->lib_dentry = dentry_by_path(LIBEWEBKIT2_PATH);
	if (web_data->lib_dentry == NULL)
		return -EFAULT;

	if (web_data->pfg)
		put_pf_group(web_data->pfg);

	web_data->pfg = get_pf_group_by_comm(app_id, web_data->app_dentry);
	if (web_data->pfg == NULL)
		return -EFAULT;

	return 0;
}

struct dentry *web_prof_lib_dentry(void)
{
	return web_data->lib_dentry;
}

enum web_prof_state_t web_prof_enabled(void)
{
	return web_data->enabled;
}

int web_prof_enable(void)
{
	int ret = 0;

	mutex_lock(&mutex_enable);
	if (web_data->enabled == PROF_OFF) {
		web_data->enabled = PROF_ON;

		if ((web_data->inspserver_addr == 0) ||
		    (web_data->willexecute_addr == 0) ||
		    (web_data->didexecute_addr == 0)) {
			pr_err("ERROR: Can't enable web profiling\n");
			ret = -EFAULT;
		} else {
			web_func_inst_add(web_data->inspserver_addr);
			web_func_inst_add(web_data->willexecute_addr);
			web_func_inst_add(web_data->didexecute_addr);
		}
	} else {
		pr_err("ERROR: Web profiling is already enabled\n");
	}
	mutex_unlock(&mutex_enable);

	return ret;
}

int web_prof_disable(void)
{
	int ret = 0;

	mutex_lock(&mutex_enable);
	if (web_data->enabled == PROF_ON) {
		web_data->enabled = PROF_OFF;

		if ((web_data->inspserver_addr == 0) ||
		    (web_data->willexecute_addr == 0) ||
		    (web_data->didexecute_addr == 0)) {
			pr_err("ERROR: Can't disable web profiling\n");
			ret = -EFAULT;
		} else {
			web_func_inst_remove(web_data->inspserver_addr);
			web_func_inst_remove(web_data->willexecute_addr);
			web_func_inst_remove(web_data->didexecute_addr);
		}
	} else {
		pr_err("ERROR: Web profiling is already disabled\n");
	}
	mutex_unlock(&mutex_enable);

	return ret;
}

int web_prof_init(void)
{
	web_data = kmalloc(sizeof(*web_data), GFP_KERNEL);
	if (web_data == NULL)
		return -ENOMEM;

	memset(web_data, 0, sizeof(struct web_prof_data));

	web_data->enabled = PROF_OFF;

	return 0;
}


void web_prof_exit(void)
{
	if (web_data->pfg)
		put_pf_group(web_data->pfg);

	kfree(web_data);
}
