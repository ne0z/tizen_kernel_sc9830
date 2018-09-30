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
 * Copyright (C) Samsung Electronics, 2016
 *
 * 2016         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <us_manager/pf/pf_group.h>
#include "uihv.h"
#include "preload_module.h"


static int uihv_data_inst(struct uihv_data *ui_data)
{
	int ret;
	struct pf_group *pfg;
	struct dentry *dentry = ui_data->dentry;

	pfg = get_pf_group_by_dentry(dentry, (void *)dentry);
	if (pfg == NULL)
		return -ENOMEM;

	ret = pin_register(&ui_data->p_main, pfg, dentry);
	if (ret)
		goto put_g;

	ui_data->pfg = pfg;

	return 0;
put_g:
	put_pf_group(pfg);
	return ret;
}

static void uihv_data_uninst(struct uihv_data *ui_data)
{
	struct pf_group *pfg = ui_data->pfg;

	pin_unregister(&ui_data->p_main, pfg, ui_data->dentry);
	put_pf_group(pfg);

	ui_data->pfg = NULL;
}


static DEFINE_MUTEX(state_mutex);
static enum uihv_state state = UIHV_DISABLE;

static struct uihv_data uihv_data;

static bool is_init(void)
{
	return !!uihv_data.dentry;
}

static int do_uihv_data_set(const char *app_path, unsigned long main_addr)
{
	struct dentry *dentry;

	dentry = dentry_by_path(app_path);
	if (dentry == NULL)
		return -ENOENT;

	uihv_data.dentry = dentry;
	uihv_data.p_main.info = uihv_pin_main();
	uihv_data.p_main.offset = main_addr;
	uihv_data.pfg = NULL;

	return 0;
}

int uihv_data_set(const char *app_path, unsigned long main_addr)
{
	int ret;

	mutex_lock(&state_mutex);
	if (state == UIHV_DISABLE)
		ret = do_uihv_data_set(app_path, main_addr);
	else
		ret = -EBUSY;
	mutex_unlock(&state_mutex);

	return ret;
}

static int uihv_enable(void)
{
	int ret;

	if (is_init() == false)
		return -EPERM;

	if (state == UIHV_ENABLE)
		return -EINVAL;

	ret = uihv_data_inst(&uihv_data);
	if (ret)
		return ret;

	state = UIHV_ENABLE;

	return 0;
}

static int uihv_disable(void)
{
	if (state == UIHV_DISABLE)
		return -EINVAL;

	uihv_data_uninst(&uihv_data);

	state = UIHV_DISABLE;

	return 0;
}

int uihv_set_state(enum uihv_state st)
{
	int ret = -EINVAL;

	mutex_lock(&state_mutex);
	switch (st) {
	case UIHV_DISABLE:
		ret = uihv_disable();
		break;
	case UIHV_ENABLE:
		ret = uihv_enable();
		break;
	}
	mutex_unlock(&state_mutex);

	return ret;
}

enum uihv_state uihv_get_state(void)
{
	return state;
}

int uihv_init(void)
{
	state = UIHV_DISABLE;
	uihv_data.dentry = NULL;

	return 0;
}

void uihv_uninit(void)
{
	uihv_disable();
}
