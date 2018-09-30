#ifndef _UIHV_H
#define _UIHV_H

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


#include <us_manager/probes/probe_info_new.h>


struct dentry;
struct pf_group;

struct uihv_data {
	struct dentry *dentry;
	struct probe_new p_main;
	struct pf_group *pfg;
};

enum uihv_state {
	UIHV_DISABLE,
	UIHV_ENABLE
};


int uihv_data_set(const char *app_path, unsigned long main_addr);

int uihv_set_state(enum uihv_state st);
enum uihv_state uihv_get_state(void);

int uihv_init(void);
void uihv_uninit(void);


#endif /* _UIHV_H */
