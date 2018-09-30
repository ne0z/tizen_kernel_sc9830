/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/ip.c
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
 * 2013         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */

#include <linux/slab.h>
#include <linux/module.h>
#include "ip.h"
#include "sspt_page.h"
#include "sspt_file.h"
#include <us_manager/probes/use_probes.h>

/**
 * @brief Create us_ip struct
 *
 * @param page User page
 * @param offset Function offset from the beginning of the page
 * @param probe_i Pointer to the probe data.
 * @param page Pointer to the parent sspt_page struct
 * @return Pointer to the created us_ip struct
 */
struct us_ip *create_ip(unsigned long offset, const struct probe_info *info,
			struct sspt_page *page)
{
	struct us_ip *ip;
	struct probe_info *info_new;

	info_new = probe_info_dup(info);
	if (info_new == NULL) {
		printk("Cannot probe_info_dup in %s function!\n", __func__);
		return NULL;
	}

	ip = kmalloc(sizeof(*ip), GFP_ATOMIC);
	if (ip != NULL) {
		memset(ip, 0, sizeof(*ip));

		INIT_LIST_HEAD(&ip->list);
		ip->offset = offset;
		ip->page = page;

		probe_info_copy(info, info_new);
		probe_info_init(info_new, ip);
		ip->info = info_new;
	} else {
		printk(KERN_INFO "Cannot kmalloc in create_ip function!\n");
		probe_info_free(info_new);
	}

	return ip;
}

/**
 * @brief Remove us_ip struct
 *
 * @param ip remove object
 * @return Void
 */
void free_ip(struct us_ip *ip)
{
	probe_info_uninit(ip->info, ip);
	probe_info_free(ip->info);
	kfree(ip);
}
