#ifndef __IP__
#define __IP__

/**
 * @file us_manager/sspt/ip.h
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

#include <linux/list.h>
#include <uprobe/swap_uprobes.h>
#include <us_manager/probes/probes.h>

struct sspt_page;

/**
 * @struct us_ip
 * @breaf Image of instrumentation pointer for specified process
 */
struct us_ip {
	struct list_head list;      /**< For sspt_page */
	struct sspt_page *page;     /**< Pointer on the page (parent) */
	struct probe_info *info;    /**< Probe's data */

	unsigned long orig_addr;    /**< Function address */
	unsigned long offset;       /**< Page offset */

	union {
		struct uretprobe retprobe;
		struct uprobe uprobe;
	};
};

#define to_us_ip(rp) container_of(rp, struct us_ip, retprobe)

struct us_ip *create_ip(unsigned long offset, const struct probe_info *info,
			struct sspt_page *page);
void free_ip(struct us_ip *ip);

#endif /* __IP__ */
