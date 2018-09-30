/*
 *  SWAP uprobe manager
 *  modules/us_manager/probes/preload_probe.c
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
 * Copyright (C) Samsung Electronics, 2014
 *
 * 2014	 Alexander Aksenov: Preload implement
 *
 */

#include <linux/module.h>
#include <us_manager/us_manager.h>
#include <us_manager/probes/register_probes.h>
#include <us_manager/sspt/sspt_page.h>
#include <uprobe/swap_uprobes.h>
#include <us_manager/sspt/ip.h>
#include "preload_probe.h"
#include "preload.h"
#include "preload_module.h"
#include "preload_debugfs.h"

static unsigned long long probes_count = 0;

static int preload_info_copy(struct probe_info *dest,
			      const struct probe_info *source)
{
	memcpy(dest, source, sizeof(*source));

	return 0;
}

static void preload_info_cleanup(struct probe_info *probe_i)
{
}

static struct uprobe *preload_get_uprobe(struct us_ip *ip)
{
	return &ip->retprobe.up;
}

/* We count all preload probes to know current state of the preload module:
 * if there are registered probes, than it is currently running, if there is no
 * probes, module is just ready to be used.
 *
 * If there was no registered probes and now they're appeared, change state to
 * 'running'.
 */
static inline void inc_probes(void)
{
	if (probes_count == 0)
		preload_module_set_running();

	probes_count++;
}

/* If there were probes, but now there's no of them, change state to 'ready'.
 */
static inline void dec_probes(void)
{
	if (unlikely(probes_count == 0))
		printk(KERN_ERR PRELOAD_PREFIX "Trying to remove probe when there is no one!\n");

	probes_count--;
	if (probes_count == 0)
		preload_module_set_ready();
}

/* Checks if preload can be in 'ready' state. It is so, if loader's dentry and
 * offset are specified.
 */
static inline bool can_be_ready(void)
{
	struct dentry *dentry = preload_debugfs_get_loader_dentry();
	unsigned long offset = preload_debugfs_get_loader_offset();

	if (dentry != NULL && offset != 0)
		return true;

	return false;
}

/* Registers probe if preload is 'running' or 'ready'.
 */
static int preload_register_probe(struct us_ip *ip)
{
	if (preload_module_is_not_ready()) {
		if (can_be_ready()) {
			preload_module_set_ready();
		} else {
			printk(PRELOAD_PREFIX "Module is not initialized!\n");
			return -EINVAL;
		}
	}

	inc_probes();

	return swap_register_uretprobe(&ip->retprobe);
}

static void preload_unregister_probe(struct us_ip *ip, int disarm)
{
	__swap_unregister_uretprobe(&ip->retprobe, disarm);

	dec_probes();
}

static void preload_init(struct us_ip *ip)
{
	preload_module_uprobe_init(ip);
}

static void preload_uninit(struct us_ip *ip)
{
	preload_module_uprobe_exit(ip);

	preload_info_cleanup(ip->info);
}

static struct probe_iface preload_iface = {
	.init = preload_init,
	.uninit = preload_uninit,
	.reg = preload_register_probe,
	.unreg = preload_unregister_probe,
	.get_uprobe = preload_get_uprobe,
	.copy = preload_info_copy,
	.cleanup = preload_info_cleanup
};

static int get_caller_info_copy(struct probe_info *dest,
				const struct probe_info *source)
{
	memcpy(dest, source, sizeof(*source));

	return 0;
}

static void get_caller_info_cleanup(struct probe_info *probe_i)
{
}

static struct uprobe *get_caller_get_uprobe(struct us_ip *ip)
{
	return &ip->uprobe;
}

static int get_caller_register_probe(struct us_ip *ip)
{
	return swap_register_uprobe(&ip->uprobe);
}

static void get_caller_unregister_probe(struct us_ip *ip, int disarm)
{
	__swap_unregister_uprobe(&ip->uprobe, disarm);
}

static void get_caller_init(struct us_ip *ip)
{
	preload_module_get_caller_init(ip);
}

static void get_caller_uninit(struct us_ip *ip)
{
	preload_module_get_caller_exit(ip);

	get_caller_info_cleanup(ip->info);
}

static struct probe_iface get_caller_iface = {
	.init = get_caller_init,
	.uninit = get_caller_uninit,
	.reg = get_caller_register_probe,
	.unreg = get_caller_unregister_probe,
	.get_uprobe = get_caller_get_uprobe,
	.copy = get_caller_info_copy,
	.cleanup = get_caller_info_cleanup
};

static void get_call_type_init(struct us_ip *ip)
{
	preload_module_get_call_type_init(ip);
}

static void get_call_type_uninit(struct us_ip *ip)
{
	preload_module_get_call_type_exit(ip);

	get_caller_info_cleanup(ip->info);
}

static struct probe_iface get_call_type_iface = {
	.init = get_call_type_init,
	.uninit = get_call_type_uninit,
	.reg = get_caller_register_probe,
	.unreg = get_caller_unregister_probe,
	.get_uprobe = get_caller_get_uprobe,
	.copy = get_caller_info_copy,
	.cleanup = get_caller_info_cleanup
};

static void write_msg_init(struct us_ip *ip)
{
	preload_module_write_msg_init(ip);
}

static int write_msg_reg(struct us_ip *ip)
{
	ip->uprobe.atomic_ctx = false;

	return get_caller_register_probe(ip);
}

static void write_msg_uninit(struct us_ip *ip)
{
	preload_module_write_msg_exit(ip);

	get_caller_info_cleanup(ip->info);
}

static struct probe_iface write_msg_iface = {
	.init = write_msg_init,
	.uninit = write_msg_uninit,
	.reg = write_msg_reg,
	.unreg = get_caller_unregister_probe,
	.get_uprobe = get_caller_get_uprobe,
	.copy = get_caller_info_copy,
	.cleanup = get_caller_info_cleanup
};

int register_preload_probes(void)
{
	int ret;

	ret = swap_register_probe_type(SWAP_PRELOAD_PROBE, &preload_iface);
	if (ret != 0)
		return ret;

	ret = swap_register_probe_type(SWAP_GET_CALLER, &get_caller_iface);
	if (ret != 0)
		return ret;

	ret = swap_register_probe_type(SWAP_GET_CALL_TYPE, &get_call_type_iface);
	if (ret != 0)
		return ret;

	ret = swap_register_probe_type(SWAP_WRITE_MSG, &write_msg_iface);

	return ret;
}

void unregister_preload_probes(void)
{
	swap_unregister_probe_type(SWAP_PRELOAD_PROBE);
	swap_unregister_probe_type(SWAP_GET_CALLER);
	swap_unregister_probe_type(SWAP_GET_CALL_TYPE);
	swap_unregister_probe_type(SWAP_WRITE_MSG);
}
