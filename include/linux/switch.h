/*
 *  Switch class driver
 *
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
*/

#ifndef __LINUX_SWITCH_H__
#define __LINUX_SWITCH_H__

struct switch_dev {
	const char	*name;
	struct device	*dev;
	int		index;
	int		state;

	ssize_t	(*print_name)(struct switch_dev *sdev, char *buf);
	ssize_t	(*print_state)(struct switch_dev *sdev, char *buf);
};

struct gpio_switch_platform_data {
	const char *name;
	unsigned 	gpio;

	/* if NULL, switch_dev.name will be printed */
	const char *name_on;
	const char *name_off;
	/* if NULL, "0" or "1" will be printed */
	const char *state_on;
	const char *state_off;
};

extern int switch_dev_register(struct switch_dev *sdev);
extern void switch_dev_unregister(struct switch_dev *sdev);

static inline int switch_get_state(struct switch_dev *sdev)
{
	return sdev->state;
}

extern void switch_set_state(struct switch_dev *sdev, int state);

#ifdef CONFIG_SWITCH
struct sec_switch_data {
	void (*init_cb) (void);
	void (*dock_cb) (u8 type);
	void (*usb_cb)  (u8 attached);
	void (*otg_cb)  (u8 attached);
	void (*cable_chg_cb) (int cable_type);
	void (*set_jig_state_cb) (u8 jig_attached);
#ifdef CONFIG_MUIC_SUPPORT_PS_CABLE
	void (*ps_cable_cb) (u8 attached);
#endif
};
#endif
#endif /* __LINUX_SWITCH_H__ */
