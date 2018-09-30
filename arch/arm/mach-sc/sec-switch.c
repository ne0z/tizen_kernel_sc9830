/*
 * arch/arm/mach-sc/sec-switch.c
 *
 * c source file supporting MUIC common platform device register
 *
 * Copyright (C) 2014 Samsung Electronics
 * tyung.kim <tyung.kim@samsung.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/power_supply.h>
#include <linux/module.h>
#include <linux/usb/gadget.h>
#include <linux/regulator/consumer.h>
#include <linux/mfd/sm5701_core.h>

#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
#include <linux/i2c/ist30xxc.h>
#endif

#ifdef CONFIG_TOUCHSCREEN_ZINITIX_BT432
#include <linux/i2c/zinitix_ts.h>
#endif

#ifdef CONFIG_MFD_SM5504
#include <linux/mfd/sm5504.h>
#endif

#ifdef CONFIG_SWITCH
#include <linux/switch.h>
static struct switch_dev switch_dock = {
	.name = "dock",
};

static struct switch_dev switch_usb = {
	.name = "usb_cable",
};

static struct switch_dev switch_otg = {
	.name = "otg",
};

static struct switch_dev switch_jig = {
	.name = "jig_cable",
};
/* Samsung's Power Sharing Cable EP-SG900 */
#ifdef CONFIG_MUIC_SUPPORT_PS_CABLE
static struct switch_dev switch_ps_cable = {
        .name = "ps_cable",
};
#endif
#endif /* CONFIG_SWITCH */

extern struct class *sec_class;
struct device *switch_device;
EXPORT_SYMBOL(switch_device);

#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
struct tsp_callbacks *ist30xxc_charger_callbacks;
void ist30xxc_tsp_charger_infom(int cable_type)
{
	if (ist30xxc_charger_callbacks && ist30xxc_charger_callbacks->inform_charger)
		ist30xxc_charger_callbacks->inform_charger(ist30xxc_charger_callbacks, cable_type);
}
#endif

#ifdef CONFIG_TOUCHSCREEN_ZINITIX_BT432
struct tsp_callbacks *zinitix_charger_callbacks;
void zinitix_tsp_charger_infom(int cable_type)
{
	if (zinitix_charger_callbacks && zinitix_charger_callbacks->inform_charger)
		zinitix_charger_callbacks->inform_charger(zinitix_charger_callbacks, cable_type);
}
void zinitix_tsp_register_callback(struct tsp_callbacks *cb)
{
	zinitix_charger_callbacks = cb;
	pr_info("%s\n", __func__);
}
#endif

static void muic_init_cb(void)
{
#ifdef CONFIG_SWITCH
	int ret;
	pr_info("func:%s\n", __func__);

	ret = switch_dev_register(&switch_dock);
	if (ret < 0)
		pr_err("%s Failed to register dock switch(%d)\n", __func__, ret);

	ret = switch_dev_register(&switch_usb);
	if (ret < 0)
		pr_err("%s Failed to register usb switch(%d)\n", __func__, ret);

	ret = switch_dev_register(&switch_otg);
	if (ret < 0)
		pr_err("%s Failed to register otg switch(%d)\n", __func__, ret);

	ret = switch_dev_register(&switch_jig);
	if (ret < 0)
		pr_err("%s Failed to register jig switch(%d)\n", __func__, ret);

#ifdef CONFIG_MUIC_SUPPORT_PS_CABLE
        ret = switch_dev_register(&switch_ps_cable);
        if (ret < 0)
                pr_err("%s Failed to register ps_cable switch(%d)\n", __func__, ret);
#endif
#endif
}

extern void usb_notify_cb(int plug_in);

static void muic_usb_cb(u8 attached)
{
	pr_info("%s: usb_mode:%d\n", __func__, attached);
	usb_notify_cb(attached);

#ifdef CONFIG_SWITCH
	switch_set_state(&switch_usb, attached);
#endif
	return;
}

static void muic_otg_cb(u8 attached)
{
	pr_info("%s: otg_mode:%d\n", __func__, attached);



#ifdef CONFIG_SWITCH
	switch_set_state(&switch_otg, attached);
#endif

#ifdef CONFIG_MFD_SM5504
	if (attached) {
		SM5701_set_bstout(SM5701_BSTOUT_5P0);
		SM5701_set_operationmode(SM5701_OPERATIONMODE_OTG_ON);
	}
	else {
		SM5701_set_bstout(SM5701_BSTOUT_4P5);
		SM5701_clear_operationmode(SM5701_OPERATIONMODE_OTG_ON);
	}
#endif

	return;
}

#ifdef CONFIG_TOUCHSCREEN_IST30XXB
void charger_enable(int enable);
#endif

bool is_jig_on;
#ifdef CONFIG_MFD_SM5504
extern int current_cable_type;
#endif

static void muic_charger_cb(int cable_type)
{
	struct power_supply *psy = power_supply_get_by_name("battery");
	union  power_supply_propval value;

	pr_info("%s: cable type (0x%02x)\n", __func__, cable_type);

#ifdef CONFIG_TOUCHSCREEN_ZINITIX_BT432
	zinitix_tsp_charger_infom(cable_type);
#endif

#ifdef CONFIG_MFD_SM5504
	switch (cable_type) {
		case MUIC_SM5504_CABLE_TYPE_NONE:
		case MUIC_SM5504_CABLE_TYPE_UNKNOWN:
			current_cable_type = POWER_SUPPLY_TYPE_BATTERY;
			is_jig_on = false;
#ifdef CONFIG_TOUCHSCREEN_IST30XXB
			charger_enable(0);
#endif
#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
			ist30xxc_tsp_charger_infom(0);
#endif
			break;
		case MUIC_SM5504_CABLE_TYPE_USB:
		case MUIC_SM5504_CABLE_TYPE_CDP:
		case MUIC_SM5504_CABLE_TYPE_L_USB:
		case MUIC_SM5504_CABLE_TYPE_0x15:
		case MUIC_SM5504_CABLE_TYPE_TYPE1_CHARGER:
			current_cable_type = POWER_SUPPLY_TYPE_USB;
			is_jig_on = false;
#ifdef CONFIG_TOUCHSCREEN_IST30XXB
			charger_enable(1);
#endif
#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
			ist30xxc_tsp_charger_infom(1);
#endif
			break;
		case MUIC_SM5504_CABLE_TYPE_REGULAR_TA:
			current_cable_type = POWER_SUPPLY_TYPE_MAINS;
			is_jig_on = false;
#ifdef CONFIG_TOUCHSCREEN_IST30XXB
			charger_enable(1);
#endif
#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
			ist30xxc_tsp_charger_infom(1);
#endif
			break;
		case MUIC_SM5504_CABLE_TYPE_ATT_TA:
			current_cable_type = POWER_SUPPLY_TYPE_UPS;
			is_jig_on = false;
#ifdef CONFIG_TOUCHSCREEN_IST30XXB
			charger_enable(1);
#endif
#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
			ist30xxc_tsp_charger_infom(1);
#endif
			break;
#ifdef CONFIG_MUIC_SUPPORT_PS_CABLE
		case MUIC_SM5504_CABLE_TYPE_SAMSUNG_PS:
			current_cable_type = POWER_SUPPLY_TYPE_POWER_SHARING;
			is_jig_on = false;
			break;
#endif
		case MUIC_SM5504_CABLE_TYPE_OTG:
#if 0 /*def CONFIG_MACH_KIRAN*/
			current_cable_type = POWER_SUPPLY_TYPE_USB;
			is_jig_on = false;
#else
			goto skip;
#endif
		case MUIC_SM5504_CABLE_TYPE_JIG_UART_OFF_WITH_VBUS:
		case MUIC_SM5504_CABLE_TYPE_JIG_UART_ON_WITH_VBUS:
			current_cable_type = POWER_SUPPLY_TYPE_UARTOFF;
			is_jig_on = true;
			break;
		case MUIC_SM5504_CABLE_TYPE_JIG_UART_OFF:
		case MUIC_SM5504_CABLE_TYPE_JIG_UART_ON:
			current_cable_type = POWER_SUPPLY_TYPE_BATTERY;
			is_jig_on = true;
			break;
		case MUIC_SM5504_CABLE_TYPE_JIG_USB_ON:
		case MUIC_SM5504_CABLE_TYPE_JIG_USB_OFF:
			current_cable_type = POWER_SUPPLY_TYPE_USB;
			is_jig_on = true;
#ifdef CONFIG_TOUCHSCREEN_IST30XXB
			charger_enable(1);
#endif
#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
			ist30xxc_tsp_charger_infom(1);
#endif
			break;
		case MUIC_SM5504_CABLE_TYPE_0x1A:
		case MUIC_SM5504_CABLE_TYPE_UART:
			current_cable_type = POWER_SUPPLY_TYPE_MAINS;
			is_jig_on = false;
#ifdef CONFIG_TOUCHSCREEN_IST30XXB
			charger_enable(1);
#endif
#ifdef CONFIG_TOUCHSCREEN_IMAGIS_IST30XXC
			ist30xxc_tsp_charger_infom(1);
#endif
			break;
		default:
			pr_err("%s: invalid type for charger:%d\n",
					__func__, cable_type);
			current_cable_type = POWER_SUPPLY_TYPE_UNKNOWN;
			goto skip;
	}

	if (!psy || !psy->set_property)
		pr_err("%s: fail to get battery psy\n", __func__);
	else {
		value.intval = current_cable_type;
		psy->set_property(psy, POWER_SUPPLY_PROP_ONLINE, &value);
	}
#endif

skip:
	return;
}

static void muic_dock_cb(u8 type)
{
	pr_info("%s: type: %d\n", __func__, type);

#ifdef CONFIG_SWITCH
	switch_set_state(&switch_dock, type);
#endif
}

bool is_jig_attached;
int muic_get_jig_state(void)
{
	return is_jig_attached;
}
EXPORT_SYMBOL(muic_get_jig_state);

static void muic_set_jig_state(u8 attached)
{
	pr_info("%s: attached: %d\n", __func__, attached);
	is_jig_attached = !!attached;

#ifdef CONFIG_SWITCH
	switch_set_state(&switch_jig, !!attached);
#endif
}

#ifdef CONFIG_MUIC_SUPPORT_PS_CABLE
static void muic_ps_cable_cb(u8 attached)
{
        pr_info("%s: ps_cable: %d\n", __func__, attached);

#ifdef CONFIG_SWITCH
        switch_set_state(&switch_ps_cable, attached);
#endif
}
#endif

struct sec_switch_data switch_data = {
	.init_cb = muic_init_cb,
	.dock_cb = muic_dock_cb,
	.usb_cb  = muic_usb_cb,
	.otg_cb  = muic_otg_cb,
	.cable_chg_cb = muic_charger_cb,
	.set_jig_state_cb = muic_set_jig_state,
#ifdef CONFIG_MUIC_SUPPORT_PS_CABLE
	.ps_cable_cb = muic_ps_cable_cb,
#endif
};

static int __init sec_switch_init(void)
{
	if (!sec_class) {
		pr_err("%s: sec_class is null\n", __func__);
		return -ENODEV;
	}

	switch_device = device_create(sec_class, NULL, 0, NULL, "switch");
	if (IS_ERR(switch_device)) {
		pr_err("%s: Failed to create device(switch)!\n", __func__);
		return -ENODEV;
	}

	return 0;
};

device_initcall(sec_switch_init);
