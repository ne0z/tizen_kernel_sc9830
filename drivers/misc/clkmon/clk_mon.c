/*
 * driver/misc/clkmon/clk_mon.c
 *
 * Copyright (C) 2014 Samsung Electronics co. ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/clk_mon.h>
#include <soc/sprd/pm_debug.h>
#include "clk_mon_ioctl.h"
#include "clk_mon_scx35.h"
/* SPRD is based on regulator framework and not Domain based framework
 * hence, we need to get the status of the Parent regulators to check if
 * it is ON/OFF
*/
#include <linux/regulator/consumer.h>

#define SIZE_REG							0x4
#define CHECK_BIT_SET(var, pos)			((var) & (1<<(pos)))
#define BIT_ZERO							0x0
#define BIT_ONE							0x1

/* SPRD is based on regulator concept and hence we get the list
 * of regulators in the system. They are source of supply for
 * the consumers that are under them.
*/

struct power_domain_mask power_domain_masks[] = {
	{"vdd18"}, {"vdd28"}, {"vdd25"}, {"vddcon"}, {"vdddcxo"}, {"vddmem"},
	{"vddemmccore"}, {"vddrf0"}, {"vddcore"}, {"vddarm"}, {"vddgen"},
	{"vddrf"},{"vddsdcore"}, {"vddsim0"}, {"vddsim1"}, {"vddsim2"}, {"vddcama"},
	{"vddcamd"}, {"vddcamio"}, {"vddcammot"}, {"vddusb"}, {"vddwpa"},
	{"vddgen1"}, {"vddgen0"}, {"vddwifipa"}, {"vddsdio"}, {"vddvibr"},
	{"vddkpled"},
};

struct clk_gate_mask *clk_gate_masks = NULL;

static int clk_mon_ioc_check_reg(struct clk_mon_ioc_buf __user *uarg)
{
	struct clk_mon_ioc_buf *karg = NULL;
	void __iomem *v_addr = NULL;
	int size = sizeof(struct clk_mon_ioc_buf);
	int ret = -EFAULT;
	int i;

	if (!access_ok(VERIFY_WRITE, uarg, size))
		return -EFAULT;

	karg = kzalloc(size, GFP_KERNEL);

	if (!karg)
		return -ENOMEM;

	if (copy_from_user(karg, uarg, size)) {
		ret = -EFAULT;
		goto out;
	}

	for (i = 0; i < karg->nr_addrs; i++) {
		v_addr = ioremap((unsigned int)karg->reg[i].addr, SIZE_REG);
		karg->reg[i].value = ioread32(v_addr);
		iounmap(v_addr);
	}

	if (copy_to_user(uarg, karg, size)) {
		ret = -EFAULT;
		goto out;
	}
	ret = 0;

out:
	kfree(karg);
	return ret;
}

static int clk_mon_ioc_check_power_domain(struct clk_mon_ioc_buf __user *uarg)
{
	struct clk_mon_ioc_buf *karg = NULL;
	unsigned int dom_en = 0;
	int size = sizeof(struct clk_mon_ioc_buf);
	int ret = -EFAULT;
	int i;
	unsigned int num_domains = 0;
	static struct regulator *regulator_pm;

	if (!access_ok(VERIFY_WRITE, uarg, size))
		return -EFAULT;

	karg = kzalloc(size, GFP_KERNEL);

	if (!karg)
		return -ENOMEM;

	num_domains = sizeof(power_domain_masks)/sizeof(power_domain_masks[0]);

	for (i = 0; i < num_domains; i++) {
		regulator_pm = regulator_get(NULL, power_domain_masks[i].name);
		if (IS_ERR(regulator_pm)) {
			pr_err("%s - Failed to get [%s] regulator\n",
				__func__, power_domain_masks[i].name);
		} else {
			dom_en = regulator_is_enabled(regulator_pm);

			strlcpy(karg->reg[i].name,
					power_domain_masks[i].name,
					sizeof(karg->reg[i].name));
			karg->reg[i].value = dom_en;
			/* Free the regulator from the consumer list
				else suspend would be prevented */
			regulator_put(regulator_pm);
			regulator_pm = NULL;
			karg->nr_addrs++;
		}
	}

	if (copy_to_user(uarg, karg, size)) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	kfree(karg);
	return ret;
}

static int clk_mon_ioc_check_clock_gating(struct clk_mon_ioc_buf __user *uarg)
{
	struct clk_mon_ioc_buf *karg = NULL;
	unsigned int val = 0, value = 0;
	int size = sizeof(struct clk_mon_ioc_buf);
	int ret = -EFAULT;
	int i;
	void __iomem *v_addr = NULL;

	if (!access_ok(VERIFY_WRITE, uarg, size))
		return -EFAULT;

	karg = kzalloc(size, GFP_KERNEL);

	if (!karg)
		return -ENOMEM;

	for (i = 0; clk_gate_masks[i].addr != 0; i++) {
		v_addr = ioremap((unsigned int)clk_gate_masks[i].addr,
				SIZE_REG);
		value = ioread32(v_addr);
		val = CHECK_BIT_SET((unsigned int) value, (unsigned int)clk_gate_masks[i].bit_number);
		/* The output contains the register_name, address & value */
		strlcpy(karg->reg[i].name,
			clk_gate_masks[i].name,
			sizeof(karg->reg[i].name));
		karg->reg[i].addr = (void *) (&(clk_gate_masks[i].addr));
		karg->reg[i].value = val;
		karg->nr_addrs++;
	}

	if (copy_to_user(uarg, karg, size)) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	kfree(karg);
	return ret;
}

static int clk_mon_ioc_set_reg(struct clk_mon_reg_info __user *uarg)
{
	struct clk_mon_reg_info *karg = NULL;
	void __iomem *v_addr = NULL;
	int size = sizeof(struct clk_mon_reg_info);
	int ret = 0;

	if (!access_ok(VERIFY_READ, uarg, size))
		return -EFAULT;

	karg = kzalloc(size, GFP_KERNEL);

	if (!karg)
		return -ENOMEM;

	if (copy_from_user(karg, uarg, size)) {
		ret = -EFAULT;
		goto out;
	}

	v_addr = ioremap((unsigned int)karg->addr, SIZE_REG);
	iowrite32(karg->value, v_addr);
	iounmap(v_addr);

	ret = 0;

out:
	kfree(karg);
	return ret;
}

static long clk_mon_ioctl(struct file *filep, unsigned int cmd,
		unsigned long arg)
{
	struct clk_mon_ioc_buf __user *uarg = NULL;
	int ret = 0;

	pr_info("%s\n", __func__);

	if (!arg)
		return -EINVAL;

	uarg = (struct clk_mon_ioc_buf __user *)arg;

	switch (cmd) {
	case CLK_MON_IOC_CHECK_REG:
		ret = clk_mon_ioc_check_reg(uarg);
		break;
	case CLK_MON_IOC_CHECK_POWER_DOMAIN:
		ret = clk_mon_ioc_check_power_domain(uarg);
		break;
	case CLK_MON_IOC_CHECK_CLOCK_DOMAIN:
		ret = clk_mon_ioc_check_clock_gating(uarg);
		break;
	case CLK_MON_IOC_SET_REG:
		ret = clk_mon_ioc_set_reg(
				(struct clk_mon_reg_info __user *)arg);
		break;
	default:
		pr_err("%s:Invalid ioctl\n", __func__);
		ret = -EINVAL;
	}

	return ret;
}

static unsigned int g_reg_addr;
static unsigned int g_reg_value;

/* Useage - echo "Register_Address" "Value_to_be_set" > set_reg
	Eg. Input - echo 0x40038814 0x1 > set_reg
	>> Output - cat check_reg
	>> [0x40038814] 0x00000001
*/

static ssize_t clk_mon_store_check_reg(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int reg_addr = 0;
	char *cur = NULL;
	int ret = 0;

	if (!buf)
		return -EINVAL;

	cur = strnstr(buf, "0x", sizeof(buf));

	if (cur && cur + 2)
		ret = sscanf(cur + 2, "%x", &reg_addr);

	if (!ret)
		return -EINVAL;

	g_reg_addr = reg_addr;

	return size;
}

/* Useage - echo "Register_Address" > check_reg
	Eg. Input - echo 0x40038814 > check_reg
	>> Output - cat check_reg
	>> [0x40038814] 0x80000000
*/

static ssize_t clk_mon_show_check_reg(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	void __iomem *v_addr = NULL;
	unsigned int p_addr = 0;
	unsigned int value = 0;
	ssize_t size = 0;

	if (!g_reg_addr)
		return -EINVAL;

	p_addr = g_reg_addr;

	v_addr = ioremap(p_addr, SIZE_REG);
	value = ioread32(v_addr);
	iounmap(v_addr);

	size += snprintf(buf + size, CLK_MON_BUF_SIZE,
		"[0x%x] 0x%x\n", p_addr, value) + 1;

	return size + 1;
}

static ssize_t clk_mon_store_set_reg(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int reg_addr = 0;
	unsigned int reg_value = 0;
	void __iomem *v_addr = NULL;
	char tmp_addr[9] = {0};
	char *cur = NULL;

	if (!buf)
		return -EINVAL;

	cur = strnstr(buf, "0x", strlen(buf));

	if (!cur || !(cur + 2))
		return -EINVAL;

	strlcpy(tmp_addr, cur + 2, 8);

	if (!sscanf(tmp_addr, "%x", &reg_addr))
		return -EFAULT;

	cur = strnstr(&cur[2], "0x", strlen(&cur[2]));

	if (!cur || !(cur + 2))
		return -EINVAL;

	if (!sscanf(cur + 2, "%x", &reg_value))
		return -EFAULT;

	g_reg_addr  = reg_addr;
	g_reg_value = reg_value;

	v_addr = ioremap(g_reg_addr, SIZE_REG);
	iowrite32(g_reg_value, v_addr);
	iounmap(v_addr);

	return size;
}

static const int NR_BIT = 8 * sizeof(unsigned int);
static const int IDX_SHIFT = 5;

int clk_mon_power_domain(unsigned int *pm_status)
{
	unsigned int dom_en = 0;
	int i, bit_shift, idx;
	unsigned int num_domains = 0;
	static struct regulator *regulator_pm;
	/* In total, 62+ regulators are present */
	int bit_max = NR_BIT * PWR_DOMAINS_NUM;

	num_domains = sizeof(power_domain_masks)/sizeof(power_domain_masks[0]);

	/* Parse through the list of regulators & based on request from the
	consumers of the regulator, it would be enabled/disabled i.e. ON/OFF
	*/

	if (!pm_status || bit_max < 0 || num_domains <= 0)
		return -EINVAL;

	memset(pm_status, 0, sizeof(unsigned int) * PWR_DOMAINS_NUM);

	for (i = 0; i < num_domains; i++) {
		if (i > bit_max) {
			pr_err("%s: Error Exceed storage size %d(%d)\n",
				__func__, i, bit_max);
			break;
		}
		regulator_pm = regulator_get(NULL, power_domain_masks[i].name);
		if (IS_ERR(regulator_pm)) {
			pr_err("%s - Failed to get [%s] regulator\n",
				__func__, power_domain_masks[i].name);
		} else {
			idx = (i >> IDX_SHIFT);
			bit_shift = (i % NR_BIT);
			/* Check the regulator status */
			dom_en = regulator_is_enabled(regulator_pm);

			if (dom_en)
				pm_status[idx] |= (0x1 << bit_shift);
			else
				pm_status[idx] &= ~(0x1 << bit_shift);
			regulator_put(regulator_pm);
			regulator_pm = NULL;
		}
	}
	return i;
}

int clk_mon_get_power_info(unsigned int *pm_status, char *buf)
{
	int i, bit_shift, idx, size = 0;
	unsigned int num_domains = 0, dom_en = 0;
	int bit_max = NR_BIT * PWR_DOMAINS_NUM;

	num_domains = sizeof(power_domain_masks)/sizeof(power_domain_masks[0]);

	if  ((!pm_status) || (!buf) || (num_domains <= 0))
		return -EINVAL;

	for (i = 0; i < num_domains; i++) {
		if (i > bit_max) {
			pr_err("%s: Error Exceed storage size %d(%d)\n",
				__func__, i, NR_BIT);
			break;
		}

		bit_shift = i % NR_BIT;
		idx = i >> IDX_SHIFT;
		dom_en = 0;
		/* If the bit is set indicates that the regulator is enabled as
		observed in the API clk_mon_power_domain.
		*/
		dom_en = CHECK_BIT_SET(pm_status[idx], bit_shift);

		size += snprintf(buf + size, CLK_MON_BUF_SIZE,
				"[%-15s] %-3s\n",
				power_domain_masks[i].name,
				(dom_en) ? "on" : "off");
	}
	return size + 1;
}

int clk_mon_clock_gate(unsigned int *clk_status)
{
	int bit_max = NR_BIT * CLK_GATES_NUM;
	unsigned int val = 0;
	volatile unsigned int value = 0;
	unsigned long addr = 0;
	unsigned int clk_en = 0;
	int i, bit_shift, idx;

	if (!clk_status || bit_max < 0)
		return -EINVAL;

	memset(clk_status, 0, sizeof(unsigned int) * CLK_GATES_NUM);

	for (i = 0; clk_gate_masks[i].addr != 0; i++) {
		if (i >= bit_max) {
			pr_err("%s: Error Exceed storage size %d(%d)\n",
				__func__, i, bit_max);
			break;
		}

		if (addr != clk_gate_masks[i].addr) {
			addr = clk_gate_masks[i].addr;
			value = __raw_readl(clk_gate_masks[i].addr);
		}
		val = CHECK_BIT_SET(value,
			(unsigned int) clk_gate_masks[i].bit_number);
		clk_en = val;

		idx = i >> IDX_SHIFT;
		bit_shift = i % NR_BIT;

		if (!clk_en)
			clk_status[idx] &= ~(BIT_ONE << bit_shift);
		else
			clk_status[idx] |= (BIT_ONE << bit_shift);
	}
	return i;
}

int clk_mon_get_clock_info(unsigned int *clk_status, char *buf)
{
	unsigned long addr = 0;
	int bit_max = NR_BIT * CLK_GATES_NUM;
	int bit_shift, idx;
	int size = 0;
	int val, i;
	void __iomem *v_addr = NULL;
	unsigned int value = 0;

	if (!clk_status || !buf)
		return -EINVAL;

	for (i = 0; clk_gate_masks[i].addr != 0; i++) {
		if (i >= bit_max) {
			pr_err("%s: Error Exceed storage size %d(%d)\n",
				__func__, i, bit_max);
			break;
		}

		if (addr != clk_gate_masks[i].addr) {
			addr = clk_gate_masks[i].addr;
			value = __raw_readl(clk_gate_masks[i].addr);
			size += snprintf(buf + size, CLK_MON_BUF_SIZE,
				"\n[0x%x]\n",
				((unsigned int) clk_gate_masks[i].addr));
		}

		bit_shift = i % NR_BIT;
		idx = i >> IDX_SHIFT;
		/* If the bit is set indicates that the clock is enabled as
		observed in the API clk_mon_clock_gate.
		*/
		val = CHECK_BIT_SET(clk_status[idx], bit_shift);
		size += snprintf(buf + size, CLK_MON_BUF_SIZE,
				" %-20s\t: %s\n", clk_gate_masks[i].name,
				(val !=0) ? "on" : "off");
	}
	return size;
}

static ssize_t clk_mon_show_power_domain(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned int val = 0;
	ssize_t size = 0;
	static struct regulator *regulator_pm;
	unsigned int num_domains = 0;
	int i;

	num_domains = sizeof(power_domain_masks)/sizeof(power_domain_masks[0]);

	memset(buf, 0, sizeof(buf));

	/* Parse through the list of regulators & based on request from the
	consumers of the regulator, it would be enabled/disabled i.e. ON/OFF
	*/
	for (i = 0; i < num_domains; i++) {
		regulator_pm = regulator_get(NULL, power_domain_masks[i].name);
		if (IS_ERR(regulator_pm)) {
			pr_err("Failed to get [%s] regulator\n",
				power_domain_masks[i].name);
		} else {
			val = regulator_is_enabled(regulator_pm);

			regulator_put(regulator_pm);
			regulator_pm = NULL;
		}
		size += snprintf(buf + size, CLK_MON_BUF_SIZE,
			" %-15s\t: %s\n",
			power_domain_masks[i].name, (val) ? "on" : "off");
	}
	return size + 1;
}

static ssize_t clk_mon_show_clock_gating(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned int val  = 0;
	unsigned long addr=0;
	volatile unsigned  int value = 0;
	ssize_t size = 0;
	int i;

	for (i = 0; clk_gate_masks[i].addr != 0; i++) {
		if(addr != clk_gate_masks[i].addr){
			addr = clk_gate_masks[i].addr;
			value = __raw_readl(clk_gate_masks[i].addr);
			size += sprintf(buf + size, "\n[0x%x] 0x%x\n",
			vaddr_to_paddr(addr, CLK_REG), value);
			}
		val = CHECK_BIT_SET( value,
				(unsigned int)clk_gate_masks[i].bit_number);
		size += snprintf(buf + size, CLK_MON_BUF_SIZE,
				" %-20s\t: %s\n",
				clk_gate_masks[i].name, (val) ? "on" : "off");
	}

	return size + 1;
}


static DEVICE_ATTR(check_reg, S_IRUSR | S_IWUSR,
		clk_mon_show_check_reg, clk_mon_store_check_reg);
static DEVICE_ATTR(set_reg, S_IWUSR, NULL, clk_mon_store_set_reg);
static DEVICE_ATTR(power_domain, S_IRUSR, clk_mon_show_power_domain, NULL);
static DEVICE_ATTR(clock_gating, S_IRUSR, clk_mon_show_clock_gating, NULL);


static struct attribute *clk_mon_attributes[] = {
	&dev_attr_check_reg.attr,
	&dev_attr_set_reg.attr,
	&dev_attr_power_domain.attr,
	&dev_attr_clock_gating.attr,
	NULL,
};

static struct attribute_group clk_mon_attr_group = {
	.attrs = clk_mon_attributes,
	.name  = "check",
};

static const struct file_operations clk_mon_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = clk_mon_ioctl,
};

static struct miscdevice clk_mon_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "clk_mon",
	.fops  = &clk_mon_fops,
};

static int __init clk_mon_init(void)
{
	int ret = 0;

	pr_info("%s\n", __func__);

	ret = misc_register(&clk_mon_device);

	if (ret) {
		pr_err("%s: Unable to register clk_mon_device\n", __func__);
		goto err_misc_register;
	}

	ret = sysfs_create_group(&clk_mon_device.this_device->kobj,
			&clk_mon_attr_group);

	if (ret) {
		pr_err("%s: Unable to Create sysfs node\n", __func__);
		goto err_create_group;
	}

/* Base addresses of the registers are located in include/soc/sprd/sci_glb_regs.h */

	struct clk_gate_mask clk_gate_mask_temp[] = {
	/* System Related Clocks, Start */
	/* AHB EB */
	{"ZIPMTX_EB", CLK_MON_AHB_EB, 23},
	{"LVDS_EB", CLK_MON_AHB_EB, 22},
	{"ZIPDEC_EB", CLK_MON_AHB_EB, 21},
	{"ZIPENC_EB", CLK_MON_AHB_EB, 20},
	{"NANDC_ECC_EB", CLK_MON_AHB_EB, 19},
	{"NANDC_2X_EB", CLK_MON_AHB_EB, 18},
	{"NANDC_EB", CLK_MON_AHB_EB, 17},
	{"BUSMON2_EB", CLK_MON_AHB_EB, 16},
	{"BUSMON1_EB", CLK_MON_AHB_EB, 15},
	{"BUSMON0_EB", CLK_MON_AHB_EB, 14},
	{"SPINLOCK_EB", CLK_MON_AHB_EB, 13},
	{"GPS_EB", CLK_MON_AHB_EB, 12},
	{"EMMC_EB", CLK_MON_AHB_EB, 11},
	{"SDIO2_EB", CLK_MON_AHB_EB, 10},
	{"SDIO1_EB", CLK_MON_AHB_EB, 9},
	{"SDIO0_EB", CLK_MON_AHB_EB, 8},
	{"DRM_EB", CLK_MON_AHB_EB, 7},
	{"NFC_EB", CLK_MON_AHB_EB, 6},
	{"DMA_EB", CLK_MON_AHB_EB, 5},
	{"USB_EB", CLK_MON_AHB_EB, 4},
	{"GSP_EB", CLK_MON_AHB_EB, 3},
	{"DISPC1_EB", CLK_MON_AHB_EB, 2},
	{"DISPC2_EB", CLK_MON_AHB_EB, 1},
	{"DSI_EB", CLK_MON_AHB_EB,0},

	/* AP_AHB_AP_SYS_AUTO_SLEEP_CFG*/
	{"GSP_CKG_FORCE_EN", CLK_MON_AP_SYS_AUTO_SLEEP_CFG, 9},
	{"GSP_AUTO_GATE_EN", CLK_MON_AP_SYS_AUTO_SLEEP_CFG, 8},
	{"AP_AHB_AUTO_GATE_EN",  CLK_MON_AP_SYS_AUTO_SLEEP_CFG, 5},
	{"CA7_DBG_FORCE_SLEEP",  CLK_MON_AP_SYS_AUTO_SLEEP_CFG, 2},
	{"CA7_DBG_AUTO_GATE_EN",  CLK_MON_AP_SYS_AUTO_SLEEP_CFG, 1},
	{"CA7_CORE_AUTO_GATE_EN",  CLK_MON_AP_SYS_AUTO_SLEEP_CFG, 0},

	/* AP_APB EB */
	{"INTC3_EB",  CLK_MON_APB_EB, 22},
	{"INTC2_EB",  CLK_MON_APB_EB, 21},
	{"INTC1_EB",  CLK_MON_APB_EB, 20},
	{"INTC0_EB",  CLK_MON_APB_EB, 19},
	{"CKG_EB",  CLK_MON_APB_EB, 18},
	{"UART4_EB", CLK_MON_APB_EB, 17},
	{"UART3_EB",  CLK_MON_APB_EB, 16},
	{"UART2_EB",  CLK_MON_APB_EB, 15},
	{"UART1_EB",  CLK_MON_APB_EB, 14},
	{"UART0_EB",  CLK_MON_APB_EB, 13},
	{"I2C4_EB",  CLK_MON_APB_EB, 12},
	{"I2C3_EB",  CLK_MON_APB_EB, 11},
	{"I2C2_EB",  CLK_MON_APB_EB, 10},
	{"I2C1_EB",  CLK_MON_APB_EB, 9},
	{"I2C0_EB",  CLK_MON_APB_EB, 8},
	{"SPI2_EB",  CLK_MON_APB_EB, 7},
	{"SPI1_EB",  CLK_MON_APB_EB, 6},
	{"SPI0_EB",  CLK_MON_APB_EB, 5},
	{"IIS3_EB",  CLK_MON_APB_EB, 4},
	{"IIS2_EB",  CLK_MON_APB_EB, 3},
	{"IIS1_EB",  CLK_MON_APB_EB, 2},
	{"IIS0_EB",  CLK_MON_APB_EB, 1},
	{"SIM0_EB",  CLK_MON_APB_EB, 0},

	/* Always on APB EB0 */
	{"I2C_EB",  CLK_MON_AON_APB_EB0, 31},
	{"CA7_DAP_EB",  CLK_MON_AON_APB_EB0, 30},
	{"CA7_TS1_EB",  CLK_MON_AON_APB_EB0, 29},
	{"CA7_TS0_EB",  CLK_MON_AON_APB_EB0, 28},
	{"GPU_EB",  CLK_MON_AON_APB_EB0, 27},
	{"CKG_EB",  CLK_MON_AON_APB_EB0, 26},
	{"MM_EB",  CLK_MON_AON_APB_EB0, 25},
	{"AP_WDG_EB",  CLK_MON_AON_APB_EB0, 24},
	{"SPLK_EB",  CLK_MON_AON_APB_EB0, 22},
	{"PIN_EB",  CLK_MON_AON_APB_EB0, 20},
	{"VBC_EB",  CLK_MON_AON_APB_EB0, 19},
	{"AUD_EB",  CLK_MON_AON_APB_EB0, 18},
	{"AUDIF_EB",  CLK_MON_AON_APB_EB0, 17},
	{"ADI_EB",  CLK_MON_AON_APB_EB0, 16},
	{"INTC_EB",  CLK_MON_AON_APB_EB0, 15},
	{"EIC_EB",  CLK_MON_AON_APB_EB0, 14},
	{"EFUSE_EB",  CLK_MON_AON_APB_EB0, 13},
	{"AP_TMR0_EB",  CLK_MON_AON_APB_EB0, 12},
	{"AON_TMR_EB",  CLK_MON_AON_APB_EB0, 11},
	{"AP_SYST_EB",  CLK_MON_AON_APB_EB0, 10},
	{"AON_SYST_EB",  CLK_MON_AON_APB_EB0, 9},
	{"KPD_EB",  CLK_MON_AON_APB_EB0, 8},
	{"PWM3_EB",  CLK_MON_AON_APB_EB0, 7},
	{"PWM2_EB",  CLK_MON_AON_APB_EB0, 6},
	{"PWM1_EB",  CLK_MON_AON_APB_EB0, 5},
	{"PWM0_EB",  CLK_MON_AON_APB_EB0, 4},
	{"GPIO_EB",  CLK_MON_AON_APB_EB0, 3},

	/* Always on APB EB1 */
	{"CODEC_EB", CLK_MON_AON_APB_EB1,28},
	{"ORP_JTAG_EB",  CLK_MON_AON_APB_EB1, 27},
	{"CA5_TS0_EB",  CLK_MON_AON_APB_EB1, 26},
	{"LVDS_PLL_DIV_EN",  CLK_MON_AON_APB_EB1, 24},
	{"ARM7_JTAG_EB",  CLK_MON_AON_APB_EB1, 23},
	{"AON_DMA_EB",  CLK_MON_AON_APB_EB1, 22},
	{"MBOX_EB",  CLK_MON_AON_APB_EB1, 21},
	{"DJTAG_EB",  CLK_MON_AON_APB_EB1, 20},
	{"RTC4M1_CAL_EB",  CLK_MON_AON_APB_EB1, 19},
	{"RTC4M0_CAL_EB",  CLK_MON_AON_APB_EB1, 18},
	{"MDAR_EB",  CLK_MON_AON_APB_EB1, 17},
	{"LVDS_TCXO_EB",  CLK_MON_AON_APB_EB1, 16},
	{"LVDS_TRX_EB",  CLK_MON_AON_APB_EB1, 15},
	{"CA5_DAP_EB",  CLK_MON_AON_APB_EB1, 14},
	{"DISP_EMC_EB",  CLK_MON_AON_APB_EB1, 11},
	{"AP_TMR2_EB",  CLK_MON_AON_APB_EB1, 10},
	{"AP_TMR1_EB",  CLK_MON_AON_APB_EB1, 9},
	{"CA7_WDG_EB",  CLK_MON_AON_APB_EB1, 8},
	{"AVS_EB",  CLK_MON_AON_APB_EB1, 6},
	{"PROBE_EB",  CLK_MON_AON_APB_EB1, 5},
	{"AUX2_EB",  CLK_MON_AON_APB_EB1, 4},
	{"AUX1_EB",  CLK_MON_AON_APB_EB1, 3},
	{"AUX0_EB",  CLK_MON_AON_APB_EB1, 2},
	{"THM_EB",  CLK_MON_AON_APB_EB1, 1},
	{"PMU_EB",  CLK_MON_AON_APB_EB1, 0},

	/* PMU_APB_PWR_STATUS0_DBG */
	{"PD_MM_TOP_STATE",  CLK_MON_PWR_STATUS0_DBG, 30},
	{"PD_GPU_TOP_STATE",  CLK_MON_PWR_STATUS0_DBG, 26},
	{"PD_AP_SYS_STATE",  CLK_MON_PWR_STATUS0_DBG, 22},
	{"PD_CA7_C3_STATE",  CLK_MON_PWR_STATUS0_DBG, 18},
	{"PD_CA7_C2_STATE",  CLK_MON_PWR_STATUS0_DBG, 14},
	{"PD_CA7_C1_STATE",  CLK_MON_PWR_STATUS0_DBG, 10},
	{"PD_CA7_C0_STATE",  CLK_MON_PWR_STATUS0_DBG, 6},
	{"PD_CA7_TOP_STATE",  CLK_MON_PWR_STATUS0_DBG, 2},

	/* PMU_APB_PWR_STATUS1_DBG */
	{"PD_CP0_CEVA_1_STATE",  CLK_MON_PWR_STATUS1_DBG, 30},
	{"PD_CP0_CEVA_0_STATE",  CLK_MON_PWR_STATUS1_DBG, 26},
	{"PD_CP0_GSM_0_STATE",  CLK_MON_PWR_STATUS1_DBG, 22},
	{"PD_CP0_GSM_1_STATE",  CLK_MON_PWR_STATUS1_DBG, 18},
	{"PD_CP0_HU3GE_STATE",  CLK_MON_PWR_STATUS1_DBG, 14},
	{"PD_CP0_ARM9_1_STATE",  CLK_MON_PWR_STATUS1_DBG, 10},
	{"PD_CP0_ARM9_0_STATE",  CLK_MON_PWR_STATUS1_DBG, 6},
	{"PD_CP0_TD_STATE",  CLK_MON_PWR_STATUS1_DBG, 2},

	/* PMU_APB_PWR_STATUS2_DBG */
	{"PD_PUB_SYS_STATE",  CLK_MON_PWR_STATUS2_DBG, 26},
	{"PD_CP1_COMWRAP_STATE",  CLK_MON_PWR_STATUS2_DBG, 22},
	{"PD_CP1_LTE_P2_STATE",  CLK_MON_PWR_STATUS2_DBG, 18},
	{"PD_CP1_LTE_P1_STATE",  CLK_MON_PWR_STATUS2_DBG, 14},
	{"PD_CP1_CEVA_STATE",  CLK_MON_PWR_STATUS2_DBG, 10},
	{"PD_CP1_CA5_STATE",  CLK_MON_PWR_STATUS2_DBG, 6},
	{"PD_CODEC_TOP_STATE",  CLK_MON_PWR_STATUS2_DBG, 2},

	/* PMU_APB_PWR_STATUS3_DBG */
	//{"PD_PUB_SYS_STATE",  CLK_MON_PWR_STATUS3_DBG, 6},
	//{"PD_CP2_SYS_STATE",  CLK_MON_PWR_STATUS3_DBG, 2},

	/* PMU_APB_SLEEP_STATUS */
	{"ARM7_SLP_STATUS",  CLK_MON_APB_SLEEP_STATUS, 22},
	{"VCP1_SLP_STATUS",  CLK_MON_APB_SLEEP_STATUS, 18},
	{"VCP0_SLP_STATUS",  CLK_MON_APB_SLEEP_STATUS, 14},
	{"CP1_SLP_STATUS",  CLK_MON_APB_SLEEP_STATUS, 10},
	{"CP0_SLP_STATUS",  CLK_MON_APB_SLEEP_STATUS, 6},
	{"AP_SLP_STATUS",  CLK_MON_APB_SLEEP_STATUS,2},

	/*  End [160+ clocks]*/
	/* Any Missing Clocks to be added here */
	{"",0,0},

	};

	clk_gate_masks = kmalloc(sizeof(clk_gate_mask_temp), GFP_KERNEL);
	if (!clk_gate_masks)
		return -ENOMEM;

	memcpy(clk_gate_masks, clk_gate_mask_temp, sizeof( clk_gate_mask_temp ));

	return 0;

err_create_group:
	misc_deregister(&clk_mon_device);
err_misc_register:
	return ret;
}

static void __exit clk_mon_exit(void)
{
	if (clk_gate_masks)
		kfree(clk_gate_masks);
	misc_deregister(&clk_mon_device);
}

module_init(clk_mon_init);
module_exit(clk_mon_exit);

MODULE_AUTHOR("Himanshu Sheth <himanshu.s@samsung.com>");
MODULE_DESCRIPTION("Clock Gate Monitor");
MODULE_LICENSE("GPL");
