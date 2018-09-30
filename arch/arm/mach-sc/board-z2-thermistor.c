/* board-z2-thermistor.c
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/gfp.h>
#include <linux/of.h>
#include <linux/err.h>
#include <linux/sec_thermistor.h>
#include <soc/sprd/adc.h>

static struct sec_therm_adc_table temp_table_ap[] = {
	/* adc, temperature */
	{619,	700},
	{727,	650},
	{819,	600},
	{900,	570},
	{963,	550},
	{1010,	530},
	{1061,	520},
	{1116,	500},
	{1185,	480},
	{1305,	450},
	{1471,	400},
	{1696,	350},
	{1931,	300},
	{2136,	250},
	{2400,	200},
	{2614,	150},
	{2836,	100},
	{3055,	50},
	{3181,	20},
	{3270,	0},
	{3382,	-20},
	{3439,	-30},
	{3489,	-50},
	{3539,	-70},
	{3609,	-100},
	{3736,	-150},
	{3825,	-200},
};

static struct sec_therm_adc_table temp_table_battery[] = {
	/* adc, temperature */
	{619,	700},
	{727,	650},
	{819,	600},
	{900,	570},
	{963,	550},
	{1010,	530},
	{1061,	520},
	{1116,	500},
	{1185,	480},
	{1305,	450},
	{1471,	400},
	{1696,	350},
	{1931,	300},
	{2136,	250},
	{2400,	200},
	{2614,	150},
	{2836,	100},
	{3055,	50},
	{3181,	20},
	{3270,	0},
	{3382,	-20},
	{3439,	-30},
	{3489,	-50},
	{3539,	-70},
	{3609,	-100},
	{3736,	-150},
	{3825,	-200},
};

static struct sec_therm_adc_table temp_table_xo[] = {
	/* adc, temperature */
	{678,   700},
	{796,   650},
	{923,   600},
	{966,   580},
	{1054,  550},
	{1208,	500},
	{1345,  460},
	{1386,  450},
	{1568,  400},
	{1759,  350},
	{1952,  300},
	{2152,  250},
	{2364,  200},
	{2569,  150},
	{2832,  100},
	{2967,  50},
	{3005,  20},
	{3093,  0},
	{3156,  -20},
	{3238,  -50},
	{3291,  -70},
	{3458,  -150},
	{3539,  -200},
	{3615,  -250},
	{3661,  -300},
	{3703,  -350},
};

static struct sec_therm_adc_table temp_table_default[] = {
	/* adc, temperature */
	{501,	700},
	{615,	650},
	{738,	600},
	{795,	580},
	{846,	550},
	{956,	500},
	{1065,	460},
	{1088,	450},
	{1180,	400},
	{1307,	350},
	{1392,	300},
	{1477,	250},
	{1627,	200},
	{1777,	150},
	{1922,	100},
	{2098,	50},
	{2144,	20},
	{2182,	0},
	{2212,	-20},
	{2260,	-50},
	{2302,	-70},
	{2452,	-150},
	{2555,	-200},
};

static int sec_therm_temp_table_init(struct sec_therm_adc_info *adc_info)
{
	if (unlikely(!adc_info))
		return -EINVAL;

	switch (adc_info->therm_id) {
		case SEC_THERM_AP:
			adc_info->temp_table = temp_table_ap;
			adc_info->temp_table_size = ARRAY_SIZE(temp_table_ap);
			break;
		case SEC_THERM_BATTERY:
			adc_info->temp_table = temp_table_battery;
			adc_info->temp_table_size = ARRAY_SIZE(temp_table_battery);
			break;
		case SEC_THERM_XO:
			adc_info->temp_table = temp_table_xo;
			adc_info->temp_table_size = ARRAY_SIZE(temp_table_xo);
			break;
		case SEC_THERM_PAM0:
		case SEC_THERM_PAM1:
			case SEC_THERM_FLASH:
			adc_info->temp_table = temp_table_default;
			adc_info->temp_table_size = ARRAY_SIZE(temp_table_default);
			break;
		default:
			return -EINVAL;
	}

	return 0;
}

static int sec_therm_parse_dt(struct device_node *node,
			struct sec_therm_adc_info *adc_list)
{
	struct device_node *child = NULL;
	int i = 0, ret;

	for_each_child_of_node(node, child) {
		int therm_id, therm_adc_ch;
		const char *therm_name, *therm_adc_name;

		therm_name = child->name;
		if (!therm_name) {
			pr_err("%s: Failed to get thermistor name\n", __func__);
			return -EINVAL;
		}

		ret = of_property_read_u32(child, "sec,therm-id", &therm_id);
		if (ret) {
			pr_err("%s: Failed to get thermistor id\n", __func__);
			return ret;
		}

		therm_adc_name = of_get_property(child, "sec,therm-adc-name", NULL);
		if (!therm_adc_name) {
			pr_err("%s: Failed to get adc name\n", __func__);
			return -EINVAL;
		}

		ret = of_property_read_u32(child, "sec,therm-adc-ch", &therm_adc_ch);
		if (ret) {
			pr_err("%s: Failed to get thermistor adc channel\n", __func__);
			return ret;
		}

		pr_info("%s: name:%s, therm_id:%d, adc_name:%s, adc_ch:0x%x\n",
				__func__, therm_name, therm_id, therm_adc_name, therm_adc_ch);

		adc_list[i].name = therm_name;
		adc_list[i].therm_id = therm_id;
		adc_list[i].adc_name = therm_adc_name;
		adc_list[i].adc_ch = therm_adc_ch;
		i++;
	}

	return 0;
}

int sec_therm_adc_read(struct sec_therm_info *info, int therm_id, int *val)
{
	struct sec_therm_adc_info *adc_info = NULL;
	int adc_data;
	int i, ret = 0;

	if (unlikely(!info || !val))
		return -EINVAL;

	for (i = 0; i < info->adc_list_size; i++) {
		if (therm_id == info->adc_list[i].therm_id) {
			adc_info = &info->adc_list[i];
			break;
		}
	}

	if (!adc_info) {
		pr_err("%s: Failed to found therm_id %d\n", __func__, therm_id);
		return -EINVAL;
	}

	adc_data = sci_adc_get_value(adc_info->adc_ch, false);
	if (ret < 0) {
		pr_err("%s: Failed to read adc channel: %d (%d)\n",
					__func__, adc_info->adc_ch, ret);
		return -EINVAL;
	}

	*val = adc_data;
	return 0;
}

int sec_therm_adc_init(struct platform_device *pdev)
{
	struct sec_therm_info *info = platform_get_drvdata(pdev);
	struct sec_therm_adc_info *adc_list = NULL;
	int adc_list_size = 0;
	int i, ret = 0;

	/* device tree support */
	if (pdev->dev.of_node) {
		struct device_node *node = pdev->dev.of_node;
		struct device_node *child;

		for_each_child_of_node(node, child)
			adc_list_size++;

		if (adc_list_size <= 0) {
			pr_err("%s: No adc channel info\n", __func__);
			return -ENODEV;
		}

		adc_list = devm_kzalloc(&pdev->dev,
				sizeof(struct sec_therm_adc_info) * adc_list_size, GFP_KERNEL);
		if (!adc_list) {
			pr_err("%s: Failed to allocate memory\n", __func__);
			return -ENOMEM;
		}

		ret = sec_therm_parse_dt(node, adc_list);
		if (ret) {
			pr_err("%s: Failed to parse dt (%d)\n", __func__, ret);
			goto err;
		}
	} else {
		pr_err("%s: Failed to find device tree info\n", __func__);
		return -ENODEV;
	}

	for (i = 0; i < adc_list_size; i++) {
		ret = sec_therm_temp_table_init(&adc_list[i]);
		if (ret) {
			pr_err("%s: Failed to init %d adc_temp_table\n",
					__func__, adc_list[i].therm_id);
			goto err;
		}
	}

	info->adc_list = adc_list;
	info->adc_list_size = adc_list_size;

	return 0;

err:
	devm_kfree(&pdev->dev, adc_list);
	return ret;
}

void sec_therm_adc_exit(struct platform_device *pdev)
{
	struct sec_therm_info *info = platform_get_drvdata(pdev);

	if (!info)
		return;

	if (pdev->dev.of_node && info->adc_list)
		devm_kfree(&pdev->dev, info->adc_list);
}
