/* drivers/motor/ff_dc_vibrator.c
* Copyright (C) 2016 Samsung Electronics Co. Ltd. All Rights Reserved.
*
* Author: Sanghyeon Lee <sirano06.lee@samsung.com>\
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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/pwm.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/regulator/consumer.h>
#include <linux/ff_dc_vibrator.h>
#include <linux/gpio.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of.h>
#include <linux/delay.h>
#include <mach/gpio.h>

#define MAX_MAGNITUDE		0xff
#define FF_VAL_SHIFT		8

extern struct class *sec_class;
struct device *motor_device;
struct ff_dc_vibrator_data *g_hap_data;

enum FF_DC_VIBRATOR_CONTROL {
	FF_DC_VIBRATOR_DISABLE = 0,
	FF_DC_VIBRATOR_ENABLE = 1,
};

struct ff_dc_vibrator_data {
	struct device *dev;
	struct input_dev *input_dev;
	struct ff_dc_vibrator_platform_data *pdata;
	struct regulator *regulator;
	struct work_struct work;
	int max_mV;
	int min_mV;
	int level;
};

static void vib_en(bool en)
{
	int strength = 0;

	if (!g_hap_data) {
		pr_info("[VIB] the motor is not ready!!!");
		return ;
	}

	if (en) {
		strength = g_hap_data->pdata->min_volt;
		strength += (g_hap_data->level * (g_hap_data->pdata->max_volt -
			    g_hap_data->pdata->min_volt)) / MAX_MAGNITUDE;

		if (strength < g_hap_data->pdata->min_volt)
			g_hap_data->level = g_hap_data->pdata->min_volt;
		else if (strength > g_hap_data->pdata->max_volt)
			g_hap_data->level = g_hap_data->pdata->max_volt;
		else
			g_hap_data->level = strength;

		regulator_set_voltage(g_hap_data->regulator,
				g_hap_data->level, g_hap_data->level);

		if (!regulator_is_enabled(g_hap_data->regulator))
			regulator_enable(g_hap_data->regulator);
	} else {
		if (regulator_is_enabled(g_hap_data->regulator))
			regulator_disable(g_hap_data->regulator);
	}
	pr_info("[VIB] %s %s - %duv\n", __func__, en ? "on" : "off", g_hap_data->level);
}

static int ff_dc_haptic_play(struct input_dev *input, void *data,
				struct ff_effect *effect)
{
	if (!g_hap_data) {
		pr_info("%s platform data error\n", __func__);
		return 0;
	}

	g_hap_data->level = effect->u.rumble.strong_magnitude >> FF_VAL_SHIFT;
	schedule_work(&g_hap_data->work);

	return 0;
}

static void ff_dc_haptic_close(struct input_dev *input)
{
	struct ff_dc_vibrator_data *haptic = input_get_drvdata(input);

	cancel_work_sync(&haptic->work);
	vib_en(FF_DC_VIBRATOR_DISABLE);
}

static void haptic_work(struct work_struct *work)
{
	struct ff_dc_vibrator_data *haptic = container_of(work,
						       struct ff_dc_vibrator_data,
						       work);
	if (haptic->level)
		vib_en(FF_DC_VIBRATOR_ENABLE);
	else
		vib_en(FF_DC_VIBRATOR_DISABLE);
}

static ssize_t motor_control_show_motor_on(struct device *dev, struct device_attribute *attr, char *buf)
{
	vib_en(FF_DC_VIBRATOR_ENABLE);
	return 0;
}

static ssize_t motor_control_show_motor_off(struct device *dev, struct device_attribute *attr, char *buf)
{
	vib_en(FF_DC_VIBRATOR_DISABLE);
	return 0;
}

static DEVICE_ATTR(motor_on, S_IRUGO, motor_control_show_motor_on, NULL);
static DEVICE_ATTR(motor_off, S_IRUGO, motor_control_show_motor_off, NULL);

static struct attribute *motor_control_attributes[] = {
	&dev_attr_motor_on.attr,
	&dev_attr_motor_off.attr,
	NULL
};
static const struct attribute_group motor_control_group = {
	.attrs = motor_control_attributes,
};

static int ff_dc_vibrator_probe(struct platform_device *pdev)
{
	int ret;
	int error = 0;
	struct input_dev *input_dev;
	struct ff_dc_vibrator_data *hap_data;
	struct ff_dc_vibrator_platform_data *ff_dc_pdata;

	pr_info("[VIB] ++ %s\n", __func__);

	if (pdev->dev.of_node) {
		ff_dc_pdata = devm_kzalloc(&pdev->dev, sizeof(*ff_dc_pdata), GFP_KERNEL);

		ret = of_property_read_string(pdev->dev.of_node, "vibrator,regulator_name", &ff_dc_pdata->regulator_name);
		if (ret < 0)
			dev_err(&pdev->dev, "Failed to read regulator_name\n");

		ret = of_property_read_u32(pdev->dev.of_node, "vibrator,max_volt", &ff_dc_pdata->max_volt);

		if (ret < 0)
			dev_err(&pdev->dev, "Failed to read max_volt\n");

		ret = of_property_read_u32(pdev->dev.of_node, "vibrator,min_volt", &ff_dc_pdata->min_volt);

		if (ret < 0)
			dev_err(&pdev->dev, "Failed to read min_volt\n");
	} else {
		ff_dc_pdata = dev_get_platdata(&pdev->dev);
	}

	hap_data = kzalloc(sizeof(struct ff_dc_vibrator_data), GFP_KERNEL);
	if (!hap_data)
		return -ENOMEM;

	input_dev = input_allocate_device();
	if (!input_dev) {
		dev_err(&pdev->dev, "unable to allocate memory\n");
		error =  -ENOMEM;
		goto err_kfree_mem;
	}

	hap_data->pdata = ff_dc_pdata;
	if (hap_data->pdata == NULL) {
		pr_info("%s: no pdata\n", __func__);
		goto err_free_input;
	}

	platform_set_drvdata(pdev, hap_data);
	g_hap_data = hap_data;
	hap_data->dev = &pdev->dev;
	hap_data->input_dev = input_dev;
	INIT_WORK(&hap_data->work, haptic_work);
	hap_data->input_dev->name = "ff_dc_haptic";
	hap_data->input_dev->dev.parent = &pdev->dev;
	hap_data->input_dev->close = ff_dc_haptic_close;

	input_set_drvdata(hap_data->input_dev, hap_data);
	input_set_capability(hap_data->input_dev, EV_FF, FF_RUMBLE);
	error = input_ff_create_memless(input_dev, NULL,
		ff_dc_haptic_play);

	if (error) {
		dev_err(&pdev->dev,
			"input_ff_create_memless() failed: %d\n",
			error);
		goto err_kfree_pdata;
	}

	error = input_register_device(hap_data->input_dev);
        if (error) {
		dev_err(&pdev->dev,
			"couldn't register input device: %d\n",
			error);
		goto err_destroy_ff;
	}

	hap_data->regulator
			= regulator_get(NULL, hap_data->pdata->regulator_name);
	if (IS_ERR(hap_data->regulator)) {
		pr_info("[VIB] Failed to get vmoter regulator.\n");
		error = -EFAULT;
		goto err_unregister_input;
	}

	regulator_set_voltage(hap_data->regulator, hap_data->pdata->min_volt,
			hap_data->pdata->max_volt);
	ret = sysfs_create_group(&motor_device->kobj, &motor_control_group);
	if (ret) {
		pr_info("%s: failed to create motor control attribute group\n", __func__);
		goto err_regulator_put;
	}

	platform_set_drvdata(pdev, hap_data);
	pr_info("[VIB] -- %s\n", __func__);

	return error;

err_regulator_put:
	regulator_put(hap_data->regulator);
err_unregister_input:
	input_unregister_device(hap_data->input_dev);
err_destroy_ff:
	input_ff_destroy(hap_data->input_dev);
err_kfree_pdata:
	kfree(hap_data->pdata);
err_free_input:
	input_free_device(hap_data->input_dev);
err_kfree_mem:
	kfree(hap_data);

	return error;
}

static int __exit ff_dc_vibrator_remove(struct platform_device *pdev)
{
	struct ff_dc_vibrator_data *data = platform_get_drvdata(pdev);

	regulator_put(data->regulator);
	kfree(data->pdata);
	kfree(data);
	g_hap_data = NULL;
	return 0;
}

#if defined(CONFIG_OF)
static struct of_device_id haptic_dt_ids[] = {
	{ .compatible = "ff-dc-vibrator" },
	{ },
};
MODULE_DEVICE_TABLE(of, haptic_dt_ids);
#endif /* CONFIG_OF */

static int ff_dc_vibrator_suspend(struct platform_device *pdev,
			pm_message_t state)
{
	pr_info("[VIB] %s\n", __func__);
	if (g_hap_data != NULL) {
		cancel_work_sync(&g_hap_data->work);
	}

	return 0;
}

static int ff_dc_vibrator_resume(struct platform_device *pdev)
{
	pr_info("[VIB] %s\n", __func__);

	return 0;
}

static struct platform_driver ff_dc_vibrator_driver = {
	.probe		= ff_dc_vibrator_probe,
	.remove		= ff_dc_vibrator_remove,
	.suspend	= ff_dc_vibrator_suspend,
	.resume		= ff_dc_vibrator_resume,
	.driver = {
		.name	= "ff-dc-vibrator",
		.owner	= THIS_MODULE,
#if defined(CONFIG_OF)
		.of_match_table = haptic_dt_ids,
#endif /* CONFIG_OF */
	},
};

static int __init ff_dc_vibrator_init(void)
{
	motor_device = device_create(sec_class, NULL, 0, NULL, "motor");
	if (IS_ERR(motor_device)) {
		pr_err("%s Failed to create device(motor)!\n", __func__);
		return -ENODEV;
	}

	pr_info("[VIB] %s\n", __func__);

	return platform_driver_register(&ff_dc_vibrator_driver);
}
module_init(ff_dc_vibrator_init);

static void __exit ff_dc_vibrator_exit(void)
{
	platform_driver_unregister(&ff_dc_vibrator_driver);
}
module_exit(ff_dc_vibrator_exit);

MODULE_AUTHOR("Samsung Electronics");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Forced feedback dc vibrator driver");
