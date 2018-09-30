#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <asm/io.h>
#include <linux/file.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/leds.h>
#include <linux/mfd/sm5701_core.h>

 /*This flag is used by camera
*driver to check the state of flash led extern definition in
*Dcam_v4l2.c (drivers\media\sprd_dcam\common */
/*Currently all sensors are not enabled so commenting this code. When all sensors will be enabled
need to uncomment the below code*/
extern uint32_t flash_torch_status;
//uint32_t flash_torch_status;

#define to_sprd_led(led_cdev) \
	container_of(led_cdev, struct torch_sec, cdev)


#define TORCH_MAX_BRIGHTNESS 31
#if defined(CONFIG_MACH_Z2_LTE)
#define TORCH_DEFAULT_BRIGHTNESS 0x7 /* default brightness */
#define TORCH_BRIGHTNES_LVL_1 6
#define TORCH_BRIGHTNES_LVL_2 12
#define TORCH_BRIGHTNES_LVL_3 18
#define TORCH_BRIGHTNES_LVL_4 24
#define TORCH_BRIGHTNES_LVL_5 31
#endif

/*Torch Sec */
struct torch_sec {
	struct platform_device *dev;
	struct work_struct work;
	enum led_brightness value;
	struct led_classdev cdev;
	int enabled;
};

#if defined(CONFIG_MACH_Z2_LTE)
int  torch_sec_map_brightness(int brightness)
{
	if (brightness <= TORCH_BRIGHTNES_LVL_1)
		return 0x2; //30mA current
	else if (brightness <=TORCH_BRIGHTNES_LVL_2)
		return 0x4; //50mA current
	else if (brightness <=TORCH_BRIGHTNES_LVL_3)
		return 0x7; //80mA current
	else if (brightness <=TORCH_BRIGHTNES_LVL_4)
		return 0xB; //120mA current
	else
		return 0xF; //160mA current
}
#endif
static void torch_sec_set_brightness(unsigned long  brightness)
{
	unsigned long brightness_level;
	brightness_level = brightness;

	if (brightness == 0) {
			pr_debug("flashlight: set torch brightness to %ld\n",\
					brightness);
	 /*This flag indicates that the flash led
	*is on/off so it should be handled in other
	*drivers accordingly*/
			flash_torch_status = 0;
			sm5701_led_ready(LED_DISABLE);
			sm5701_set_fleden(SM5701_FLEDEN_DISABLED);
			SM5701_operation_mode_function_control();
#if defined(CONFIG_MACH_Z2_LTE)
			/* Before turning off the torch, set default value so that
			next time when torch will turn on, it will turn on at default
			value */
			sm5701_set_imled(TORCH_DEFAULT_BRIGHTNESS);
#endif
		}
	else if (brightness > 0) {
#if defined(CONFIG_MACH_Z2_LTE)
			brightness = torch_sec_map_brightness(brightness);
#endif
			pr_debug("flashlight: set torch brightness to %ld\n",\
					brightness);
			flash_torch_status = 1;
			sm5701_led_ready(MOVIE_MODE);
#if defined(CONFIG_MACH_Z2_LTE)
			sm5701_set_imled(brightness);
#endif
			SM5701_operation_mode_function_control();
			sm5701_set_fleden(SM5701_FLEDEN_ON_MOVIE);
		}
	else {
			pr_debug("Invalid Argument: Brightness exceed the max value");
		}

}

static void torch_sec_enable(struct torch_sec *led)
{
	printk(KERN_INFO "torch_sec_enable\n");
	torch_sec_set_brightness(led->value);
	led->enabled = 1;
}

static void torch_sec_disable(struct torch_sec *led)
{
	torch_sec_set_brightness(led->value);
	printk(KERN_INFO "torch_sec_disable\n");
	led->enabled = 0;
}

static void torch_sec_work(struct work_struct *work)
{
	struct torch_sec *led = container_of(work, struct torch_sec, work);

	if (led->value == LED_OFF)
		torch_sec_disable(led);
	else
		torch_sec_enable(led);
}

static void torch_sec_set(struct led_classdev *led_cdev,
			   enum led_brightness value)
{
	struct torch_sec *led = to_sprd_led(led_cdev);
	led->value = value;
	schedule_work(&led->work);
}

static void torch_sec_shutdown(struct platform_device *dev)
{
	struct torch_sec *led = platform_get_drvdata(dev);
	torch_sec_disable(led);
}

static int torch_sec_probe(struct platform_device *dev)
{
	struct torch_sec *led;
	int ret;

	led = kzalloc(sizeof(struct torch_sec), GFP_KERNEL);
	if (led == NULL) {
		dev_err(&dev->dev, "No memory for device\n");
		return -ENOMEM;
	}

	led->cdev.brightness_set = torch_sec_set;
	led->cdev.default_trigger = "none";
	led->cdev.name = "torch-sec1";
	led->cdev.max_brightness = TORCH_MAX_BRIGHTNESS;
	led->cdev.brightness_get = NULL;
	led->enabled = 0;

	INIT_WORK(&led->work, torch_sec_work);
	led->value = LED_OFF;
	platform_set_drvdata(dev, led);

	/* register our new led device */

	ret = led_classdev_register(&dev->dev, &led->cdev);
	if (ret < 0) {
		dev_err(&dev->dev, "led_classdev_register failed\n");
		kfree(led);
		return ret;
	}

	torch_sec_disable(led);/*disabled by default*/
	printk("******* %s ******* , PROBE DONE\n", __func__);
	return 0;
}

static int torch_sec_remove(struct platform_device *dev)
{
	struct torch_sec *led = platform_get_drvdata(dev);

	led_classdev_unregister(&led->cdev);
	flush_scheduled_work();
	led->value = LED_OFF;
	led->enabled = 1;
	torch_sec_disable(led);
	kfree(led);
	printk("******* %s ******* , Remove DONE\n", __func__);
	return 0;
}

static struct of_device_id torch_sec_match_table[] = {
	{ .compatible = "sm,torch-sec1",},
	{},
};

static const struct platform_device_id torch_sec_id[] = {
	{"torch-sec1", 0},
	{}
};

static struct platform_driver torch_sec_driver = {
	.driver = {
		.name  = "torch-sec1",
		.owner = THIS_MODULE,
		.of_match_table = torch_sec_match_table,
	},
	.probe    = torch_sec_probe,
	.remove   = torch_sec_remove,
	.shutdown = torch_sec_shutdown,
	.id_table = torch_sec_id,
};

static int __init torch_sec_init(void)
{
	return platform_driver_register(&torch_sec_driver);
}

static void __exit torch_sec_exit(void)
{
	platform_driver_unregister(&torch_sec_driver);
}

module_init(torch_sec_init);
module_exit(torch_sec_exit);

MODULE_AUTHOR("Diwas Kumar <diwas.kumar@samsung.com>");
MODULE_DESCRIPTION("Torch Sec Driver");
MODULE_LICENSE("GPL");

