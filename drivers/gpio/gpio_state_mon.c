/*
 * driver/misc/gpio_mon/gpio_state_mon.c
 *
 * A driver program to monitor the state of gpio during initialisation and first achieved sleep.
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
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/gpio_state_mon.h>
#include <linux/secgpio_dvs.h>

static struct gpio_mon_gpio_state_map *gpio_mon_gpio_init_state_map;
static struct gpio_mon_gpio_state_map *gpio_mon_gpio_sleep_state_map;
static unsigned int is_first_sleep_achieved = 0;

#define GPIO_MON_GPIO_STATE_MAP_SIZE	\
	(sizeof(struct gpio_mon_gpio_state_map) * (gpio_mon_gpio_count + 3) )


void gpio_mon_save_gpio_state(unsigned char phonestate, unsigned int index, unsigned int gpio_no,  \
				unsigned int PIN_NAME_sel, unsigned int direction, unsigned int resistor,\
				unsigned int state){

	if(phonestate==PHONE_INIT){
		gpio_mon_gpio_init_state_map[index].pin_name_sel = PIN_NAME_sel ;
		gpio_mon_gpio_init_state_map[index].direction = direction ;
		gpio_mon_gpio_init_state_map[index].resistor = resistor;
		gpio_mon_gpio_init_state_map[index].state = state;
		gpio_mon_gpio_init_state_map[index].gpio_no = gpio_no;
	}
	else{
		is_first_sleep_achieved=1;
		gpio_mon_gpio_sleep_state_map[index].pin_name_sel = PIN_NAME_sel ;
		gpio_mon_gpio_sleep_state_map[index].direction = direction ;
		gpio_mon_gpio_sleep_state_map[index].resistor = resistor;
		gpio_mon_gpio_sleep_state_map[index].state = state;
		gpio_mon_gpio_sleep_state_map[index].gpio_no = gpio_no;
	}
}

static ssize_t gpio_mon_show_gpio_state_sub(char * buf, ssize_t  size){

char direction_i[ GPIO_MON_MAXLENGTH ], resistor_i[ GPIO_MON_MAXLENGTH ],
	state_i[ GPIO_MON_MAXLENGTH ], direction_s[ GPIO_MON_MAXLENGTH ],
	resistor_s[ GPIO_MON_MAXLENGTH ], state_s[ GPIO_MON_MAXLENGTH ] ;
unsigned int i=0;

	for(i = 0 ; i < gpio_mon_gpio_count ; i ++)
	{
		switch ( gpio_mon_gpio_init_state_map[i].resistor ) {

			case GDVS_PUPD_NP :
				strcpy(resistor_i, "NP");
				break;
			case GDVS_PUPD_PD :
				strcpy(resistor_i, "PD");
				break;
			case GDVS_PUPD_PU :
				strcpy(resistor_i, "PU");
				break;
			default :
				strcpy(resistor_i, "ERR");
		}
		switch ( gpio_mon_gpio_init_state_map[i].direction ) {

			case GDVS_IO_FUNC :
				strcpy(direction_i, "FUNC");
				break;
			case GDVS_IO_IN :
				strcpy(direction_i, "IN");
				break;
			case GDVS_IO_OUT :
				strcpy(direction_i, "OUT");
				break;
			default:
				strcpy(direction_i, "ERR");
		}

		switch ( gpio_mon_gpio_init_state_map[i].state ) {

			case GDVS_HL_L :
				strcpy(state_i, "L");
				break;
			case GDVS_HL_H :
				strcpy(state_i, "H");
				break;
			case GDVS_HL_UNKNOWN :
				strcpy(state_i, "X");
				break;
			default :
				strcpy(state_i, "ERR");
			}
		/*Update GPIO sleep state only if sleep has been achieved once*/
		if(is_first_sleep_achieved) {
		switch ( gpio_mon_gpio_sleep_state_map[i].resistor ) {

			case GDVS_PUPD_NP :
				strcpy(resistor_s, "NP");
				break;
			case GDVS_PUPD_PD :
				strcpy(resistor_s, "PD");
				break;
			case GDVS_PUPD_PU :
				strcpy(resistor_s, "PU");
				break;
			default :
				strcpy(resistor_s, "ERR");
		}
		switch ( gpio_mon_gpio_sleep_state_map[i].direction ) {

			case GDVS_IO_FUNC :
				strcpy(direction_s, "FUNC");
				break;
			case GDVS_IO_IN :
				strcpy(direction_s, "IN");
				break;
			case GDVS_IO_OUT :
				strcpy(direction_s, "OUT");
				break;
			default:
				strcpy(direction_s, "ERR");
		}

		switch ( gpio_mon_gpio_sleep_state_map[i].state ) {

			case GDVS_HL_L :
				strcpy(state_s, "L");
				break;
			case GDVS_HL_H :
				strcpy(state_s, "H");
				break;
			case GDVS_HL_UNKNOWN :
				strcpy(state_s, "X");
				break;
			default :
				strcpy(state_s, "ERR");
			}
		}
		else	 {
			strcpy(resistor_s, "N.A.");
			strcpy(direction_s, "N.A.");
			strcpy(state_s, "N.A.");
		}


		size += snprintf(buf+size,GPIO_MON_BUF_SIZE - size, \
			"  %5d               %-5s              %-5s             %-5s                %-5s                \
			%-5s           %-5s\n",\
			gpio_mon_gpio_init_state_map[i].gpio_no, direction_i, resistor_i, state_i, direction_s, resistor_s, state_s);
		}

return size;
}

static ssize_t gpio_mon_show_gpio_state(struct file *file,
	char __user *buffer, size_t count, loff_t *ppos)	{

	static char *buf = NULL;
	int buf_size = (PAGE_SIZE * 7);
	unsigned int ret = 0, size_for_copy = count;
	static unsigned int rest_size = 0;

	if (*ppos < 0 || !count)
		return -EINVAL;

	if (*ppos == 0) {
		buf = kmalloc(buf_size, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		ret+= snprintf(buf + ret, buf_size - ret, \
			"%s","================================" \
			"===========================================" \
			"=========================================\n");

		ret += snprintf(buf + ret, buf_size - ret,
			"%s%s%s",
			"                ","-------------------INIT STATE---------------------","\
			------------------SLEEP STATE------------------\n");
		ret += snprintf(buf + ret , buf_size - ret,
			"%s %s %s %s %s %s %s \n" \
			,"GPIO No.  ","	DIRECTION      "," RESISTOR TYPE	","     STATE     ","\
			DIRECTION    ","   RESISTOR TYPE   ","   STATE\n");

		ret = gpio_mon_show_gpio_state_sub(buf, ret);

		if (ret <= count) {
			size_for_copy = ret;
			rest_size = 0;
		} else {
			size_for_copy = count;
			rest_size = ret -size_for_copy;
		}
		}else {
		if (rest_size <= count) {
			size_for_copy = rest_size;
			rest_size = 0;
		} else {
			size_for_copy = count;
			rest_size -= size_for_copy;
		}
	}

	if (size_for_copy >  0) {
		int offset = (int) *ppos;
		if (copy_to_user(buffer, buf + offset , size_for_copy)) {
			kfree(buf);
			return -EFAULT;
		}
		*ppos += size_for_copy;
	} else
		kfree(buf);

	return size_for_copy;
}


static int gpio_mon_data_init( void ) {

gpio_mon_gpio_init_state_map =	(struct gpio_mon_gpio_state_map *)\
	__get_free_pages(GFP_KERNEL, get_order(GPIO_MON_GPIO_STATE_MAP_SIZE));
	if (gpio_mon_gpio_init_state_map == NULL)
		return -ENOMEM;

gpio_mon_gpio_sleep_state_map =	(struct gpio_mon_gpio_state_map *)\
	__get_free_pages(GFP_KERNEL, get_order(GPIO_MON_GPIO_STATE_MAP_SIZE));
	if (gpio_mon_gpio_sleep_state_map == NULL)
		return -ENOMEM;

memset( gpio_mon_gpio_init_state_map, 0, GPIO_MON_GPIO_STATE_MAP_SIZE );
memset( gpio_mon_gpio_sleep_state_map, 0, GPIO_MON_GPIO_STATE_MAP_SIZE );

return 0;

}

static const struct  file_operations gpio_mon_fops = {
	.owner = THIS_MODULE,
	.read = gpio_mon_show_gpio_state,
};

static int __init gpio_mon_init(void) {
	int ret = 0;
	struct dentry *d;

	d = debugfs_create_dir("gpio_mon", NULL);
	if (d) {
		if (!debugfs_create_file("show_gpio_state", 0644
		, d, NULL,&gpio_mon_fops))   \
		pr_err("%s : debugfs_create_file, error\n", "gpio_mon");
		}

	if(gpio_mon_data_init())
		pr_info("[%s] gpio_mon_data_init  ERROR", __func__);

	return ret;
}

static void  __exit gpio_mon_exit(void)
{
	if (gpio_mon_gpio_init_state_map != NULL)
		vfree(gpio_mon_gpio_init_state_map);

	if (gpio_mon_gpio_sleep_state_map != NULL)
		vfree(gpio_mon_gpio_sleep_state_map);

}

module_init(gpio_mon_init);
module_exit(gpio_mon_exit);

MODULE_AUTHOR("Diwas Kumar <diwas.kumar@samsung.com>");
MODULE_DESCRIPTION("Gpio State Monitor");
MODULE_LICENSE("GPL");


