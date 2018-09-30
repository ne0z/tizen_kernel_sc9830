#include <linux/module.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>//
#include <linux/param.h> //
#include <linux/bitops.h>//
#include <linux/gpio.h>
#include <linux/hrtimer.h>
#include <linux/seq_file.h>
#include <net/bluetooth/bluetooth.h>
#include <linux/wakelock.h>

#include <linux/export.h>


#define BT_SLEEP_DBG BT_ERR

#define PROC_DIR        "bluetooth/sleep"

extern int set_marlin_wakeup(unsigned int chn,unsigned int user_id);
extern int set_marlin_sleep(unsigned int chn,unsigned int user_id);

struct proc_dir_entry *bluetooth_dir, *sleep_dir;

struct sprd_bt_lpm {
	struct hrtimer enter_lpm_timer;
	ktime_t enter_lpm_delay;

	struct uart_port *uport;

	struct wake_lock BT_wakelock;
	int bt_wake_state;
} bt_lpm;

void bt_wakeup(unsigned int chn,unsigned int user_id)
{
	set_marlin_wakeup(chn,user_id);
}
void bt_sleep(unsigned int chn,unsigned int user_id)
{
	return;
}

static enum hrtimer_restart enter_lpm(struct hrtimer *timer)
{
	wake_lock_timeout(&bt_lpm.BT_wakelock, HZ/2);

	return HRTIMER_NORESTART;
}

void sprd_bt_lpm_exit_lpm_locked(struct uart_port *uport)
{
	bt_lpm.uport = uport;

	hrtimer_try_to_cancel(&bt_lpm.enter_lpm_timer);

	wake_lock(&bt_lpm.BT_wakelock);
	bt_wakeup(0xff,0x2);//set_marlin_wakeup(0xff,0x2)

	hrtimer_start(&bt_lpm.enter_lpm_timer, bt_lpm.enter_lpm_delay,
		HRTIMER_MODE_REL);
}
EXPORT_SYMBOL(sprd_bt_lpm_exit_lpm_locked);

static ssize_t bluesleep_write_proc_btwrite(struct file *file, const char __user *buffer,size_t count, loff_t *pos)
{
	char b;
	//BT_ERR("bluesleep_write_proc_btwrite");

	if (count < 1)
		return -EINVAL;

	if (copy_from_user(&b, buffer, 1))
		return -EFAULT;
	BT_ERR("bluesleep_write_proc_btwrite=%d",b);

	if(b == '1')
	{
		wake_lock(&bt_lpm.BT_wakelock);
		bt_wakeup(0xff,0x2);//set_marlin_wakeup(0xff,0x2)
	}
	else if(b=='2')
		wake_unlock(&bt_lpm.BT_wakelock);
	else
		BT_ERR("bludroid pass a unsupport parameter");
		//bt_sleep(0xff,0x2);//set_marlin_sleep(0xff ,0x2)
	return count;
}
static int btwrite_proc_show(struct seq_file * m,void * v)
{
	//unsigned int btwrite;
	BT_ERR("bluesleep_read_proc_lpm\n");
	seq_printf(m, "unsupported to read\n");
	return 0;
}

static int bluesleep_open_proc_btwrite(struct inode *inode, struct file *file)
{
	return single_open(file, btwrite_proc_show, PDE_DATA(inode));

}


static const struct file_operations lpm_proc_btwrite_fops = {
	.owner = THIS_MODULE,
	.open = bluesleep_open_proc_btwrite,
	.read = seq_read,
	.write = bluesleep_write_proc_btwrite,
	.release = single_release,
};


static int __init bluesleep_init(void)
{
        int retval;
        struct proc_dir_entry *ent;
        bluetooth_dir = proc_mkdir("bluetooth", NULL);
        if (bluetooth_dir == NULL) {
                BT_SLEEP_DBG("Unable to create /proc/bluetooth directory");
                return -ENOMEM;
        }
        sleep_dir = proc_mkdir("sleep", bluetooth_dir);
        if (sleep_dir == NULL) {
                BT_SLEEP_DBG("Unable to create /proc/%s directory", PROC_DIR);
                return -ENOMEM;
        }

        /* Creating read/write  entry */
	ent=proc_create("btwrite", S_IRUGO | S_IWUSR | S_IWGRP, sleep_dir,&lpm_proc_btwrite_fops); /*read/write */
	if (ent == NULL) {
        BT_SLEEP_DBG("Unable to create /proc/%s/btwake entry", PROC_DIR);
	 retval = -ENOMEM;
         goto fail;
	}
        wake_lock_init(&bt_lpm.BT_wakelock, WAKE_LOCK_SUSPEND, "bluetooth_wakelock");

	hrtimer_init(&bt_lpm.enter_lpm_timer, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL);
	bt_lpm.enter_lpm_delay = ktime_set(10, 0);  /* 1 sec */ /*1->3*//*3->4*/
	bt_lpm.enter_lpm_timer.function = enter_lpm;
	bt_lpm.uport = NULL;

	return 0;
fail:
	remove_proc_entry("btwrite", sleep_dir);
	remove_proc_entry("sleep", bluetooth_dir);
	remove_proc_entry("bluetooth", 0);
	wake_lock_destroy(&bt_lpm.BT_wakelock);
	return retval;
}

static void __exit bluesleep_exit(void)
{
        remove_proc_entry("btwrite", sleep_dir);
        remove_proc_entry("sleep", bluetooth_dir);
        remove_proc_entry("bluetooth", 0);
	wake_lock_destroy(&bt_lpm.BT_wakelock);

}

module_init(bluesleep_init);
module_exit(bluesleep_exit);

MODULE_DESCRIPTION("Bluetooth Sleep Mode Driver ver %s " VERSION);
//#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
//#endif

