/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.


 *  Copyright (C) 2009-2014 Broadcom Corporation
 */

/************************************************************************************
 *
 *  Filename:      fmdrv_v4l2.c
 *
 *  Description:   FM Driver for Connectivity chip of Broadcom Corporation.
*  This file provides interfaces to V4L2 subsystem.
*
*  This module registers with V4L2 subsystem as Radio
*  data system interface (/dev/radio). During the registration,
*  it will expose three set of function pointers to V4L2 subsystem.
*
*    1) File operation related API (open, close, read, write, poll...etc).
*    2) Set of V4L2 IOCTL complaint API.
*
************************************************************************************/
#include <linux/export.h>

#include "fmdrv.h"
#include "fmdrv_v4l2.h"
#include "fmdrv_main.h"
#include "fmdrv_rx.h"
#include <linux/fm_public.h>
#define FMDRV_V4L2_QUERYCTRL
#include "fmdrv_config.h"

/************************************************************************************
**  Constants & Macros
************************************************************************************/

#ifndef DEBUG
#ifdef pr_info
#undef pr_info
#define pr_info(fmt, arg...)
#endif
#endif

/************************************************************************************
**  Static variables
************************************************************************************/

static struct video_device *gradio_dev;
static unsigned char radio_disconnected;

static atomic_t v4l2_device_available = ATOMIC_INIT(1);

/************************************************************************************
**  Forward function declarations
************************************************************************************/

static int fm_v4l2_vidioc_s_hw_freq_seek(struct file *, void *,
                    const struct v4l2_hw_freq_seek *);

/************************************************************************************
**  Functions
************************************************************************************/
/*****************************************************************************
**   V4L2 RADIO (/dev/radioX) device file operation interfaces
*****************************************************************************/

/* Read RX RDS data */
static ssize_t fm_v4l2_fops_read(struct file *file, char __user * buf,
                    size_t count, loff_t *ppos)
{
    int ret, bytes_read;
    struct fmdrv_ops *fmdev;

    fmdev = video_drvdata(file);

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));

    if (!radio_disconnected) {
        pr_err("(fmdrv): FM device is already disconnected\n");
        ret = -EIO;
        return ret;
    }

        if (mutex_lock_interruptible(&fmdev->mutex))
                return -ERESTARTSYS;

	/* Copy RDS data from the cicular buffer to userspace */
	bytes_read =
	    fmc_transfer_rds_from_cbuff(fmdev, file, buf, count);
    mutex_unlock(&fmdev->mutex);
    return bytes_read;
}

/* Write RDS data. Since FM TX is not supported, return EINVAL
 */
static ssize_t fm_v4l2_fops_write(struct file *file, const char __user * buf,
                    size_t count, loff_t *ppos)
{
    return -EINVAL;
}

/* Handle Poll event for "/dev/radioX" device.*/
static unsigned int fm_v4l2_fops_poll(struct file *file,
                      struct poll_table_struct *pts)
{
    int ret;
    struct fmdrv_ops *fmdev;
#if V4L2_RDS_DEBUG
    pr_info("(fm_rds): %s, f_count %ld\n", __func__, file_count(file));
#endif
    fmdev = video_drvdata(file);
    mutex_lock(&fmdev->mutex);
    /* Check if RDS data is available */
    ret = fm_rx_is_rds_data_available(fmdev, file, pts);
    mutex_unlock(&fmdev->mutex);
    if (!ret)
        return POLLIN | POLLRDNORM;
    return 0;
}

static ssize_t show_fmrx_comp_scan(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    /* Chip doesn't support complete scan for weather band */
    if (fmdev->rx.region.fm_band == FM_BAND_WEATHER)
        return -EINVAL;

    return sprintf(buf, "%d\n", fmdev->rx.no_of_chans);
}

static ssize_t store_fmrx_comp_scan(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long comp_scan;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    /* Chip doesn't support complete scan for weather band */
    if (fmdev->rx.region.fm_band == FM_BAND_WEATHER)
        return -EINVAL;

    if (kstrtoul(buf, 0, &comp_scan))
        return -EINVAL;

    ret = fm_rx_seek_station(fmdev, 1, 0);// FM_CHANNEL_SPACING_200KHZ, comp_scan);
    if (ret < 0)
        pr_err("(fmdrv) %s(): RX complete scan failed - %d\n",
						__func__, ret);

    if (comp_scan == COMP_SCAN_READ)
        return (size_t) fmdev->rx.no_of_chans;
    else
        return size;
}

static ssize_t show_fmrx_deemphasis(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", (fmdev->rx.region.deemphasis==
                FM_RX_EMPHASIS_FILTER_50_USEC) ? 50 : 75);
}

static ssize_t store_fmrx_deemphasis(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned char deemph_mode;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, (long unsigned int*)&deemph_mode))
        return -EINVAL;

    ret = fm_rx_config_deemphasis(fmdev,deemph_mode);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Failed to set De-emphasis Mode 0x%x\n",
					__func__, deemph_mode);
        return ret;
    }

    return size;
}

static ssize_t show_fmrx_af(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->rx.af_mode);
}

static ssize_t store_fmrx_af(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long af_mode;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &af_mode))
        return -EINVAL;

    if (af_mode < 0 || af_mode > 1)
        return -EINVAL;

    ret = fm_rx_set_af_switch(fmdev, af_mode);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Failed to set AF Switch %lu\n",
			__func__, af_mode);
        return ret;
    }

    return size;
}

static ssize_t show_fmrx_band(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->rx.region.fm_band);
}

static ssize_t store_fmrx_band(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long fm_band;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);
    if (kstrtoul(buf, 0, &fm_band))
        return -EINVAL;
    pr_info("(fmdrv) %s(): store_fmrx_band In  fm_band %lu\n",
				__func__, fm_band);

    if (fm_band < FM_BAND_EUROPE_US || fm_band > FM_BAND_WEATHER)
        return -EINVAL;

    ret = fm_rx_set_region(fmdev, fm_band);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Failed to set FM Band %lu\n",
				__func__, fm_band);
        return ret;
    }

    return size;
}

static ssize_t show_fmrx_Frequency_Offset_lvl (struct device *dev,
        struct device_attribute *attr, char *buf) { return 0;}

static ssize_t show_fmrx_Noise_Power_lvl(struct device *dev,
        struct device_attribute *attr, char *buf){return 0;}

static ssize_t show_fmrx_Pilot_Power_lvl(struct device *dev,
        struct device_attribute *attr, char *buf){return 0;}

static ssize_t store_fmrx_Frequency_Offset_lvl(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long Frequency_Offset_lvl;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &Frequency_Offset_lvl))
        return -EINVAL;

    ret = fm_rx_set_Frequency_Offset_threshold(fmdev, Frequency_Offset_lvl);
    if (ret < 0) {
        pr_err("Failed to set Frequency_Offset level\n");
        return ret;
    }

    return size;
}

static ssize_t store_fmrx_Noise_Power_lvl(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long Noise_Power_lvl;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &Noise_Power_lvl))
        return -EINVAL;

    ret = fm_rx_set_Noise_Power_threshold(fmdev, Noise_Power_lvl);
    if (ret < 0) {
        pr_err("Failed to set Noise_Power level\n");
        return ret;
    }

    return size;
}

static ssize_t store_fmrx_Pilot_Power_lvl(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long Pilot_Power_lvl;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &Pilot_Power_lvl))
        return -EINVAL;

    ret = fm_rx_set_Pilot_Power_threshold(fmdev, Pilot_Power_lvl);
    if (ret < 0) {
        pr_err("Failed to set Pilot_Power level\n");
        return ret;
    }

    return size;
}


static ssize_t show_fmrx_rssi_lvl(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->rx.curr_rssi_threshold);
}
static ssize_t store_fmrx_rssi_lvl(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long rssi_lvl;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &rssi_lvl))
        return -EINVAL;

    ret = fm_rx_set_rssi_threshold(fmdev, rssi_lvl);
    if (ret < 0) {
        pr_err("Failed to set RSSI level\n");
        return ret;
    }

    return size;
}

static ssize_t show_fmrx_snr_lvl(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->rx.curr_snr_threshold);
}

static ssize_t store_fmrx_snr_lvl(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long snr_lvl;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &snr_lvl))
        return -EINVAL;

    ret = fm_rx_set_snr_threshold(fmdev, snr_lvl);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Failed to set SNR level %lu\n",
			__func__, snr_lvl);
        return ret;
    }

    return size;
}


static ssize_t show_fmrx_curr_snr(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    int ret;
    unsigned int curr_snr = 0;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    ret = fm_rx_get_snr(fmdev,&curr_snr);

    if (ret < 0 )
    {
        pr_err("(fmdrv) %s(): fail to get current SNR\n",
			__func__);
    }

    return sprintf(buf, "%d\n", curr_snr);
}

static ssize_t store_fmrx_curr_snr(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    pr_info("nothing to do for store\n");
    return size;
}



static ssize_t show_fmrx_cos_th(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->rx.curr_cos_threshold);
}

static ssize_t store_fmrx_cos_th(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    signed long cos;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtol(buf, 0, &cos))
        return -EINVAL;

    ret = fm_rx_set_cos_threshold(fmdev, cos);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Failed to set COS level\n",
					__func__);
        return ret;
    }

    return size;
}


static ssize_t show_fmrx_channel_space(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    int chl_space;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    switch( fmdev->rx.sch_step){
	case FM_STEP_50KHZ:
		chl_space= CHL_SPACE_ONE;
		break;
        case FM_STEP_100KHZ:
		chl_space= CHL_SPACE_TWO;
		break;
	case FM_STEP_200KHZ:
		chl_space= CHL_SPACE_FOUR;
		break;
	default:
		chl_space= CHL_SPACE_TWO;
		break;
	};
    return sprintf(buf, "%d\n",chl_space);
}

static ssize_t store_fmrx_channel_space(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long chl_spacing,chl_step;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &chl_spacing))
        return -EINVAL;
    switch( chl_spacing){
        case CHL_SPACE_ONE:
            chl_step= FM_STEP_50KHZ;
            break;
        case CHL_SPACE_TWO:
            chl_step= FM_STEP_100KHZ;
            break;
        case CHL_SPACE_FOUR:
            chl_step= FM_STEP_200KHZ;
            break;
        default:
            chl_step= FM_STEP_100KHZ;
    };
    ret = fmc_set_scan_step(fmdev, chl_step);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Failed to set channel spacing\n",
						__func__);
        return ret;
    }

    return size;
}

static ssize_t show_fmrx_start_snr(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.start_snr);
}

static ssize_t store_fmrx_start_snr(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    unsigned long start_snr;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &start_snr))
        return -EINVAL;

    if (start_snr < FM_START_SNR_MIN || start_snr > FM_START_SNR_MAX)
        return -EINVAL;

    fmdev->softmute_blend_config.start_snr = start_snr;

    return size;
}

static ssize_t show_fmrx_stop_snr(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.stop_snr);
}

static ssize_t store_fmrx_stop_snr(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    unsigned long stop_snr;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &stop_snr))
        return -EINVAL;

    if (stop_snr < FM_STOP_SNR_MIN || stop_snr > FM_STOP_SNR_MAX)
        return -EINVAL;

    fmdev->softmute_blend_config.stop_snr = stop_snr;

    return size;
}

static ssize_t show_fmrx_start_rssi(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.start_rssi);
}

static ssize_t store_fmrx_start_rssi(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    long start_rssi;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtol(buf, 0, &start_rssi))
        return -EINVAL;

    if (start_rssi < FM_START_RSSI_MIN || start_rssi > FM_START_RSSI_MAX)
        return -EINVAL;

    fmdev->softmute_blend_config.start_rssi = start_rssi;

    return size;
}

static ssize_t show_fmrx_stop_rssi(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.stop_rssi);
}

static ssize_t store_fmrx_stop_rssi(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    signed long stop_rssi;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtol(buf, 0, &stop_rssi))
        return -EINVAL;

    if (stop_rssi < FM_STOP_RSSI_MIN || stop_rssi > FM_STOP_RSSI_MAX)
        return -EINVAL;

    fmdev->softmute_blend_config.stop_rssi = stop_rssi;

    return size;
}

static ssize_t show_fmrx_start_mute(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.start_mute);
}


static ssize_t store_fmrx_start_mute(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    unsigned long start_mute;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &start_mute))
        return -EINVAL;

    fmdev->softmute_blend_config.start_mute = start_mute;

    return size;
}

static ssize_t show_fmrx_stop_atten(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.stop_atten);
}

static ssize_t store_fmrx_stop_atten(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    signed long stop_atten;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtol(buf, 0, &stop_atten))
        return -EINVAL;

    if (stop_atten < FM_STOP_ATTEN_MIN || stop_atten > FM_STOP_ATTEN_MAX)
        return -EINVAL;

    fmdev->softmute_blend_config.stop_atten = stop_atten;

    return size;
}

static ssize_t show_fmrx_mute_rate(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.mute_rate);
}

static ssize_t store_fmrx_mute_rate(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    unsigned long mute_rate;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtoul(buf, 0, &mute_rate))
        return -EINVAL;

    if (mute_rate < FM_MUTE_RATE_MIN || mute_rate > FM_MUTE_RATE_MAX)
        return -EINVAL;

    fmdev->softmute_blend_config.mute_rate = mute_rate;

    return size;
}

static ssize_t show_fmrx_snr40(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->softmute_blend_config.snr40);
}

static ssize_t store_fmrx_snr40(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    signed long snr40;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    if (kstrtol(buf, 0, &snr40))
        return -EINVAL;

    if (snr40 < FM_SNR40_MIN || snr40 > FM_SNR40_MAX)
        return -EINVAL;

    fmdev->softmute_blend_config.snr40 = snr40;

    return size;
}


static ssize_t show_fmrx_set_blndmute(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", fmdev->set_blndmute);
}

static ssize_t store_fmrx_set_blndmute(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    int ret;
    unsigned long set_blndmute;
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);
    struct fm_blend_soft_mute p_cfg_blend_softmute;

    if (kstrtoul(buf, 0, &set_blndmute))
        return -EINVAL;

    if (set_blndmute < 0 || set_blndmute > 1)
        return -EINVAL;

    p_cfg_blend_softmute.is_blend = set_blndmute;
    /*Hard code values as per sprd */
    p_cfg_blend_softmute.blend.power_th = 422;
    p_cfg_blend_softmute.blend.phyt = 5;
    p_cfg_blend_softmute.soft_mute.hbound = 427;
    p_cfg_blend_softmute.soft_mute.lbound = 422;

    ret = fm_rx_cfg_blend_softmute (fmdev, &p_cfg_blend_softmute);

    if (ret < 0) {
        pr_err("(fmdrv) %s(): Failed to set softemute and audio blending\n",__func__);
        return ret;
    }
    return size;
}

static ssize_t show_fmrx_search_abort(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", "abort search read no impact.");
}

static ssize_t store_fmrx_search_abort(struct device *dev,
        struct device_attribute *attr, char *buf, size_t size)
{
    struct fmdrv_ops *fmdev = dev_get_drvdata(dev);

    fm_rx_seek_station_abort(fmdev);


    return size;
}

static ssize_t show_fmrx_status(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", radio_disconnected);
}

static ssize_t store_fmrx_status(struct device *dev,
	struct device_attribute *attr, char *buf, size_t size)
{
	pr_info("(fmdrv) %s(): no effect\n", __func__);
	return size;
}

/* structures specific for sysfs entries
 * FM GUI app belongs to group "fmradio", these sysfs entries belongs to "root",
 * but GUI app needs both read and write permissions to these sysfs entires for
 * below features, so these entries got permission "666"
 */

/* To start FM RX complete scan*/
static struct kobj_attribute v4l2_fmrx_comp_scan =
__ATTR(fmrx_comp_scan, 0666, (void *)show_fmrx_comp_scan,
        (void *)store_fmrx_comp_scan);

/* To Set De-Emphasis filter mode */
static struct kobj_attribute v4l2_fmrx_deemph_mode =
__ATTR(fmrx_deemph_mode, 0666, (void *)show_fmrx_deemphasis,
        (void *)store_fmrx_deemphasis);

/* To Enable/Disable FM RX RDS AF feature */
static struct kobj_attribute v4l2_fmrx_rds_af =
__ATTR(fmrx_rds_af, 0666, (void *)show_fmrx_af, (void *)store_fmrx_af);

/* To switch between Japan/US bands */
static struct kobj_attribute v4l2_fmrx_band =
__ATTR(fmrx_band, 0666, (void *)show_fmrx_band, (void *)store_fmrx_band);

/* To set the desired FM reception RSSI level */
static struct kobj_attribute v4l2_fmrx_rssi_lvl =
__ATTR(fmrx_rssi_lvl, 0666, (void *) show_fmrx_rssi_lvl,
        (void *)store_fmrx_rssi_lvl);

/* To set the desired FM reception SNR level */
static struct kobj_attribute v4l2_fmrx_snr_lvl =
__ATTR(fmrx_snr_lvl, 0666, (void *) show_fmrx_snr_lvl,
        (void *)store_fmrx_snr_lvl);

/* To read current SNR level */
static struct kobj_attribute v4l2_fmrx_curr_snr =
__ATTR(fmrx_curr_snr, 0666, (void *) show_fmrx_curr_snr,
        (void *)store_fmrx_curr_snr);

/* To set COS value */
static struct kobj_attribute v4l2_fmrx_cos_th =
__ATTR(fmrx_cos_th, 0666, (void *) show_fmrx_cos_th,
        (void *)store_fmrx_cos_th);

/* To set the desired channel spacing */
static struct kobj_attribute v4l2_fmrx_channel_space =
__ATTR(fmrx_chl_lvl, 0666, (void *) show_fmrx_channel_space,
        (void *)store_fmrx_channel_space);

/* To set start snr */
static struct kobj_attribute v4l2_fmrx_start_snr =
__ATTR(fmrx_start_snr, 0666, (void *) show_fmrx_start_snr,
        (void *)store_fmrx_start_snr);

/* To set stop snr */
static struct kobj_attribute v4l2_fmrx_stop_snr =
__ATTR(fmrx_stop_snr, 0666, (void *) show_fmrx_stop_snr,
        (void *)store_fmrx_stop_snr);

/* To set start rssi */
static struct kobj_attribute v4l2_fmrx_start_rssi =
__ATTR(fmrx_start_rssi, 0666, (void *) show_fmrx_start_rssi,
        (void *)store_fmrx_start_rssi);

/* To set stop rssi */
static struct kobj_attribute v4l2_fmrx_stop_rssi =
__ATTR(fmrx_stop_rssi, 0666, (void *) show_fmrx_stop_rssi,
        (void *)store_fmrx_stop_rssi);


/* To set start mute */
static struct kobj_attribute v4l2_fmrx_start_mute =
__ATTR(fmrx_start_mute, 0666, (void *) show_fmrx_start_mute,
        (void *)store_fmrx_start_mute);

/* To set stop atten */
static struct kobj_attribute v4l2_fmrx_stop_atten =
__ATTR(fmrx_stop_atten, 0666, (void *) show_fmrx_stop_atten,
        (void *)store_fmrx_stop_atten);


/* To set mute rate */
static struct kobj_attribute v4l2_fmrx_mute_rate =
__ATTR(fmrx_mute_rate, 0666, (void *) show_fmrx_mute_rate,
        (void *)store_fmrx_mute_rate);

/* To set snr40 */
static struct kobj_attribute v4l2_fmrx_snr40 =
__ATTR(fmrx_snr40, 0666, (void *) show_fmrx_snr40,
        (void *)store_fmrx_snr40);

/* To start blendmute */
static struct kobj_attribute v4l2_fmrx_set_blndmute =
__ATTR(fmrx_set_blndmute, 0666, (void *) show_fmrx_set_blndmute,
        (void *)store_fmrx_set_blndmute);


/* To abort search */
static struct kobj_attribute v4l2_fmrx_search_abort =
__ATTR(fmrx_search_abort, 0666, (void *) show_fmrx_search_abort,
        (void *)store_fmrx_search_abort);

/* To check radio status */
static struct kobj_attribute v4l2_fmrx_status =
__ATTR(fmrx_status, 0666, (void *) show_fmrx_status,
        (void *)store_fmrx_status);

static struct kobj_attribute v4l2_fmrx_freq_offset =
__ATTR(fmrx_freq_offset, 0666, (void *) show_fmrx_Frequency_Offset_lvl,
        (void *)store_fmrx_Frequency_Offset_lvl);

static struct kobj_attribute v4l2_fmrx_noise_power =
__ATTR(fmrx_noise_power, 0666, (void *) show_fmrx_Noise_Power_lvl,
        (void *)store_fmrx_Noise_Power_lvl);

static struct kobj_attribute v4l2_fmrx_pilot_power =
__ATTR(fmrx_pilot_power, 0666, (void *) show_fmrx_Pilot_Power_lvl,
        (void *)store_fmrx_Pilot_Power_lvl);

static struct attribute *v4l2_fm_attrs[] = {
    &v4l2_fmrx_comp_scan.attr,
    &v4l2_fmrx_deemph_mode.attr,
    &v4l2_fmrx_rds_af.attr,
    &v4l2_fmrx_band.attr,
    &v4l2_fmrx_rssi_lvl.attr,
    &v4l2_fmrx_snr_lvl.attr,
    &v4l2_fmrx_curr_snr.attr,
    &v4l2_fmrx_cos_th.attr,
    &v4l2_fmrx_channel_space.attr,
    &v4l2_fmrx_start_snr.attr,
    &v4l2_fmrx_stop_snr.attr,
    &v4l2_fmrx_start_rssi.attr,
    &v4l2_fmrx_stop_rssi.attr,
    &v4l2_fmrx_start_mute.attr,
    &v4l2_fmrx_stop_atten.attr,
    &v4l2_fmrx_mute_rate.attr,
    &v4l2_fmrx_snr40.attr,
    &v4l2_fmrx_set_blndmute.attr,
    &v4l2_fmrx_search_abort.attr,
    &v4l2_fmrx_status.attr,
    &v4l2_fmrx_freq_offset.attr,
    &v4l2_fmrx_noise_power.attr,
    &v4l2_fmrx_pilot_power.attr,
    NULL,
};
static struct attribute_group v4l2_fm_attr_grp = {
    .attrs = v4l2_fm_attrs,
};

/* Handle open request for "/dev/radioX" device.
 * Start with FM RX mode as default.
 */
static int fm_v4l2_fops_open(struct file *file)
{
    int ret = -EINVAL;
    unsigned char option;
    struct fmdrv_ops *fmdev = NULL;
    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));
    /* Don't allow multiple open */
    if(!atomic_dec_and_test(&v4l2_device_available))
    {
        atomic_inc(&v4l2_device_available);
        pr_err("(fmdrv): FM device is already opened .. v4l2 device busy\n");
        return -EBUSY;
    }

    if (radio_disconnected) {
        pr_err("(fmdrv): FM device is already opened .. radio not disconnected\n");
        return  -EBUSY;
    }

    fmdev = video_drvdata(file);

    if (mutex_lock_interruptible(&fmdev->mutex))
            return -ERESTARTSYS;

    /* initialize the driver */
    ret = fmc_prepare(fmdev);
    if (ret < 0) {
        atomic_inc(&v4l2_device_available);
        pr_err("(fmdrv): Unable to prepare FM CORE");
        mutex_unlock(&fmdev->mutex);
        return ret;
    }

    radio_disconnected = 1;

    ret = fmc_set_mode(fmdev, FM_MODE_RX); /* As of now, support only Rx */
    if (ret < 0) {
	radio_disconnected = 0;
	fmc_release(fmdev);
        atomic_inc(&v4l2_device_available);
        pr_err("(fmdrv): Unable to enable FM");
        mutex_unlock(&fmdev->mutex);
        return ret;
    }

#if(defined(DEF_V4L2_FM_WORLD_REGION) && DEF_V4L2_FM_WORLD_REGION == FM_REGION_NA)
    option = FM_REGION_NA | FM_RBDS_BIT;
#elif(defined(DEF_V4L2_FM_WORLD_REGION) && DEF_V4L2_FM_WORLD_REGION == FM_REGION_EUR)
    option = FM_REGION_EUR | FM_RDS_BIT;
#elif(defined(DEF_V4L2_FM_WORLD_REGION) && DEF_V4L2_FM_WORLD_REGION == FM_REGION_JP)
    option = FM_REGION_JP | FM_RDS_BIT;
#else
    option = 0;
#endif

    /* Enable FM */
    pr_info("(fmdrv): FM Enable INIT option : %d\n", option);
    ret = fmc_enable(fmdev, option);
    if (ret < 0) {
	radio_disconnected = 0;
	fmc_release(fmdev);
        atomic_inc(&v4l2_device_available);
        pr_err("(fmdrv): Unable to enable FM\n");
        mutex_unlock(&fmdev->mutex);
        return ret;
    }

    /* Set Audio mode */
    pr_info("(fmdrv): FM Set Audio mode option : %d\n", DEF_V4L2_FM_AUDIO_MODE);
    ret = fmc_set_audio_mode(fmdev, DEF_V4L2_FM_AUDIO_MODE);
    if (ret < 0) {
	radio_disconnected = 0;
	fmc_release(fmdev);
        atomic_inc(&v4l2_device_available);
        pr_err("(fmdrv): Error setting Audio mode during FM enable operation\n");
        mutex_unlock(&fmdev->mutex);
        return ret;
    }

    /* Set Audio path */
	/*
    pr_info("(fmdrv): FM Set Audio path option : %d\n", DEF_V4L2_FM_AUDIO_PATH);
    ret = fm_rx_config_audio_path(fmdev, DEF_V4L2_FM_AUDIO_PATH);
    if (ret < 0) {
	radio_disconnected = 0;
	fmc_release(fmdev);
        atomic_inc(&v4l2_device_available);
        pr_err("(fmdrv): Error setting Audio path during FM enable operation\n");
        mutex_unlock(&fmdev->mutex);
        return ret;
    }

	*/
    mutex_unlock(&fmdev->mutex);
    return 0;
}

/* Handle close request for "/dev/radioX" device.
 */
static int fm_v4l2_fops_release(struct file *file)
{
    int ret =  -EINVAL;
    struct fmdrv_ops *fmdev;
    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));

    fmdev = video_drvdata(file);

    if (!radio_disconnected) {
        pr_info("(fmdrv):FM dev already closed, close called again?\n");
        return ret;
    }

     mutex_lock(&fmdev->mutex);

    /* First set audio path to NONE */
    ret = fm_rx_config_audio_path(fmdev, FM_AUDIO_NONE);
    if (ret < 0) {
        pr_err("(fmdrv): Failed to set audio path to FM_AUDIO_NONE\n");
        /*ret = 0;*/
    }

    /* Now disable FM */
    ret = fmc_turn_fm_off(fmdev);
    if(ret < 0)
    {
        pr_err("(fmdrv): Error disabling FM. Continuing to release FM core..\n");
        ret = 0;
    }

    ret = fmc_release(fmdev);
    if (ret < 0)
    {
        pr_err("(fmdrv): FM CORE release failed\n");
        radio_disconnected = 0;
        atomic_inc(&v4l2_device_available);
        mutex_unlock(&fmdev->mutex);
        return ret;
    }

    radio_disconnected = 0;
    atomic_inc(&v4l2_device_available);
    mutex_unlock(&fmdev->mutex);
    pr_info("(fmdrv): %s, E\n", __func__);
    return 0;
}

/*****************************************************************************
**   V4L2 RADIO (/dev/radioX) device IOCTL interfaces
*****************************************************************************/

/*
* Function to query the driver capabilities
*/
static int fm_v4l2_vidioc_querycap(struct file *file, void *priv,
                    struct v4l2_capability *capability)
{
    struct fmdrv_ops *fmdev;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));
    fmdev = video_drvdata(file);

    strlcpy(capability->driver, FM_DRV_NAME, sizeof(capability->driver));
    strlcpy(capability->card, FM_DRV_CARD_SHORT_NAME,
                                    sizeof(capability->card));
    sprintf(capability->bus_info, "UART");
    capability->version = FM_DRV_RADIO_VERSION;
    capability->capabilities = fmdev->device_info.capabilities;
    return 0;
}

/*
* Function to query the driver control params
*/
static int fm_v4l2_vidioc_queryctrl(struct file *file, void *priv,
                                        struct v4l2_queryctrl *qc)
{
    int index;
    int ret = -EINVAL;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));
    if (qc->id < V4L2_CID_BASE)
        return ret;

    /* Search control ID and copy its properties */
    for (index = 0; index < NO_OF_ENTRIES_IN_ARRAY(fmdrv_v4l2_queryctrl);\
            index++) {
        if (qc->id && qc->id == fmdrv_v4l2_queryctrl[index].id) {
            memcpy(qc, &(fmdrv_v4l2_queryctrl[index]), sizeof(*qc));
            ret = 0;
            break;
        }
    }
    return ret;
}

/*
* Function to get the driver control params. Called
* by user-space via IOCTL call
*/
static int fm_v4l2_vidioc_g_ctrl(struct file *file, void *priv,
                    struct v4l2_control *ctrl)
{
    int ret = -EINVAL;
    unsigned short curr_vol;
    unsigned char curr_mute_mode;
    struct fmdrv_ops *fmdev;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));
    fmdev = video_drvdata(file);

    switch (ctrl->id) {
        case V4L2_CID_AUDIO_MUTE:    /* get mute mode */
            ret = fm_rx_get_mute_mode(fmdev, &curr_mute_mode);
            if (ret < 0)
                return ret;
            ctrl->value = curr_mute_mode;
            break;

        case V4L2_CID_AUDIO_VOLUME:    /* get volume */
            pr_debug ("(fmdrv): V4L2_CID_AUDIO_VOLUME get\n");
            ret = fm_rx_get_volume(fmdev, &curr_vol);
            if (ret < 0)
                return ret;
            ctrl->value = curr_vol;
            break;

       default:
           pr_debug("(fmdrv): Unhandled IOCTL for get Control\n");
           break;
    }

    return ret;
}

/*
* Function to Set the driver control params. Called
* by user-space via IOCTL call
*/
static int fm_v4l2_vidioc_s_ctrl(struct file *file, void *priv,
                    struct v4l2_control *ctrl)
{
    int ret = -EINVAL;
    struct fmdrv_ops *fmdev;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));
    fmdev = video_drvdata(file);

    switch (ctrl->id) {
        case V4L2_CID_AUDIO_MUTE:    /* set mute */
            ret = fm_rx_set_mute_mode(fmdev, (unsigned char)ctrl->value);
            if (ret < 0)
                return ret;
            break;

        case V4L2_CID_AUDIO_VOLUME:    /* set volume */
            pr_info ("(fmdrv): V4L2_CID_AUDIO_VOLUME set : %d\n", ctrl->value);
            ret = fm_rx_set_volume(fmdev, (unsigned short)ctrl->value);
            if (ret < 0){
                pr_info ("(fmdrv): V4L2_CID_AUDIO_VOLUME ret : %d\n", ret);
                return ret;
            }
            break;

        default:
            pr_debug("(fmdrv): Unhandled IOCTL for set Control\n");
            break;
    }

    return ret;
}

/*
* Function to get the driver audio params. Called
* by user-space via IOCTL call
*/
static int fm_v4l2_vidioc_g_audio(struct file *file, void *priv,
                    struct v4l2_audio *audio)
{
    memset(audio, 0, sizeof(*audio));
    audio->index = 0;
    strcpy(audio->name, "Radio");
    /* For FM Radio device, the audio capability should always return
   V4L2_AUDCAP_STEREO */
    audio->capability = V4L2_AUDCAP_STEREO;
    return 0;
}

/*
* Function to set the driver audio params. Called
* by user-space via IOCTL call
*/
static int fm_v4l2_vidioc_s_audio(struct file *file, void *priv,
                    const struct v4l2_audio *audio)
{
    if (audio->index != 0)
        return -EINVAL;
    return 0;
}

/* Get tuner attributes. This IOCTL call will return attributes like tuner type,
   upper/lower frequency, audio mode, RSSI value and AF channel */
static int fm_v4l2_vidioc_g_tuner(struct file *file, void *priv,
                    struct v4l2_tuner *tuner)
{
    unsigned short curr_rssi;
    unsigned int high = 0, low = 0;
    int ret = -EINVAL;
    struct fmdrv_ops *fmdev;

    if (tuner->index != 0)
        return ret;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));

    fmdev = video_drvdata(file);
    strcpy(tuner->name, "FM");
    tuner->type = fmdev->device_info.type;
    /* The V4L2 specification defines all frequencies in unit of 62.5 kHz */
    ret = fm_rx_get_band_frequencies(fmdev, &low, &high);
    tuner->rangelow = (low * 100000)/625;
    tuner->rangehigh = (high * 100000)/625;

    tuner->audmode =  ((fmdev->rx.audio_mode == FM_AUTO_MODE) ?
                    V4L2_TUNER_MODE_STEREO : V4L2_TUNER_MODE_MONO);
    tuner->capability = fmdev->device_info.tuner_capability;
    tuner->rxsubchans = fmdev->device_info.rxsubchans;

    ret = fm_rx_read_curr_rssi_freq(fmdev, TRUE);
    curr_rssi = fmdev->rx.curr_rssi;

    pr_info ("(fmdrv): fm_v4l2_vidioc_g_tuner curr_rssi : %d\n", curr_rssi);

    /* This is absolute value of negative dBm on SC2331 chipset */
    tuner->signal = curr_rssi;
    ret = 0;
    return ret;
}

/* Set tuner attributes. This IOCTL call will set attributes like
   upper/lower frequency, audio mode.
 */
static int fm_v4l2_vidioc_s_tuner(struct file *file, void *priv,
                    const struct v4l2_tuner *tuner)
{
    int ret = -EINVAL;
    struct fmdrv_ops *fmdev;
    unsigned short high_freq, low_freq;
    unsigned short mode;
    if (tuner->index != 0)
        return ret;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));

    fmdev = video_drvdata(file);

    /* TODO : Figure out how to set the region based on lower/upper freq */
    /* The V4L2 specification defines all frequencies in unit of 62.5 kHz.
    Hence translate the incoming tuner band frequencies to controller
    recognized values. Set only if rangelow/rangehigh is not 0*/
    if(tuner->rangelow != 0 && tuner->rangehigh != 0)
    {
        pr_info("(fmdrv) rangelow:%d rangehigh:%d\n", tuner->rangelow, tuner->rangehigh);
        low_freq = ((tuner->rangelow) * 625)/100000;
        high_freq= ((tuner->rangehigh) * 625)/100000;
        pr_info("(fmdrv) low_freq:%d high_freq:%d\n", low_freq, high_freq);
        ret = fm_rx_set_band_frequencies(fmdev, low_freq, high_freq);
        if (ret < 0)
            return ret;
    }

	if (tuner->rxsubchans & V4L2_TUNER_SUB_RDS)
		ret = fm_rx_enable_rds(fmdev, FM_RDS_ENABLE);
	else
		ret = fm_rx_enable_rds(fmdev, FM_RDS_DISABLE);

    /* Map V4L2 stereo/mono macro to Broadcom controller equivalent audio mode */
    mode = (tuner->audmode == V4L2_TUNER_MODE_STEREO) ?
        FM_AUTO_MODE : FM_MONO_MODE;

    ret = fmc_set_audio_mode(fmdev, mode);
    if (ret < 0)
        return ret;
    return 0;
}

/* Get tuner or modulator radio frequency */
static int fm_v4l2_vidioc_g_frequency(struct file *file, void *priv,
                    struct v4l2_frequency *freq)
{
    int ret;
    struct fmdrv_ops *fmdev;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));
    fmdev = video_drvdata(file);
    ret = fmc_get_frequency(fmdev, &freq->frequency);
    /* Translate the controller frequency to V4L2 specific frequency
        (frequencies in unit of 62.5 Hz):
        x = (y * 100) * 1000/62.5  = y * 160 */
    freq->frequency = (freq->frequency * 160);
    if (ret < 0)
        return ret;
    return 0;
}

/* Set tuner or modulator radio frequency, this is tune channel */
static int fm_v4l2_vidioc_s_frequency(struct file *file, void *priv,
                    const struct v4l2_frequency *freq)
{
    int ret = 0;
    struct fmdrv_ops *fmdev;
    unsigned int frequency;

    pr_info("(fmdrv): %s, f_count %ld\n", __func__, file_count(file));
    fmdev = video_drvdata(file);
    /* Translate the incoming tuner band frequencies
    (frequencies in unit of 62.5 Hz to controller
    recognized values. x = y * (62.5/1000000) * 100 = y / 160 */
   pr_info("(fmdrv): %s, frequency %d\n", __func__, freq->frequency);
    frequency = (freq->frequency/160);
    ret = fmc_set_frequency(fmdev, frequency);
    if (ret < 0)
        return ret;
    return 0;
}

/* Set hardware frequency seek. This is scanning radio stations. */
static int fm_v4l2_vidioc_s_hw_freq_seek(struct file *file, void *priv,
                   const struct v4l2_hw_freq_seek *seek)
{
    int ret = -EINVAL;
    struct fmdrv_ops *fmdev;
    if (seek->tuner != 0)
        return -EINVAL;

    fmdev = video_drvdata(file);

#if V4L2_FM_DEBUG
    pr_debug("(fmdrv) %s direction:%d wrap:%d f_count: %ld\n", __func__,
				seek->seek_upward, seek->wrap_around, file_count(file));
#endif
    ret = fmc_seek_station(fmdev, seek->seek_upward, seek->wrap_around);

    if (ret < 0)
        return ret;
    return 0;
}

static const struct v4l2_file_operations fm_drv_fops = {
    .owner = THIS_MODULE,
    .read = fm_v4l2_fops_read,
    .write = fm_v4l2_fops_write,
    .poll = fm_v4l2_fops_poll,
    /* Since no private IOCTLs are supported currently,
    direct all calls to video_ioctl2() */
    .ioctl = video_ioctl2,
    .open = fm_v4l2_fops_open,
    .release = fm_v4l2_fops_release,
};

static const struct v4l2_ioctl_ops fm_drv_ioctl_ops = {
    .vidioc_querycap = fm_v4l2_vidioc_querycap,
    .vidioc_queryctrl = fm_v4l2_vidioc_queryctrl,
    .vidioc_g_ctrl = fm_v4l2_vidioc_g_ctrl,
    .vidioc_s_ctrl = fm_v4l2_vidioc_s_ctrl,
    .vidioc_g_audio = fm_v4l2_vidioc_g_audio,
    .vidioc_s_audio = fm_v4l2_vidioc_s_audio,
    .vidioc_g_tuner = fm_v4l2_vidioc_g_tuner,
    .vidioc_s_tuner = fm_v4l2_vidioc_s_tuner,
    .vidioc_g_frequency = fm_v4l2_vidioc_g_frequency,
    .vidioc_s_frequency = fm_v4l2_vidioc_s_frequency,
    .vidioc_s_hw_freq_seek = fm_v4l2_vidioc_s_hw_freq_seek
};

/* V4L2 RADIO device parent structure */
static struct video_device fm_viddev_template = {
    .fops = &fm_drv_fops,
    .ioctl_ops = &fm_drv_ioctl_ops,
    .name = FM_DRV_NAME,
    .release = video_device_release,
    .vfl_type = VFL_TYPE_RADIO,
};

int fm_v4l2_init_video_device(struct fmdrv_ops *fmdev, int radio_nr)
{
    int ret = -ENOMEM;

    /* Init mutex for core locking */
    mutex_init(&fmdev->mutex);
    mutex_init(&fmdev->completionmutex);

    gradio_dev = NULL;
    /* Allocate new video device */
    gradio_dev = video_device_alloc();
    if (NULL == gradio_dev) {
        pr_err("(fmdrv): Can't allocate video device\n");
        return -ENOMEM;
    }

    /* Setup FM driver's V4L2 properties */
    memcpy(gradio_dev, &fm_viddev_template, sizeof(fm_viddev_template));

    video_set_drvdata(gradio_dev, fmdev);

    gradio_dev->lock = &fmdev->mutex;

    /* Register with V4L2 subsystem as RADIO device */
    if (video_register_device(gradio_dev, VFL_TYPE_RADIO, radio_nr)) {
        video_device_release(gradio_dev);
        pr_err("(fmdrv): Could not register video device\n");
        return -EINVAL;
    }

    fmdev->radio_dev = gradio_dev;

    pr_info("(fmdrv) registered with video device\n");

    /* Register sysfs entries */
    ret = sysfs_create_group(&fmdev->radio_dev->dev.kobj,
            &v4l2_fm_attr_grp);
    if (ret) {
        pr_err("(fmdrv) %s(): failed to create sysfs entries\n", __func__);
        return -ENOTDIR;
    }

    kobject_uevent(&fmdev->radio_dev->dev.kobj, KOBJ_ADD);
    ret = 0;

    return ret;
}

void *fm_v4l2_deinit_video_device(void)
{
    struct fmdrv_ops *fmdev;

    fmdev = video_get_drvdata(gradio_dev);

    /* Unregister sysfs entries */
    kobject_uevent(&fmdev->radio_dev->dev.kobj, KOBJ_REMOVE);
    sysfs_remove_group(&fmdev->radio_dev->dev.kobj, &v4l2_fm_attr_grp);

    /* Unregister RADIO device from V4L2 subsystem */
    video_unregister_device(gradio_dev);

    return fmdev;
}
