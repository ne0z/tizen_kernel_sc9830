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
 *  Filename:      fmdrv_config.h
 *
 *  Description:   Configuration file for V4L2 FM driver module.
 *  Configurations such as World region, Scan step, Audio mode, NFL will be set
 *  in this file as these params are not defined by the standard V4L2 driver
 *
 ***********************************************************************************/

#ifndef _FM_DRV_CONFIG_H
#define _FM_DRV_CONFIG_H

#include <linux/fm_public.h>
#include "fmdrv_main.h"
#include <media/v4l2-common.h>

/*******************************************************************************
**  Constants & Macros
*******************************************************************************/
//#define DEBUG 1
/* Set default World region */
#define DEF_V4L2_FM_WORLD_REGION FM_REGION_EUR

/* Set default Audio mode */
#define DEF_V4L2_FM_AUDIO_MODE FM_STEREO_MODE

/* Set default Audio path */
#define DEF_V4L2_FM_AUDIO_PATH FM_AUDIO_DAC

/* FM driver debug flag. Set this to FALSE for Production release */
#define V4L2_FM_DEBUG TRUE

/* FM driver RDS debug flag. Set this to FALSE for Production release */
#define V4L2_RDS_DEBUG TRUE

/* Set default Noise Floor Estimation value */
#define DEF_V4L2_FM_NFE 93
#define DEF_V4L2_FM_SIGNAL_STRENGTH 103  /*RSSI default Value -103dbm=0x67*/
#define DEF_V4L2_FM_RSSI 0x55 /* RSSI threshold value 85 dBm */

/*******************************************************************************
**  Static Variables
*******************************************************************************/
#ifdef FMDRV_V4L2_QUERYCTRL
/* Query control */
static struct v4l2_queryctrl fmdrv_v4l2_queryctrl[] = {
    {
        .id = V4L2_CID_AUDIO_VOLUME,
        .type = V4L2_CTRL_TYPE_INTEGER,
        .name = "Volume",
        .minimum = FM_RX_VOLUME_MIN,
        .maximum = FM_RX_VOLUME_MAX,
        .step = 1,
        .default_value = FM_DEFAULT_RX_VOLUME,
    },
    {
        .id = V4L2_CID_AUDIO_BALANCE,
        .flags = V4L2_CTRL_FLAG_DISABLED,
    },
    {
        .id = V4L2_CID_AUDIO_BASS,
        .flags = V4L2_CTRL_FLAG_DISABLED,
    },
    {
        .id = V4L2_CID_AUDIO_TREBLE,
        .flags = V4L2_CTRL_FLAG_DISABLED,
    },
    {
        .id = V4L2_CID_AUDIO_MUTE,
        .type = V4L2_CTRL_TYPE_BOOLEAN,
        .name = "Mute",
        .minimum = 0,
        .maximum = 2,
        .step = 1,
        .default_value = FM_MUTE_OFF,
    },
    {
        .id = V4L2_CID_AUDIO_LOUDNESS,
        .flags = V4L2_CTRL_FLAG_DISABLED,
    },
// may need private control
};
#endif
#ifdef FMDRV_REGION_CONFIGS
/* Region info */
static struct region_info region_configs[] = {
     /* Europe */
    {
     .low_bound = FM_GET_FREQ(8750),    /* 87.5 MHz */
     .high_bound = FM_GET_FREQ(10800),    /* 108 MHz */
     .deemphasis = FM_DEEMPHA_50U,
     .scan_step = 100,
     },

    /* Japan */
    {
     .low_bound = FM_GET_FREQ(7600),    /* 76 MHz */
     .high_bound = FM_GET_FREQ(9000),    /* 90 MHz */
     .deemphasis = FM_DEEMPHA_50U,
     .scan_step = 100,
     },

     /* North America */
     {
      .low_bound = FM_GET_FREQ(8750),    /* 87.5 MHz */
      .high_bound = FM_GET_FREQ(10800),    /* 108 MHz */
      .deemphasis = FM_DEEMPHA_75U,
      .scan_step = 200,
      },

     /* Russia-Ext */
    {
     .low_bound = FM_GET_FREQ(6580),    /* 65.8 MHz */
     .high_bound = FM_GET_FREQ(10800),    /* 108 MHz */
     .deemphasis = FM_DEEMPHA_75U,
     .scan_step = 100,
    },

    /* China Region */
    {
     .low_bound = FM_GET_FREQ(7600),    /* 76 MHz */
     .high_bound = FM_GET_FREQ(10800),    /* 108 MHz */
     .deemphasis = FM_DEEMPHA_75U,
     .scan_step = 100,
     },
};

#endif
#endif
