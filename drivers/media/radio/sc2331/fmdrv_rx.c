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

/*******************************************************************************
 *
 *  Filename:      fmdrv_rx.c
 *
 *  Description:   This sub-module of FM driver implements FM RX functionality.
 *
 ***********************************************************************************/

#include "fmdrv.h"
#include "fmdrv_main.h"
#include "fmdrv_rx.h"
#include "fmdrv_config.h"
#include <linux/fm_public.h>

/*******************************************************************************
**  Constants & Macros
*******************************************************************************/

#ifndef DEBUG
#ifdef pr_info
#undef pr_info
#define pr_info(fmt, arg...)
#endif
#endif

const unsigned short fm_sch_step_size[] =     /* darrel issue_06 : 50Khz scan step add. */
{
    50,
    100,
    200
};

extern unsigned short global_frequency;

/************************************************************************************
**  Functions
************************************************************************************/
/************************************************************************************
**  Helper functions
*******************************************************************************/

/* Configures Alternate Frequency switch mode */
int fm_rx_set_af_switch(struct fmdrv_ops *fmdev, u8 af_mode)
{
    u16 payload;
    int ret;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    if (af_mode != FM_RX_RDS_AF_SWITCH_MODE_ON &&
        af_mode != FM_RX_RDS_AF_SWITCH_MODE_OFF) {
        pr_err("(fmdrv) %s(): Invalid af mode 0x%x\n", __func__, af_mode);
        return -EINVAL;
    }
    /* Enable/disable low RSSI interrupt based on af_mode */
    if (af_mode == FM_RX_RDS_AF_SWITCH_MODE_ON)
        fmdev->rx.fm_rds_mask |= I2C_MASK_RSSI_LOW_BIT;
    else
        fmdev->rx.fm_rds_mask &= ~I2C_MASK_RSSI_LOW_BIT;

    payload = fmdev->rx.fm_rds_mask;

    ret = fmc_send_cmd(fmdev, FM_REG_FM_RDS_MSK, &fmdev->rx.fm_rds_mask,
                            2, REG_WR,&fmdev->maintask_completion, NULL, NULL);

    if (ret < 0)
        return ret;

    fmdev->rx.af_mode = af_mode;

    return 0;
}

/*
 * Sets the Frequency offset threshold level to chip side in orde to tune.
 * default value:1500(0x5dc)
 * set value to 80, less station
 * set value to 2304, more station
 * valid range[0x0, 0x1000]
 */
int fm_rx_set_Frequency_Offset_threshold(struct fmdrv_ops *fmdev, short Frequency_Offset_toset)
{

    u16 payload;
    int ret;
    pr_info("(fmdrv) %s(): fm_rx_set_Frequency_Offset_threshold to set is %d\n",
					        __func__,Frequency_Offset_toset);

    if (Frequency_Offset_toset < FM_RX_Frequency_Offset_THRESHOLD_MIN ||
        Frequency_Offset_toset > FM_RX_Frequency_Offset_THRESHOLD_MAX) {
        pr_err("(fmdrv) %s(): Invalid Frequency_Offset threshold level\n",
            __func__);
        return -EINVAL;
    }

    payload = (u16) Frequency_Offset_toset;
    ret = fmc_send_cmd(fmdev, FM_SET_Frequency_Offset_CMD, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL,NULL);

    if (ret < 0)
        return ret;

    return 0;

}


/*
 * Sets the Noise_Power threshold level to chip side in orde to tune.
 * default value:176
 * set value to 5, less station
 * set value to 192, more station
 * valid range[0x000, 0x200]
 */
int fm_rx_set_Noise_Power_threshold(struct fmdrv_ops *fmdev, short Noise_Power_toset)
{

    u16 payload;
    int ret;
    pr_info("(fmdrv) %s(): fm_rx_set_Noise_Power_threshold to set is %d\n",
					        __func__,Noise_Power_toset);

    if (Noise_Power_toset < FM_RX_Noise_Power_THRESHOLD_MIN ||
        Noise_Power_toset > FM_RX_Noise_Power_THRESHOLD_MAX) {
        pr_err("(fmdrv) %s(): Invalid Noise_Power threshold level\n",
            __func__);
        return -EINVAL;
    }

    payload = (u16) Noise_Power_toset;
    ret = fmc_send_cmd(fmdev, FM_SET_Noise_Power_CMD, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL,NULL);

    if (ret < 0)
        return ret;

    return 0;

}

/*
 * Sets the Pilot_Power threshold level to chip side in orde to tune.
 * default value:400
 * set value to <400, no significant effect on the number of stations
 * set value to 768, more station
 * valid range[0x000, 0x300]
 */
int fm_rx_set_Pilot_Power_threshold(struct fmdrv_ops *fmdev, short Pilot_Power_toset)
{

    u16 payload;
    int ret;
    pr_info("(fmdrv) %s(): fm_rx_set_Pilot_Power_threshold to set is %d\n",
					        __func__,Pilot_Power_toset);

    if (Pilot_Power_toset < FM_RX_Pilot_Power_THRESHOLD_MIN ||
        Pilot_Power_toset > FM_RX_Pilot_Power_THRESHOLD_MAX) {
        pr_err("(fmdrv) %s(): Invalid Pilot_Power threshold level\n",
            __func__);
        return -EINVAL;
    }

    payload = (u16) Pilot_Power_toset;
    ret = fmc_send_cmd(fmdev, FM_SET_Pilot_Power_CMD, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL,NULL);

    if (ret < 0)
        return ret;

    return 0;

}

/*
 * Bug 539221 - FM soft blending
 * related command Z150H
 */

int fm_rx_cfg_blend_softmute (struct fmdrv_ops *fmdev,struct fm_blend_soft_mute *p_cfg_blend_softmute) {

	int ret;

	pr_info("(fmdrv) %s(): fm_rx_cfg_blend_softmute to set is %d\n",
				__func__,p_cfg_blend_softmute->is_blend);
	ret = fmc_send_cmd(fmdev, FM_BLEND_SOFTMUTE_SUB_CMD, p_cfg_blend_softmute,
			sizeof(struct fm_blend_soft_mute),REG_WR, &fmdev->maintask_completion, NULL,NULL);
	if (ret < 0)
		return ret;

	return 0;
}

/*
 * Sets the signal strength level that once reached
 * will stop the auto search process
 */
int fm_rx_set_rssi_threshold(struct fmdrv_ops *fmdev, short rssi_lvl_toset)
{
    pr_info("(fmdrv) %s(): fm_rx_set_rssi_threshold to set is %d\n",
					        __func__,rssi_lvl_toset);

    if (rssi_lvl_toset < FM_RX_RSSI_THRESHOLD_MIN ||
        rssi_lvl_toset > FM_RX_RSSI_THRESHOLD_MAX) {
        pr_err("(fmdrv) %s(): Invalid RSSI threshold level\n",
            __func__);
        return -EINVAL;
    }

    fmdev->rx.curr_rssi_threshold = rssi_lvl_toset;

    return 0;
}


/*
 * Sets the signal strength level that once reached
 * will stop the auto search process
 */
int fm_rx_set_snr_threshold(struct fmdrv_ops *fmdev, short snr_lvl_toset)
{
    u16 payload;
    int ret;

    if (snr_lvl_toset < FM_RX_SNR_THRESHOLD_MIN ||
        snr_lvl_toset > FM_RX_SNR_THRESHOLD_MAX) {
        pr_err("(fmdrv) %s(): Invalid SNR threshold level, %d\n",
            __func__, snr_lvl_toset);
        return -EINVAL;
    }
    payload = (u16) snr_lvl_toset;
    ret = fmc_send_cmd(fmdev, FM_SEARCH_SNR, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL,NULL);

    if (ret < 0)
        return ret;

    fmdev->rx.curr_snr_threshold= snr_lvl_toset;

    return 0;
}

/*
 * Sets the Carrier Offset Slop
 */
int fm_rx_set_cos_threshold(struct fmdrv_ops *fmdev, short cos_toset)
{
    u16 payload;
    int ret;

    if (cos_toset < FM_RX_COS_MIN||
        cos_toset > FM_RX_COS_MAX) {
        pr_err("(fmdrv) %s(): Invalid COS threshold value, %d\n",
            __func__, cos_toset);
        return -EINVAL;
    }
    payload = (u16) cos_toset;
    ret = fmc_send_cmd(fmdev, FM_RES_PRESCAN_QUALITY, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL,NULL);

    if (ret < 0)
        return ret;

    fmdev->rx.curr_cos_threshold= cos_toset;

    return 0;
}


/*
* Function to validate if the tuned/scanned frequency is valid
* or not
*/
int check_if_valid_freq(struct fmdrv_ops *fmdev, unsigned short frequency)
{
/* darrel issue_01 : 87.50 Mhz, 87.55 Mhz , 107.95 Mhz, 108.00Mhz  is valid frequency */
    if(frequency < fmdev->rx.region.low_bound ||
            frequency > fmdev->rx.region.high_bound)
    {
        pr_info("(fmdrv) %s(): %d - Literally out of range",
				__func__, FM_SET_FREQ(frequency));
        return FALSE;
    }
    else
    {
        pr_info("(fmdrv) %s(): %d - Freq in range",
				__func__, FM_SET_FREQ(frequency));
        return TRUE;
    }
}

/*
* Function to read the FM_RDS_FLAG registry
*/
int read_fm_rds_flag(struct fmdrv_ops *fmdev, unsigned short *value)
{
    unsigned char read_length;
    int ret;
    int resp_len;
    unsigned char resp_buf [2];

    read_length = FM_READ_2_BYTE_DATA;
    ret = fmc_send_cmd(fmdev, FM_REG_FM_RDS_FLAG, &read_length, sizeof(read_length), REG_RD,
                    &fmdev->maintask_completion, &resp_buf, &resp_len);
    *value = (unsigned short)resp_buf[0] +
                ((unsigned short)resp_buf[1] << 8);
    pr_info("(fmdrv) %s: FM Mask : 0x%x ", __func__, *value);
    return 0;
}

/*
* Function to read the FM_RDS_FLAG registry
*/
int fm_rx_set_mask(struct fmdrv_ops *fmdev, unsigned short mask)
{
    int ret;
    unsigned short flag;

    fmdev->rx.fm_rds_flag|= FM_RDS_FLAG_CLEAN_BIT; /* clean FM_RDS_FLAG */
    ret = read_fm_rds_flag(fmdev, &flag);
    FM_CHECK_SEND_CMD_STATUS(ret);

    ret = fmc_send_cmd(fmdev, FM_REG_FM_RDS_MSK, &mask, sizeof(mask), REG_WR,
            &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);
    return ret;
}

/*
only call byfm_rx_seek_station().
*/

int init_start_search(struct fmdrv_ops *fmdev, unsigned short start_freq,
				unsigned char mode, unsigned char direction)
{
	unsigned char * payload;
	/*unsigned short tmp_fm_rds_mask;*/
	int ret;
	FM_SEARCH_PAR_T fm_search_payload={0,};

	fm_search_payload.startFreq = start_freq;
	fm_search_payload.scanMode = mode;
	fm_search_payload.rssiThresh = fmdev->rx.curr_rssi_threshold; /*103db is default*/
	/*fm_search_payload.rssiThresh=0x69;*/ /*-105dbm*/
	fm_search_payload.direction = direction;

	payload = (unsigned char*) &fm_search_payload;

	ret = fmc_send_cmd(fmdev, FM_COMSEARCH_SUB_CMD, payload,
			sizeof(fm_search_payload), REG_WR,
	                &fmdev->maintask_completion, NULL, NULL);
	FM_CHECK_SEND_CMD_STATUS(ret);
	pr_info("(fmdev) %s(): FM_COMSEARCH_SUB_CMD set to 0x%x\n",
						__func__, payload[0]);
	pr_info("(fmdev) %s(): start_freq= 0x%x,direction=0x%x\n",
					__func__, start_freq,direction);
	fmc_reset_rds_cache(fmdev);

    return 0;
}



/*
* Function to process a SEEK complete event. This function determines
* whether to wrap the search, or stop the search or return error
* to user-space. This is called internally by fm_rx_seek_station() function.
*/
int process_seek_event(struct fmdrv_ops *fmdev)
{
    unsigned short tmp_freq, start_freq;
    int ret = -EINVAL;
    bool is_valid_freq;

    tmp_freq = fmdev->rx.curr_freq;
    is_valid_freq = check_if_valid_freq(fmdev, tmp_freq);

/* darrel issue_01 : to check boundary frequency    */
    if(((FM_SET_FREQ(tmp_freq) - 5) <= FM_SET_FREQ(fmdev->rx.region.low_bound)) ||
       ((FM_SET_FREQ(tmp_freq) + 5)  >= FM_SET_FREQ(fmdev->rx.region.high_bound)))
    {
        is_valid_freq = FALSE;
    }

#if V4L2_FM_DEBUG
    pr_info("(fmdrv) %s(): tmp:%d low:%d high:%d\n", __func__,
        tmp_freq, fmdev->rx.region.low_bound, fmdev->rx.region.high_bound);
#endif
    /* First check if Scan suceeded or not */
    if(fmdev->rx.curr_search_state == FM_STATE_SEEK_ERR)
    {
        fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_FRZ_BIT;
        if(!fmdev->rx.seek_wrap && !is_valid_freq)
        {
            fmdev->rx.curr_search_state = FM_STATE_SEEK_ERR;
            pr_err("(fmdrv) %s(): Seek ended with out of bound frequency %d.\n",
						__func__, FM_SET_FREQ(tmp_freq));
           return FALSE;
        }
        else if(fmdev->rx.seek_wrap && !is_valid_freq)
        {
            pr_err("(fmdrv) %s(): Scan ended with out of bound frequency. Wrapping search again..\n",
					__func__);

            start_freq = (fmdev->rx.seek_direction==FM_SCAN_DOWN)?
                (fmdev->rx.region.high_bound):(fmdev->rx.region.low_bound);
            pr_info("(fmdev) %s(): Current scanned frequency is out of bounds. Resetting to freq (%d)\n",
                        __func__, FM_SET_FREQ(start_freq));

            ret = init_start_search(fmdev, start_freq, FM_TUNER_SEEK_MODE,fmdev->rx.seek_direction);
            if(ret < 0)
            {
                fmdev->rx.curr_search_state = FM_STATE_SEEK_ERR;
                fmdev->rx.curr_freq = 0;
                pr_err ("(fmdrv) %s(): Error starting search for Seek operation\n", __func__);
                return FALSE;
            }

            fmdev->rx.curr_search_state = FM_STATE_SEEKING;
            pr_info ("(fmdrv) %s(): Started wrapped-up Seek operation\n",
								__func__);
            return TRUE;
        }
        else
        {
            fmdev->rx.curr_search_state = FM_STATE_SEEK_ERR;
            pr_err("(fmdrv) %s(): *** ERROR :: Seek failed for %d frequency ***\n",
					__func__, FM_SET_FREQ(tmp_freq));
            return FALSE;
        }
    }
    else
    {
        pr_info("(fmdrv) %s(): Seek success!\n", __func__);
        fmdev->rx.curr_search_state = FM_STATE_SEEK_CMPL;
        return TRUE;
    }
}

/************************************************************************************
**  Main functions - Called by fmdrv_main and fmdrv_v4l2.
************************************************************************************/

/*
* Function to read current RSSI and tuned frequency
*/
int fm_rx_read_curr_rssi_freq(struct fmdrv_ops *fmdev, unsigned char rssi_only)
{
	int ret = 0, resp_len;
	/* unsigned char payload; */
	/* unsigned short tmp_frq; */
	unsigned char resp_buf[1];

	/* Read current RSSI */
	ret = fmc_send_cmd(fmdev, FM_GET_RSSI_SUB_CMD, NULL, 0, REG_RD,
			&fmdev->maintask_completion, &resp_buf[0], &resp_len);
	FM_CHECK_SEND_CMD_STATUS(ret);
	/* 04 0e len 01 8c fc status rssi  */
	fmdev->rx.curr_rssi =resp_buf[0];
	pr_info("(fmdev) %s: FM_GET_RSSI_SUB_CMD: curr_rssi(%d),resp_len(%d)\n",
				__func__, fmdev->rx.curr_rssi,resp_len);

	if(rssi_only)
		return 0;

	/* Read current frequency, sprd has no cmd to support to read*/

	fmdev->rx.curr_freq = global_frequency;
	pr_info("(fmdev) %s: global_frequency: %d\n",
				__func__, fmdev->rx.curr_freq);

    return ret;
}


/*
* Function for FM TUNE frequency implementation

*/
int fm_rx_set_frequency(struct fmdrv_ops *fmdev, unsigned int freq_to_set)
{
    int ret;
    unsigned short payload;
	int resp_len;
	unsigned char resp_buf[5];
	pr_info("(fmdev) %s(): freq_to_set : %d\n", __func__, freq_to_set);
	payload=(unsigned short)freq_to_set;
    /* response :Tune (uint8 status, uint8 rssi, uint8 snr, uint16 freq)*/
    ret = fmc_send_cmd(fmdev, FM_TUNE_SUB_CMD, &payload, sizeof(payload), REG_WR,
            &fmdev->maintask_completion, &resp_buf[0], &resp_len);
    FM_CHECK_SEND_CMD_STATUS(ret);

	fmdev->rx.curr_freq=(resp_buf[3]<<8)+resp_buf[2]; //need to check
	global_frequency=fmdev->rx.curr_freq;
	pr_info("(fmdev) %s(): global_frequency : %d,resp_buf=%d %d %d\n", __func__, global_frequency,resp_buf[0],resp_buf[1],resp_buf[2]);
    return ret;

}




/*
* Function for FM TUNE frequency implementation
*   * Set the other registries such as Search method, search
*    direction, etc.
*   * Start preset search.
*   * Based on interrupt received, read the current tuned freq
*     and validate the search.
*   * If search frequency out of bound, return error code -EAGAIN
*   * If not, read RSSI, reset RDS cache and set RDS MASK to the earlier value.
*/
int brcm_fm_rx_set_frequency(struct fmdrv_ops *fmdev, unsigned int freq_to_set)
{
    unsigned short tmp_frq;
    int ret = -EINVAL;
    unsigned long timeleft;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;
    tmp_frq = FM_GET_FREQ(freq_to_set);
    if(!check_if_valid_freq(fmdev, tmp_frq))
    {
        pr_err("(fmdrv): %s(): called with %d - out of bound range (%d-%d)\n",
            __func__, freq_to_set, FM_SET_FREQ(fmdev->rx.region.low_bound),
            FM_SET_FREQ(fmdev->rx.region.high_bound));
        return -EINVAL;
    }

    ret = init_start_search(fmdev, tmp_frq, FM_TUNER_PRESET_MODE,fmdev->rx.seek_direction);
    if(ret < 0)
    {
        pr_err ("(fmdrv) %s(): Error starting search for Seek operation\n",
					__func__);
        return ret;
    }

    /* Wait for tune ended interrupt */
    init_completion(&fmdev->maintask_completion);
    timeleft = wait_for_completion_timeout(&fmdev->maintask_completion,
                           FM_DRV_TX_TIMEOUT);
    if (!timeleft)
    {
        pr_err("(fmdrv) %s(): Timeout(%d sec), didn't get tune ended interrupt\n",
               __func__, jiffies_to_msecs(FM_DRV_TX_TIMEOUT) / 1000);
        fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_FRZ_BIT;
        return -ETIMEDOUT;
    }
#if 0
    else {
	pr_info("(fmdrv) %s(): Seek %u ms\n", __func__,
			jiffies_to_msecs(FM_DRV_TX_TIMEOUT - timeleft));
    }
#endif

    /* First check if Tune suceeded or not */
    if(fmdev->rx.curr_search_state == FM_STATE_TUNE_ERR)
    {
        pr_err("(fmdrv) %s(): failed for %d MHz frequency\n",
				__func__, FM_SET_FREQ(tmp_frq));
        fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_FRZ_BIT;
        return -EAGAIN;
    }
    pr_info("(fmdrv) %s(): Set frequency done!\n", __func__);
    fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_FRZ_BIT;

    fm_rx_read_curr_rssi_freq(fmdev, FALSE);
    /* Reset RDS Cache */
    fmc_reset_rds_cache(fmdev);

    if(fmdev->rx.fm_rds_mask)
    {
        /* Update the FM_RDS_MASK to set the earlier bits */
        pr_info("(fmdrv) %s(): Update FM_RDS_MASK : 0x%x\n",
				__func__, fmdev->rx.fm_rds_mask);
        ret = fmc_send_cmd(fmdev, FM_REG_FM_RDS_MSK, &fmdev->rx.fm_rds_mask,
            sizeof(fmdev->rx.fm_rds_mask), REG_WR,
            &fmdev->maintask_completion, NULL, NULL);
    }

    return 0;
}

/*
* Function to get the current tuned frequency
* This function will query
* to determine the current tuned frequency.
*/
int fm_rx_get_frequency(struct fmdrv_ops *fmdev, unsigned int *curr_freq)
{
	*curr_freq = global_frequency;

    pr_info("(fmdev) %s(): curr_freq - %d\n", __func__, *curr_freq);
    return 0;
}

/*
* Function to get the current SNR
* This function will query controller by reading the FM_REG_SNR(0xdf)
* to read current SNR.
*/
int fm_rx_get_snr(struct fmdrv_ops *fmdev, unsigned int *curr_snr)
{
    unsigned char payload;

    int ret;
    int resp_len;

    payload = 2;
    ret = fmc_send_cmd(fmdev, FM_REG_SNR, &payload, 1, REG_RD,
            &fmdev->maintask_completion, curr_snr, &resp_len);
    FM_CHECK_SEND_CMD_STATUS(ret);
    pr_info("(fmdev) %s(): FM_REG_SNR : %d\n", __func__, *curr_snr);

    return ret;
}


/*SPRD
* Function to start a FM SEEK Operation.
*   * Set the start frequency.
*   * Set the other registries such as Search method, search
*    direction, etc.
*   * Start search.
*   * Based on interrupt received, read the current tuned freq
*     and validate the search.
*   * If search frequency out of bound and no wrap_around needed,
*    end the search and return error code -EINVAL
*   * If not, start the search again and check for interrupt.
*   * If no interrupt is received by 20 sec, timeout the seek operation
*/
int fm_rx_seek_station(struct fmdrv_ops *fmdev, unsigned char direction_upward,
                            unsigned char wrap_around)
{
    int ret = 0, freq;
    unsigned short tmp_freq, start_freq;
    unsigned long timeleft;
	unsigned direction;

    fmdev->rx.seek_direction = (direction_upward)?FM_SCAN_UP:FM_SCAN_DOWN;
    fmdev->rx.curr_sch_mode = ((FM_TUNER_NORMAL_SCAN_MODE & 0x01) |
                                                (fmdev->rx.seek_direction & 0x80));
    if( !wrap_around )
        wrap_around = 1;
    fmdev->rx.seek_wrap = wrap_around;
// seek_direction:0x01 curr_sch_mode:0x80 seek_wrap:0x1
    pr_info("(fmdrv) %s(): seek_direction:0x%x curr_sch_mode:0x%x seek_wrap:0x%x\n", __func__,
                    fmdev->rx.seek_direction, fmdev->rx.curr_sch_mode, fmdev->rx.seek_wrap);

    ret = fm_rx_get_frequency(fmdev, &freq);
 //   tmp_freq = FM_GET_FREQ(freq);
     start_freq=freq;
     direction = (direction_upward)?FM_SCAN_UP:FM_SCAN_DOWN;

    pr_info("(fmdrv) %s(): Starting FM seek (%s) from %d..\n",
		__func__, (direction_upward?"SEEKUP":"SEEKDOWN"), start_freq);



    ret = init_start_search(fmdev, start_freq, FM_TUNER_SEEK_MODE,direction);
    if(ret < 0)
    {
        pr_err ("(fmdrv) %s(): Error starting search for Seek operation\n",
								__func__);
        return -EINVAL;
    }

    /* Wait for tune ended interrupt */
    init_completion(&fmdev->seektask_completion);
    timeleft = wait_for_completion_timeout(&fmdev->seektask_completion,
                           FM_DRV_RX_SEEK_TIMEOUT);
    if (!timeleft)
    {
        pr_err("(fmdrv) %s(): Timeout(%d sec),didn't get seek ended interrupt\n",
               __func__, jiffies_to_msecs(FM_DRV_RX_SEEK_TIMEOUT) / 1000);
        fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_FRZ_BIT;
        return -ETIMEDOUT;
    }

    pr_info("(fmdrv) fm_rx_seek_station completion");

    fm_rx_read_curr_rssi_freq(fmdev, FALSE);
    tmp_freq = fmdev->rx.curr_freq;
    ret = process_seek_event(fmdev);
    if(ret && fmdev->rx.curr_search_state == FM_STATE_SEEK_CMPL)
    {
        /* Reset RDS Cache */
        fmc_reset_rds_cache(fmdev);
        if(fmdev->rx.fm_rds_mask)
        /* Update the FM_RDS_MASK to set the earlier bits */
        ret = fmc_send_cmd(fmdev, FM_REG_FM_RDS_MSK, &fmdev->rx.fm_rds_mask,
            sizeof(fmdev->rx.fm_rds_mask), REG_WR,
            &fmdev->maintask_completion, NULL, NULL);
        return 0;
    }
    if(!ret)
    {
        pr_err("(fmdrv) %s(): Error during Seek. Try again!\n", __func__);
        return -EINVAL;
    }
    else if(ret && fmdev->rx.curr_search_state == FM_STATE_SEEKING)
    {

        /* Wait for tune ended interrupt */
        init_completion(&fmdev->seektask_completion);
        timeleft = wait_for_completion_timeout(&fmdev->seektask_completion,
                               FM_DRV_RX_SEEK_TIMEOUT);

        fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_FRZ_BIT;
        if (!timeleft)
        {
            pr_err("(fmdrv) %s(): Timeout(%d sec),didn't get Seek ended interrupt\n",
                   __func__, jiffies_to_msecs(FM_DRV_RX_SEEK_TIMEOUT) / 1000);
            return -ETIMEDOUT;
        }

        fm_rx_read_curr_rssi_freq(fmdev, FALSE);

        /* First check if Scan suceeded or not */
        if(fmdev->rx.curr_search_state == FM_STATE_SEEK_ERR)
        {
            pr_err("(fmdrv) %s(): Wrap Seek failed for %d frequency\n",
			__func__,  FM_SET_FREQ(fmdev->rx.curr_freq));
            return -EAGAIN;
        }
        pr_info("(fmdrv) %s(): Wrap Seek done!\n", __func__);
        /* Reset RDS Cache */
        fmc_reset_rds_cache(fmdev);
        /* Update the FM_RDS_MASK to set the earlier bits */
        ret = fmc_send_cmd(fmdev, FM_REG_FM_RDS_MSK, &fmdev->rx.fm_rds_mask,
            sizeof(fmdev->rx.fm_rds_mask), REG_WR,
            &fmdev->maintask_completion, NULL, NULL);
        return 0;
    }

    pr_err("(fmdrv) %s(): Unhandled case in Seek\n", __func__);
    return -EINVAL;
}



/*
* Function to Abort on-going scanning operation.
*/
int fm_rx_seek_station_abort(struct fmdrv_ops *fmdev)
{
    //unsigned char payload;
    int ret;

    //payload = FM_TUNER_NORMAL_SCAN_MODE;

    ret = fmc_send_cmd(fmdev, FM_ABORT_SUB_CMD, NULL, 0,
            REG_WR, &fmdev->maintask_completion, NULL, NULL);

    pr_info("(fmdrv) %s(): ret %d\n", __func__, ret);

    if (ret < 0)
        return ret;

    return 0;
}


/*
*Function to set band's high and low frequencies
*/
int fm_rx_set_band_frequencies(struct fmdrv_ops *fmdev, unsigned int low_freq,
    unsigned int high_freq)
{
    if((fmdev->rx.region.high_bound == FM_GET_FREQ(high_freq)) &&
        (fmdev->rx.region.low_bound = FM_GET_FREQ(low_freq)))
    {
        pr_err("(fmdrv) %s(): Ignoring setting the same band frequencies\n",
							__func__);
        return 0;
    }
    fmdev->rx.region.high_bound = FM_GET_FREQ(high_freq);
    fmdev->rx.region.low_bound = FM_GET_FREQ(low_freq);
    return 0;
}

/*
*Function to get the current band's high and low frequencies
*/
int fm_rx_get_band_frequencies(struct fmdrv_ops *fmdev, unsigned int *low_freq,
    unsigned int *high_freq)
{
    *high_freq= FM_SET_FREQ(fmdev->rx.region.high_bound);
    *low_freq= FM_SET_FREQ(fmdev->rx.region.low_bound) ;
    return 0;
}

/*
* Function to set the volume
*/
int fm_rx_set_volume(struct fmdrv_ops *fmdev, unsigned short vol_to_set)
{

    /* darrel issue_04 : FM_REG_VOLUME_CTRL use UINT16 (0 - 256) */
    /*payload type changed unsigned char=> unsigned short*/
    /* unsigned char payload; */
    unsigned short payload;

    int ret;
    unsigned char read_length;
    unsigned short actual_volume;

    if(vol_to_set > FM_RX_VOLUME_MAX)
        actual_volume = (vol_to_set/FM_RX_VOLUME_RATIO);
    else
        actual_volume = vol_to_set;
    pr_info("(fmdrv) %s() Actual volume to set  : %d\n",
	        __func__,actual_volume);

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    if (actual_volume > FM_RX_VOLUME_MAX)
    {
        pr_err("(fmdrv) %s(): Volume %d is not within(%d-%d) range\n",
                        __func__, vol_to_set, FM_RX_VOLUME_MIN, FM_RX_VOLUME_MAX);
        actual_volume = 0xFF;
    }

    payload = actual_volume & 0x1ff;
    ret = fmc_send_cmd(fmdev, FM_REG_VOLUME_CTRL, &payload, sizeof(payload),
        REG_WR, &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);

    fmdev->rx.curr_volume = vol_to_set;
    /* Read current volume */
    read_length = FM_READ_1_BYTE_DATA;
    ret = fm_rx_get_volume(fmdev, &(fmdev->rx.curr_volume));
    pr_info("(fmdrv) %s(): Volume read : %d\n", __func__, fmdev->rx.curr_volume);
    if(ret == -ETIMEDOUT)
        return -EBUSY;
    return ret;
}

/*
*Function to Get volume
*/
int fm_rx_get_volume(struct fmdrv_ops *fmdev, unsigned short *curr_vol)
{
    int ret, resp_len;

    /* darrel issue_04 : FM_REG_VOLUME_CTRL use UINT16 (0 - 256) */
    //unsigned char resp_buf[2];
    unsigned short resp_buf;

    unsigned char read_length;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    if (curr_vol == NULL)
    {
        pr_err("(fmdrv) %s(): Invalid memory\n", __func__);
        return -ENOMEM;
    }

    /* Read current volume */
    read_length = FM_READ_2_BYTE_DATA;
    ret = fmc_send_cmd(fmdev, FM_REG_VOLUME_CTRL, &read_length, 1, REG_RD,
                        &fmdev->maintask_completion, &resp_buf, &resp_len);
    FM_CHECK_SEND_CMD_STATUS(ret);
    pr_info("(fmdrv) %s(): fm_rx_get_volume ret : %d\n", __func__, ret);

    *curr_vol = fmdev->rx.curr_volume = resp_buf;
    pr_info("(fmdrv) %s(): Volume read : 0x%x\n",
			__func__, fmdev->rx.curr_volume);
    return ret;
}

/* Sets band (0-US; 1-Europe; 2-Japan) */
int fm_rx_set_region(struct fmdrv_ops *fmdev,
            unsigned char region_to_set)
{
    unsigned char payload = FM_REGION_EUR;

    int ret = -EPERM;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return ret;

    if (region_to_set != FM_REGION_NA &&
            region_to_set != FM_REGION_EUR &&
                    region_to_set != FM_REGION_JP)
    {
        pr_err("(fmdrv) %s(): Invalid band\n", __func__);
        ret = -EINVAL;
        return ret;
    }
    if (region_to_set == FM_REGION_JP)/* set japan region */
    {
        payload |= FM_REGION_JP;
    }

    pr_info("(fmdrv) %s(): region_to_set : 0x%x\n",
			__func__,region_to_set );
    /* Send cmd to set the band  */
    ret = fmc_send_cmd(fmdev, FM_SETREGION_SUB_CMD, &payload, sizeof(payload), REG_WR,
        &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);

    fmc_update_region_info(fmdev, region_to_set);

    return ret;
}

/*
* Function to retrieve audio control param
* from controller
*/
int fm_rx_get_audio_ctrl(struct fmdrv_ops *fmdev, uint16_t *audio_ctrl)
{
    uint16_t payload = FM_READ_2_BYTE_DATA;
    int ret = -EINVAL, resp_len;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return ret;

    /* Send cmd to set the band  */
    ret = fmc_send_cmd(fmdev, FM_SETAUDIOMODE_SUB_CMD, &payload, sizeof(payload), REG_RD,
                &fmdev->maintask_completion, audio_ctrl, &resp_len);
    FM_CHECK_SEND_CMD_STATUS(ret);
    fmdev->aud_ctrl = fmdev->rx.aud_ctrl = *audio_ctrl;
    if(ret == -ETIMEDOUT)
        return -EBUSY;
    return ret;
}

/*
* Function to set the audio control param
* to controller
*/
int fm_rx_set_audio_ctrl(struct fmdrv_ops *fmdev,uint16_t audio_ctrl)
{
    uint16_t payload = audio_ctrl;
    int ret = -EINVAL;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return ret;

    /* Send cmd to set the band  */
    ret = fmc_send_cmd(fmdev, FM_SETAUDIOMODE_SUB_CMD, &payload, sizeof(payload), REG_WR,
                &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);
    fmdev->aud_ctrl = fmdev->rx.aud_ctrl = audio_ctrl;
    if(ret == -ETIMEDOUT)
        return -EBUSY;
    return ret;
}

/*
* Function to Read current mute mode (Mute Off/On)
*/
int fm_rx_get_mute_mode(struct fmdrv_ops *fmdev,
            unsigned char *curr_mute_mode)
{
    uint16_t tmp;
    int ret = -EINVAL;
    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    if (curr_mute_mode == NULL) {
        pr_err("(fmdrv) %s(): Invalid memory\n", __func__);
        return -ENOMEM;
    }
    ret = fm_rx_get_audio_ctrl(fmdev, &tmp);
    *curr_mute_mode = fmdev->rx.curr_mute_mode = tmp & FM_MANUAL_MUTE;
    pr_info("(fmdrv) %s(): Mute is %s\n", __func__, ((*curr_mute_mode)?"ON":"OFF"));
    return 0;
}

/*
* Configures mute mode (Mute Off/On)
*/
int fm_rx_set_mute_mode(struct fmdrv_ops *fmdev,
            unsigned char mute_mode_toset)
{
    int ret;
    uint16_t aud_ctrl;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;
    /* First read the aud_ctrl*/
    ret = fm_rx_get_audio_ctrl(fmdev, &aud_ctrl);
    /* turn on MUTE */
    if (mute_mode_toset)
    {
        aud_ctrl|= FM_MANUAL_MUTE;
    }
    else /* unmute */
    {
        aud_ctrl &= (~FM_MANUAL_MUTE);
    }
    ret = fm_rx_set_audio_ctrl (fmdev, aud_ctrl);
    FM_CHECK_SEND_CMD_STATUS(ret);
    if (mute_mode_toset)
       msleep(300);
    pr_info("(fmdrv) %s(): Current mute state : %d\n", __func__, mute_mode_toset);
    fmdev->rx.curr_mute_mode = mute_mode_toset;
    return ret;
}

/* Sets RX stereo/mono modes */
int fm_rx_set_audio_mode(struct fmdrv_ops *fmdev, unsigned char mode)
{
    unsigned char audio_ctrl = FM_STEREO_SWITCH|FM_STEREO_AUTO;
    int ret;

    if (fmdev->curr_fmmode != FM_MODE_RX)
     return -EPERM;

    if (mode != FM_STEREO_MODE && mode != FM_MONO_MODE &&
        mode != FM_AUTO_MODE && mode != FM_SWITCH_MODE)
    {
        pr_err("(fmdrv) %s(): Invalid mode :%d\n", __func__, mode);
        return -EINVAL;
    }

    if (fmdev->rx.audio_mode == mode)
    {
        pr_info ("(fmdrv) %s(): no change in audio mode\n", __func__);
        return 0;
    }
    switch (mode)
    {
        case FM_SWITCH_MODE: /* stereo witch in auto mode */
            /* as default */;
            break;
        case FM_MONO_MODE: /* manually set to mono, bit2 OFF is mono */
            audio_ctrl &= ~FM_STEREO_AUTO;/* set to manual mono */
            break;
        case FM_STEREO_MODE: /* manually set to stereo */
            audio_ctrl  &= ~FM_STEREO_AUTO; /* set to manual */
            audio_ctrl |= FM_STEREO_MANUAL; /* set to stereo in manual mode */
            break;
        case FM_AUTO_MODE:/* auto blend as default,  */
            audio_ctrl  &= ~FM_STEREO_SWITCH; /* turn OFF bit3 to activate blend */
            break;
        default:
            break;
    }
    /* set the region bit */
    audio_ctrl |= (fmdev->rx.curr_region == FM_REGION_JP) ? \
                                FM_BAND_REG_EAST : FM_BAND_REG_WEST;

    /* Set stereo/mono mode */
    ret = fmc_send_cmd(fmdev, FM_SETAUDIOMODE_SUB_CMD, &audio_ctrl, sizeof(audio_ctrl),
            REG_WR, &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);
    fmdev->rx.audio_mode = mode;
    if(mode == FM_MONO_MODE)
    {
        fmdev->device_info.rxsubchans |= V4L2_TUNER_SUB_MONO;
        fmdev->device_info.rxsubchans &= ~V4L2_TUNER_SUB_STEREO;
    }
    if(mode == FM_STEREO_MODE)
    {
        fmdev->device_info.rxsubchans |= V4L2_TUNER_SUB_STEREO;
        fmdev->device_info.rxsubchans &= ~V4L2_TUNER_SUB_MONO;
    }
    return 0;
}

/* Gets current RX stereo/mono mode */
int fm_rx_get_audio_mode(struct fmdrv_ops *fmdev, unsigned char *mode)
{
    int ret, len;
    unsigned char payload = FM_READ_1_BYTE_DATA, resp;
    if (fmdev->curr_fmmode != FM_MODE_RX)
    return -EPERM;

    if (mode == NULL)
    {
        pr_err("(fmdrv) %s(): Invalid memory\n", __func__);
        return -ENOMEM;
    }
    ret = fmc_send_cmd(fmdev, FM_SETAUDIOMODE_SUB_CMD, &payload, sizeof(payload),
            REG_RD, &fmdev->maintask_completion, &resp, &len);
    if((resp & FM_STEREO_SWITCH) && (resp & FM_STEREO_AUTO))
        *mode = FM_SWITCH_MODE;
    else if(!(resp & FM_STEREO_AUTO))
            *mode = FM_MONO_MODE;
    else if(!(resp & FM_STEREO_AUTO) && (resp & FM_STEREO_MANUAL))
            *mode = FM_STEREO_MODE;
    else if(!(resp & FM_STEREO_SWITCH))
            *mode = FM_AUTO_MODE;
    fmdev->rx.audio_mode = resp;
    return ret;
}

/* Sets RX stereo/mono modes */
int fm_rx_config_audio_path(struct fmdrv_ops *fmdev, unsigned char path)
{
    int ret;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    if (fmdev->rx.audio_path == path)
    {
        pr_info ("(fmdrv) %s(): no change in audio path\n", __func__);
        return 0;
    }
    /* if FM is on SCO and request to turn off FM over SCO */
    if (!(path & FM_AUDIO_BT_MONO) &&
                (fmdev->rx.pcm_reg & FM_PCM_ROUTE_ON_BIT))
    {
        /* disable pcm_reg CB value FM routing bit */
        fmdev->rx.pcm_reg &= ~FM_PCM_ROUTE_ON_BIT;
    }
    else if((path & FM_AUDIO_BT_MONO) &&
                !(fmdev->rx.pcm_reg & FM_PCM_ROUTE_ON_BIT)) /* turn on FM via SCO */
    {
        /* when FM to SCO active, FM enforce I2S output */
        path |= FM_AUDIO_I2S;
        /* turn on pcm_reg CB value FM routing bit */
        fmdev->rx.pcm_reg |= FM_PCM_ROUTE_ON_BIT;
    }

    /* write to PCM_ROUTE register */
    ret = fmc_send_cmd(fmdev, FM_REG_PCM_ROUTE,
            &fmdev->rx.pcm_reg, sizeof(fmdev->rx.pcm_reg), REG_WR,
            &fmdev->maintask_completion, NULL, NULL);

    FM_CHECK_SEND_CMD_STATUS(ret);

    if (path & FM_AUDIO_I2S)
        fmdev->rx.aud_ctrl |= FM_AUDIO_I2S_ON;
    else
        fmdev->rx.aud_ctrl &= ~((unsigned short)FM_AUDIO_I2S_ON);

    if (path & FM_AUDIO_DAC)
        fmdev->rx.aud_ctrl |= FM_AUDIO_DAC_ON;
    else
        fmdev->rx.aud_ctrl &= ~((unsigned short)FM_AUDIO_DAC_ON);

    ret = fm_rx_set_audio_ctrl (fmdev, fmdev->rx.aud_ctrl);

    FM_CHECK_SEND_CMD_STATUS(ret);
    fmdev->rx.audio_path = path;

    return 0;
}

/* Choose RX de-emphasis filter mode (50us/75us) */
int fm_rx_config_deemphasis(struct fmdrv_ops *fmdev, unsigned char mode)
{
    int ret;

    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    if (mode != FM_DEEMPHA_50U &&
        mode != FM_DEEMPHA_75U)
    {
        pr_err("(fmdrv) %s(): Invalid rx de-emphasis mode\n", __func__);
        return -EINVAL;
    }

    if (mode == FM_DEEMPHA_50U )
        /* set to 50us by turning off 6th bit */
        fmdev->rx.aud_ctrl &=  (~FM_DEEMPHA_75_ON);
    else
        /* set to 75us by turning on 6th bit */
        fmdev->rx.aud_ctrl |=  FM_DEEMPHA_75_ON;

    ret = fm_rx_set_audio_ctrl (fmdev, fmdev->rx.aud_ctrl);

    FM_CHECK_SEND_CMD_STATUS(ret);

    return 0;
}

/*
* Function to get the current scan step.
* Returns FM_STEP_100KHZ or FM_STEP_200KHZ
*/
int fm_rx_get_scan_step(struct fmdrv_ops *fmdev,
            unsigned char *step_type)
{
    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    if (step_type == NULL)
    {
        pr_err("(fmdrv) %s(): Invalid memory\n", __func__);
        return -ENOMEM;
    }
    *step_type = fmdev->rx.sch_step;
    return 0;
}

/*
* Sets scan step to 100 or 200 KHz based on step type :
* FM_STEP_100KHZ or FM_STEP_200KHZ
*/
int fm_rx_set_scan_step(struct fmdrv_ops *fmdev,
            unsigned char step_type)
{
    int ret;
    unsigned short payload;
    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

       /* turn on MUTE */
    if (fmdev->rx.sch_step == step_type)
    {
        pr_info ("(fmdrv) %s(): no change in scan step size\n", __func__);
        return 0;
    }
    payload = fm_sch_step_size[step_type];    /* darrel issue_06  */
    ret = fmc_send_cmd(fmdev, FM_SETSCANSTEP_SUB_CMD, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);

    fmdev->rx.sch_step = step_type;
    return ret;
}

/************************************************************************************
** RDS functions
************************************************************************************/

/* Sets RDS operation mode (RDS/RDBS) */
int fm_rx_set_rds_system(struct fmdrv_ops *fmdev, unsigned char rdbs_en_dis)
{
    unsigned char payload;
    int ret;
    pr_debug("(fmdrv) %s()\n", __func__);
    if (fmdev->curr_fmmode != FM_MODE_RX)
        return -EPERM;

    /* Set RDS control */
    if (rdbs_en_dis == FM_RDBS_ENABLE)
        payload = 0;  //0 is enable RDBS
    else
        payload = 1; // 1is enable RDS

    ret = fmc_send_cmd(fmdev, FM_SETRDSTYPE_SUB_CMD, &payload, sizeof(payload),
                        REG_WR, &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);

    return 0;
}

/*
* Function to enable RDS. Called during FM enable.
*/
int fm_rx_enable_rds(struct fmdrv_ops *fmdev, u8 RdsOn)
{
	unsigned short payload;
	int ret = 0;
	unsigned char AfOn=0;
	/* unsigned char RdsType = 1;*/
	payload=(AfOn << 8 )+RdsOn;
	ret = fmc_send_cmd(fmdev, FM_SETRDSMODE_SUB_CMD, &payload, sizeof(payload),
                        REG_WR, &fmdev->maintask_completion, NULL, NULL);

	if(ret < 0) {
		pr_err("(fmdrv) %s(%d): Error control RSD function\n", __func__, RdsOn);
		return ret;
	}

	fmdev->rx.rds.rds_flag = RdsOn;
	if (RdsOn)
		fmdev->device_info.rxsubchans |= V4L2_TUNER_SUB_RDS;
	else
		fmdev->device_info.rxsubchans &= ~V4L2_TUNER_SUB_RDS;

	return ret;

#if 0

	// set RDS Type : 1:RDS;    0: RDBS

	ret = fmc_send_cmd(fmdev, FM_SETRDSTYPE_SUB_CMD, &RdsType, sizeof(RdsType),
                        REG_WR, &fmdev->maintask_completion, NULL, NULL);
    if(ret<0)
    pr_err("(fmdrv) %s(): Error enable RSD Type\n");

#endif

#if 0
    if(fmdev->rx.fm_func_mask & (FM_RDS_BIT | FM_RBDS_BIT))
    {
        payload = FM_RDS_UPD_TUPLE;
        /* write RDS FIFO waterline in depth of RDS tuples */
        ret = fmc_send_cmd(fmdev, FM_REG_RDS_WLINE, &payload, sizeof(payload),
                            REG_WR, &fmdev->maintask_completion, NULL, NULL);
        if(ret<0)
            pr_err("(fmdrv) %s(): Error writing to RDS FIFO waterline register\n",
									__func__);
        /* drain RDS FIFO */
        payload = FM_RDS_FIFO_MAX;
        ret = fmc_send_cmd(fmdev, FM_REG_RDS_DATA, &payload, 1,
                            REG_RD, &fmdev->maintask_completion, NULL, NULL);

        /* set new FM_RDS mask so that RDS read */
        fmdev->rx.fm_rds_mask |= I2C_MASK_RDS_FIFO_WLINE_BIT;
    }
    else
    {
        pr_err("(fmdrv) %s(): RDS not enabled during FM enable\n", __func__);
        fmdev->rx.fm_rds_mask &= ~I2C_MASK_RDS_FIFO_WLINE_BIT;
    }
    fm_rx_set_mask(fmdev, fmdev->rx.fm_rds_mask);
    /* Reset the fm_rds_flag here as for the first time we dont get
    any interrupt during ENABLE to cleanup the bit */
    fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_CLEAN_BIT;

#endif

}

/*
* Returns availability of RDS data in internel buffer.
* If data is present in RDS buffer, return 0. Else, return -EAGAIN.
* The V4L2 driver's poll() uses this method to determine RDS data availability.
*/
int fm_rx_is_rds_data_available(struct fmdrv_ops *fmdev, struct file *file,
                  struct poll_table_struct *pts)
{
    poll_wait(file, &fmdev->rx.rds.read_queue, pts);
    if (fmdev->rx.rds.rd_index != fmdev->rx.rds.wr_index) {
        pr_info("(fmdrv) %s(): Poll success. RDS data is available in buffer\n",
							__func__);
        return 0;
    }
    pr_err("(fmdev) %s(): RDS Buffer is empty\n", __func__);
    return -EAGAIN;
}



/*
 * Sets the signal strength level that once reached
 * will stop the auto search process
 */
int fm_rx_set_cfg_blnd_mute(struct fmdrv_ops *fmdev, unsigned char set_blndmute)
{
    int ret;

    ret = fmc_send_cmd(fmdev, FM_REG_BLEND_MUTE, &(fmdev->softmute_blend_config), sizeof(fmdev->softmute_blend_config),
            REG_WR, &fmdev->maintask_completion, NULL,NULL);

    if (ret < 0)
        return ret;

    fmdev->set_blndmute = set_blndmute;

    return 0;
}
