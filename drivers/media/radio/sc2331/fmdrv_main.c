/*
 *  FM Driver for Connectivity chip of Broadcom Corporation.
 *
 *  This sub-module of FM driver is common for FM RX and TX
 *  functionality. This module is responsible for:
 *  1) Forming group of Channel-8 commands to perform particular
 *     functionality (eg., frequency set require more than
 *     one Channel-8 command to be sent to the chip).
 *  2) Sending each Channel-8 command to the chip and reading
 *     response back over Shared Transport.
 *  3) Managing TX and RX Queues and Tasklets.
 *  4) Handling FM Interrupt packet and taking appropriate action.
 *
 *  Copyright (C) 2009 Texas Instruments
 *  Copyright (C) 2009-2014 Broadcom Corporation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
/************************************************************************************
 *
 *  Filename:      fmdrv_main.c
 *
 *  Description:   Common sub-module for both FM Rx and Tx. Currently, only
 *                  is supported
 *
 ***********************************************************************************/

#include <linux/module.h>
#include <linux/delay.h>
#include "fmdrv.h"
#include "fmdrv_v4l2.h"
#include "fmdrv_main.h"
#include "../../../bluetooth/hci_uart_bcm.h"
#include "fmdrv_rx.h"
#include <linux/fm_public.h>
#define  FMDRV_REGION_CONFIGS
#include "fmdrv_config.h"

#ifndef DEBUG
#ifdef pr_info
#undef pr_info
#define pr_info(fmt, arg...)
#endif
#endif

/*******************************************************************************
**  Static Variables
*******************************************************************************/

/* Band selection */

static unsigned char default_radio_region;    /* US */
module_param(default_radio_region, byte, 0);
MODULE_PARM_DESC(default_radio_region, "Region: 0=US, 1=Europe, 2=Japan");

/* RDS buffer blocks */
static unsigned int default_rds_buf = 300;
module_param(default_rds_buf, uint, 0444);
MODULE_PARM_DESC(rds_buf, "RDS buffer entries");

/* Radio Nr */
static int radio_nr = -1;
module_param(radio_nr, int, 0);
MODULE_PARM_DESC(radio_nr, "Radio Nr");
#if (defined CONFIG_BCM_BT_LPM && defined CONFIG_TIZEN_WIP)
extern  struct notifier_block hci_event_nblock;
#endif

/*******************************************************************************
**  Forward function declarations
*******************************************************************************/

long (*g_bcm_write) (struct sk_buff *skb);

int parse_inrpt_flags(struct fmdrv_ops *fmdev);
int parse_rds_data(struct fmdrv_ops *fmdev);
void send_read_intrp_cmd(struct fmdrv_ops *fmdev);
int read_rds_data(struct fmdrv_ops *);

unsigned short global_frequency=8750;
unsigned char global_cur_rssi=0x6C; //-105dBm default
unsigned char global_VSE_subevent=0;

/*******************************************************************************
**  Functions
*******************************************************************************/

//#ifdef FM_DUMP_TXRX_PKT
 /* To dump outgoing FM Channel-8 packets */
inline void dump_tx_skb_data(struct sk_buff *skb)
{
    int len, len_org;
    char index;
    struct fm_cmd_msg_hdr_sprd *cmd_hdr;

    cmd_hdr = (struct fm_cmd_msg_hdr_sprd *)skb->data;
    printk(KERN_INFO "<<%shdr:%02x len:%02x opcode:%02x",
           fm_cb(skb)->completion ? " " : "*", cmd_hdr->header,
           cmd_hdr->len, cmd_hdr->fm_opcode);

    len_org = skb->len - FM_CMD_MSG_HDR_SIZE_SPRD;
    if (len_org > 0)
    {
        //printk("\n   data(%d): ", cmd_hdr->dlen);
        len = min(len_org, 14);
        for (index = 0; index < len; index++)
            printk("%x ",
                   skb->data[FM_CMD_MSG_HDR_SIZE_SPRD + index]);
        printk("%s", (len_org > 14) ? ".." : "");
    }
    printk("\n");
}

 /* To dump incoming FM Channel-8 packets */
inline void dump_rx_skb_data(struct sk_buff *skb)
{
    int len, len_org;
    char index;
    struct fm_event_msg_hdr  *evt_hdr;

    evt_hdr = (struct fm_event_msg_hdr *)skb->data;
    printk(KERN_INFO ">> header:%02x event:%02x len:%02x",
        evt_hdr->header, evt_hdr->event_id, evt_hdr->len);

    len_org = skb->len - FM_EVT_MSG_HDR_SIZE;
    if (len_org > 0)
    {
        printk("\n   data(%d): ", evt_hdr->len);
        len = min(len_org, 14);
        for (index = 0; index < len; index++)
            printk("%x ",
                   skb->data[FM_EVT_MSG_HDR_SIZE + index]);
        printk("%s", (len_org > 14) ? ".." : "");
    }
    printk("\n");
}

//#endif

/*
 * Store the currently set region
 */
void fmc_update_region_info(struct fmdrv_ops *fmdev,
                unsigned char region_to_set)
{
    fmdev->rx.curr_region = region_to_set;
    memcpy(&fmdev->rx.region, &region_configs[region_to_set],
        sizeof(struct region_info));
    fmdev->rx.curr_freq = fmdev->rx.region.low_bound;
    fm_rx_config_deemphasis( fmdev,fmdev->rx.region.deemphasis);
}

/*
* FM common sub-module will schedule this tasklet whenever it receives
* FM packet from ST driver.
*/
static void __recv_tasklet(unsigned long arg)
{
    struct fmdrv_ops *fmdev;
    struct fm_event_msg_hdr *fm_evt_hdr;
    struct sk_buff *skb;
    unsigned long flags;
    unsigned char sub_event, *p;
	unsigned char rdsdata_len=0;
	unsigned char tmpbuf[64]={0};
	unsigned char ps,rds_type;
	unsigned char i;

    fmdev = (struct fmdrv_ops *)arg;

	pr_err("wsh___recv_tasklet");
    /* Process all packets in the RX queue */
    while ((skb = skb_dequeue(&fmdev->rx_q)))
    {
        if (skb->len < sizeof(struct fm_event_msg_hdr))
        {
            pr_err("(fmdrv): skb(%p) has only %d bytes"
                            "atleast need %lu bytes to decode\n",
                                        skb, skb->len,
                                (unsigned long)sizeof(struct fm_event_msg_hdr));
            kfree_skb(skb);
            continue;
        }
//#ifdef FM_DUMP_TXRX_PKT
        dump_rx_skb_data(skb);
//#endif
        fm_evt_hdr = (void *)skb->data;
		pr_err("\neventid=%02x ,last_sent_pkt_opcode=%02x \n",fm_evt_hdr->event_id,fmdev->last_sent_pkt_opcode);

if(fmdev->response_completion != NULL){

	pr_info("response_completion have completion\n");

}
        if (fm_evt_hdr->event_id == HCI_EV_CMD_COMPLETE)
        {
            struct fm_cmd_complete_hdr_sprd *cmd_complete_hdr;
            cmd_complete_hdr = (struct fm_cmd_complete_hdr_sprd *) &skb->data [FM_EVT_MSG_HDR_SIZE];
			pr_err("the header is : %2x \n",cmd_complete_hdr->fm_opcode);
            /* Anyone waiting for this with completion handler? */
            if (/*cmd_complete_hdr->fm_opcode == fmdev->last_sent_pkt_opcode && */
                                fmdev->response_completion != NULL)
            {
                pr_info("(fmdrv) %s() : Command complete Event\n", __func__);
                if (fmdev->response_skb != NULL)
                    pr_err("(fmdrv) %s(): Response SKB ptr not NULL\n", __func__);

                if(cmd_complete_hdr->fm_opcode == FM_REG_FM_RDS_MSK)
                    fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_FRZ_BIT;

                spin_lock_irqsave(&fmdev->resp_skb_lock, flags);
                fmdev->response_skb = skb;
                spin_unlock_irqrestore(&fmdev->resp_skb_lock, flags);
                complete(fmdev->response_completion);

                fmdev->response_completion = NULL;
                atomic_set(&fmdev->tx_cnt, 1);
            }
		}
            /* This is the VSE interrupt handler case */

	  else if (fm_evt_hdr->event_id == 0xFF)

            {
                pr_info("(fmdrv) %s : VSE interrupt handler case\n", __func__);
                if (fmdev->response_skb != NULL)
                    pr_err("(fmdrv) %s(): Response SKB ptr not NULL\n", __func__);
               p = &skb->data[FM_EVT_MSG_HDR_SIZE];

               STREAM_TO_UINT8(sub_event, p);
			   //sub_event=0x30,p=0x0,p+1=0xae,p+2=0x0.p:after subevent
			   pr_info("sub_event=0x%x,p=0x%x,p+1=0x%x,p+2=0x%x",sub_event,p[0],p[1],p[2]);

			if(sub_event==0x30)
			{
			    spin_lock_irqsave(&fmdev->resp_skb_lock, flags);
			    fmdev->response_skb = skb;
                            spin_unlock_irqrestore(&fmdev->resp_skb_lock, flags);

                            complete(&fmdev->seektask_completion);

                       //(&fmdev->seektask_completion)= NULL;

			global_frequency=(p[4]<<8)+p[3];
			global_VSE_subevent =sub_event;
			global_cur_rssi=p[1];
			/*		fmdev->rx.curr_rssi_threshold=p[1]; */
			pr_info("seek freq is %d\n",global_frequency);
                       atomic_set(&fmdev->tx_cnt, 1);}
				else if(sub_event==0x31)
					{
					  pr_info("This is AF jump event\n");

					}
				else {
                           pr_info("This is RDS data event from controller\n");
                           rdsdata_len=*(p-2);
                           p=p-2;
						   ps=sub_event;
#if 0
                           rds_type=sub_event;
                           pr_info("RDS data before memcopy,rdsdata_len=%x\n",rdsdata_len);
                           fmdev->rx.rds.rd_index=900; //when before read, default value
                           memcpy(&fmdev->rx.rds.cbuffer[0], p,rdsdata_len+1);
                           fmdev->rx.rds.wr_index=rdsdata_len+1;
                           fmdev->rx.rds.buf_size=rdsdata_len+1;

                           if (fmdev->rx.rds.wr_index != fmdev->rx.rds.rd_index)
                           pr_info("after memcopy\n");
                           for(i=0;i<rdsdata_len+1;i++)
                           {
                           pr_info("p[%d]=%x__",i,p[i]);
                           }
						   pr_info("\n");
                           wake_up_interruptible(&fmdev->rx.rds.read_queue);
#endif

//#if 0
					  if(ps==0x07)
						{   pr_info("ps data before memcopy,rdsdata_len=%x\n",rdsdata_len);
					        fmdev->rx.rds.rd_index=900; //when before read, default value
						    memcpy(&fmdev->rx.rds.cbuffer[0], p,rdsdata_len+1);
							fmdev->rx.rds.wr_index=rdsdata_len+1;
							fmdev->rx.rds.buf_size=rdsdata_len+1;

							if (fmdev->rx.rds.wr_index != fmdev->rx.rds.rd_index)
							pr_info("after memcopy\n");
							for(i=0;i<rdsdata_len+1;i++)
								{
									pr_info("p[%d]=%x__",i,p[i]);
								}
                            wake_up_interruptible(&fmdev->rx.rds.read_queue);

						}
					  if(ps==0x09)
						{
							pr_info("RT data comming");
							fmdev->rx.rds.rd_index=900; //when before read, default value
						    memcpy(&fmdev->rx.rds.cbuffer[0], p,rdsdata_len+1);
							fmdev->rx.rds.wr_index=rdsdata_len+1;
							fmdev->rx.rds.buf_size=rdsdata_len+1;

							if (fmdev->rx.rds.wr_index != fmdev->rx.rds.rd_index)
							pr_info("after memcopy\n");
							for(i=0;i<rdsdata_len+1;i++)
								{
									pr_info("p[%d]=%x__",i,p[i]);
								}
                            wake_up_interruptible(&fmdev->rx.rds.read_queue);


						}
//#endif


					}
	kfree_skb(skb);
        }

       // else if(fm_evt_hdr->event_id == BRCM_FM_VS_EVENT) /* Vendor specific Event */
       else if(fm_evt_hdr->event_id ==0xFE)
        {
            p = &skb->data[FM_EVT_MSG_HDR_SIZE];

            /* Check if this is a FM vendor specific event */
            STREAM_TO_UINT8(sub_event, p);
            if(sub_event == BRCM_VSE_SUBCODE_FM_INTERRUPT)
            {
                pr_info("(fmdrv) %s(): VSE Interrupt event for FM received\n",
								__func__);
		pr_info("(fmdrv) %s(): Calling fmc_send_intrp_cmd()\n",
								__func__);
                send_read_intrp_cmd(fmdev);
            }
        }
        else
        {
            pr_err("(fmdrv) %s(): Unhandled packet SKB(%p),purging\n", __func__, skb);
        }
        if (!skb_queue_empty(&fmdev->tx_q))
                tasklet_schedule(&fmdev->tx_task);
    }
}

/*
* FM send tasklet: is scheduled when
* FM packet has to be sent to chip */
static void __send_tasklet(unsigned long arg)
{
    struct fmdrv_ops *fmdev;
    struct sk_buff *skb;
    int len;

    fmdev = (struct fmdrv_ops *)arg;
    /* Send queued FM TX packets */
    if (atomic_read(&fmdev->tx_cnt))
    {
        skb = skb_dequeue(&fmdev->tx_q);
        if (skb)
        {
            atomic_dec(&fmdev->tx_cnt);
            fmdev->last_sent_pkt_opcode = fm_cb(skb)->fm_opcode;

            if (fmdev->response_completion != NULL)
                    pr_err("(fmdrv) %s(): Response completion handler is not NULL\n",
									__func__);

            fmdev->response_completion = fm_cb(skb)->completion;
            pr_info("(fmdrv): %s(): *** pkt_type 0x%x\n",
					__func__, sh_ldisc_cb(skb)->pkt_type);
            /* SYED : Hack to set the right packet type for FM */
            sh_ldisc_cb(skb)->pkt_type = FM_PKT_LOGICAL_CHAN_NUMBER;
            /* Write FM packet to hci shared ldisc driver */
            len = g_bcm_write(skb);
            if (len < 0)
            {
                pr_err("(fmdrv): %s(): TX tasklet failed to send skb(0x%p)\n",
						__func__, skb);
                kfree_skb(skb);
                fmdev->response_completion = NULL;
                atomic_set(&fmdev->tx_cnt, 1);
            }
            else {
                fmdev->last_tx_jiffies = jiffies;
            }
        }
    }
}

/* Queues FM Channel-8 packet to FM TX queue and schedules FM TX tasklet for
 * transmission */
static int __fm_send_cmd(struct fmdrv_ops *fmdev, unsigned char fmreg_index,
                void *payload, int payload_len, unsigned char type,
                struct completion *wait_completion)
{
    struct sk_buff *skb;
    struct fm_cmd_msg_hdr_sprd *cmd_hdr;
    int size;
#if (defined CONFIG_BCM_BT_LPM && defined CONFIG_TIZEN_WIP)
    hci_event_nblock.notifier_call(NULL,HCI_DEV_WRITE,NULL);
#endif

    size = FM_CMD_MSG_HDR_SIZE_SPRD + ((payload == NULL) ? 0 : payload_len);

    skb = alloc_skb(size, GFP_ATOMIC);
    if (!skb)
    {
        pr_err("(fmdrv): %s(): No memory to create new SKB\n",
					__func__);
        return -ENOMEM;
    }

    /* Fill command header info */
    cmd_hdr =(struct fm_cmd_msg_hdr_sprd *)skb_put(skb, FM_CMD_MSG_HDR_SIZE_SPRD);

    /* kilsung Change for 4343S  */
    cmd_hdr->header = 0x01; /* FM_PKT_LOGICAL_CHAN_NUMBER;*/    /* 0x08 */
    /* 3 (cmd, len, fm_opcode,rd_wr) */
    cmd_hdr->cmd = hci_opcode_pack(HCI_GRP_VENDOR_SPECIFIC, FM_SPRD_OP_CODE);

    cmd_hdr->len = ((payload == NULL) ? 0 : payload_len) + 1;    //need to check
    /* FM opcode */
    cmd_hdr->fm_opcode = fmreg_index;
    /* read/write type */
   // cmd_hdr->rd_wr = type;

    fm_cb(skb)->fm_opcode = fmreg_index;

    if (payload != NULL)
            memcpy(skb_put(skb, payload_len), payload, payload_len);

    fm_cb(skb)->completion = wait_completion;
    skb_queue_tail(&fmdev->tx_q, skb);
    tasklet_schedule(&fmdev->tx_task);

    return 0;
}


/* Sends FM Channel-8 command to the chip and waits for the reponse */
int fmc_send_cmd(struct fmdrv_ops *fmdev, unsigned char fmreg_index,
            void *payload, int payload_len, unsigned char type,
            struct completion *wait_completion, void *reponse,
            int *reponse_len)
{
    struct sk_buff *skb;
    struct fm_event_msg_hdr *fm_evt_hdr;
    struct fm_cmd_complete_hdr_sprd *cmd_complete_hdr;
    unsigned long timeleft;
    unsigned long flags;
    int ret;

    mutex_lock(&fmdev->completionmutex);
    init_completion(wait_completion);
    ret = __fm_send_cmd(fmdev, fmreg_index, payload, payload_len, type,
                            wait_completion);
    if (ret < 0)
        return ret;

    timeleft = wait_for_completion_timeout(wait_completion, FM_DRV_TX_TIMEOUT);
    if (!timeleft)
    {
        pr_err("(fmdrv) %s(): Timeout(%d sec),didn't get reg 0x%02X "
                            "completion signal from RX tasklet\n",
			__func__, jiffies_to_msecs(FM_DRV_TX_TIMEOUT) / 1000, fmreg_index);
        mutex_unlock(&fmdev->completionmutex);
        return -ETIMEDOUT;
    }
    mutex_unlock(&fmdev->completionmutex);
    if (!fmdev->response_skb) {
        pr_err("(fmdrv) %s(): Reponse SKB is missing for 0x%02X\n", __func__, fmreg_index);
        return -EFAULT;
    }
    spin_lock_irqsave(&fmdev->resp_skb_lock, flags);
    skb = fmdev->response_skb;
    fmdev->response_skb = NULL;
    spin_unlock_irqrestore(&fmdev->resp_skb_lock, flags);

    fm_evt_hdr = (void *)skb->data;
    if (fm_evt_hdr->event_id == HCI_EV_CMD_COMPLETE) /* Vendor specific command response */
    {
        cmd_complete_hdr = (struct fm_cmd_complete_hdr_sprd *) &skb->data [FM_EVT_MSG_HDR_SIZE];
        if (cmd_complete_hdr->status != 0)
        {
            pr_err("(fmdrv) %s(): Reponse status not success for 0x%02X\n",
								__func__, fmreg_index);
            kfree (skb);
            return -EFAULT;
        }

        pr_info("(fmdrv) %s(): Reponse status success for 0x%02X: %d,head_len=%d\n",
				__func__, fmreg_index, cmd_complete_hdr->status,fm_evt_hdr->len);
        /* Send reponse data to caller */
        if (reponse != NULL && reponse_len != NULL && fm_evt_hdr->len) {
            /* Skip header info and copy only response data */
			pr_info("weisonghe\n");

            skb_pull(skb, (FM_EVT_MSG_HDR_SIZE + 4));//data after status
            memcpy(reponse, skb->data, (fm_evt_hdr->len-4) );
            *reponse_len = (fm_evt_hdr->len - 4) ;//len -4 =after status
//			debugbuf=(unsigned char *)reponse;
//			pr_info("reponse=%x\n",debugbuf[0]);

        }
        else if (reponse_len != NULL && fm_evt_hdr->len == 0) {
            *reponse_len = 0;
        }
    }
    else
    {
        pr_err("(fmdrv) %s(): Unhandled event ID for 0x%02X: %d\n",
				__func__, fmreg_index, fm_evt_hdr->event_id);
    }
    kfree_skb(skb);
    return 0;
}

/* Helper function to parse the interrupt bits
* in FM_REG_FM_RDS_FLAG (0x12).
* Called locally by fmdrv_main.c
*/
int parse_inrpt_flags(struct fmdrv_ops *fmdev)
{
    struct sk_buff *skb;
    unsigned long flags;
    unsigned short fm_rds_flag;
    unsigned char response[2];

#if V4L2_FM_DEBUG
    pr_info("(fmdrv) %s()\n", __func__);
#endif

    spin_lock_irqsave(&fmdev->resp_skb_lock, flags);
    skb = fmdev->response_skb;
    fmdev->response_skb = NULL;
    spin_unlock_irqrestore(&fmdev->resp_skb_lock, flags);

    memcpy(&response, &skb->data[FM_EVT_MSG_HDR_SIZE + FM_CMD_COMPLETE_HDR_SIZE_sprd], 2);
    fm_rds_flag= (unsigned short)response[0] + ((unsigned short)response[1] << 8) ;

    if (fmdev->rx.fm_rds_flag & (FM_RDS_FLAG_SCH_FRZ_BIT|FM_RDS_FLAG_CLEAN_BIT))
    {
        fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_CLEAN_BIT;
        pr_info("(fmdrv) %s(): Clean BIT set. So no processing of the current\
            FM/RDS flag set\n", __func__);
        kfree_skb(skb);
        return 0;
    }

    pr_info("(fmdrv) %s(): Processing the interrupt flag. Flag read is 0x%x 0x%x\n",
		__func__, response[0], response[1]);
#if V4L2_FM_DEBUG
    pr_info("(fmdrv) %s(): flag register(0x%x)\n", __func__, fm_rds_flag);
#endif
    if(fm_rds_flag & (I2C_MASK_SRH_TUNE_CMPL_BIT|I2C_MASK_SRH_TUNE_FAIL_BIT))
    {
        /* remove sch_tune pending bit */
        fmdev->rx.fm_rds_flag &= ~FM_RDS_FLAG_SCH_BIT;

        if(fm_rds_flag & I2C_MASK_SRH_TUNE_FAIL_BIT)
        {
            pr_err("(fmdrv) %s(): MASK BIT : Search failure\n", __func__);
            if(fmdev->rx.curr_search_state == FM_STATE_SEEKING)
            {
                fmdev->rx.curr_search_state = FM_STATE_SEEK_ERR;
                complete(&fmdev->seektask_completion);
            }
            else if(fmdev->rx.curr_search_state == FM_STATE_TUNING)
            {
                fmdev->rx.curr_search_state = FM_STATE_TUNE_ERR;
                complete(&fmdev->maintask_completion);
            }
        }
        else
        {
            pr_info("(fmdrv) %s(): MASK BIT : Search success\n", __func__);
            if(fmdev->rx.curr_search_state == FM_STATE_SEEKING)
            {
                fmdev->rx.curr_search_state = FM_STATE_SEEK_CMPL;
                complete(&fmdev->seektask_completion);
            }
            else if(fmdev->rx.curr_search_state == FM_STATE_TUNING)
            {
                fmdev->rx.curr_search_state = FM_STATE_TUNE_CMPL;
                complete(&fmdev->maintask_completion);
            }
        }
    }
    else if(fm_rds_flag & I2C_MASK_RDS_FIFO_WLINE_BIT)
    {
        pr_info("(fmdrv) %s(): Detected WLINE interrupt; Reading RDS.\n",
								__func__);
        read_rds_data(fmdev);
    }
    kfree_skb(skb);
    return 0;
}


/*
read RDS data from sock buffer to fmdev cbuff
called by __recv_tasklet interace
*/
#if 0
int parse_rds_data(struct fmdrv_ops *fmdev)
{
	unsigned char *rds_data;
	unsigned long flags;
	unsigned char ps_buffer[1];
	unsigned char RT_buffer[64];
	unsigned char RDS_type;
	struct sk_buffer *skb;
	int ret, response_len, index=0;
#if V4L2_RDS_DEBUG
    pr_info("(fm_rds) %s\n", __func__);
#endif
	spin_lock_irqsave(&fmdev->resp_skb_lock, flags);
    skb = fmdev->response_skb;
    fmdev->response_skb = NULL;
    spin_unlock_irqrestore(&fmdev->resp_skb_lock, flags);
   // skb_pull(skb, (sizeof(struct fm_event_msg_hdr) + sizeof(struct fm_cmd_complete_hdr)));
    rds_data = skb->data;
    response_len = skb->len;
#if V4L2_RDS_DEBUG
    pr_info("(fm_rds) RDS length : %d, RDS_data=%x\n", response_len,rds_data[0]);
#endif


}



#endif


/* Helper function to parse the RDS data
* in FM_REG_FM_RDS_DATA (0x80).
* Called locally by fmdrv_main.c
*/
int brm_parse_rds_data(struct fmdrv_ops *fmdev)
{
    unsigned long flags;
    unsigned char *rds_data, tmpbuf[3];
    unsigned char type, block_index;
    tBRCM_RDS_QUALITY qlty_index;
    int ret, response_len, index=0;
    struct sk_buff *skb;
    //struct fm_event_msg_hdr *fm_evt_hdr;
    //struct fm_cmd_complete_hdr *cmd_complete_hdr;

#if V4L2_RDS_DEBUG
    pr_info("(fm_rds) %s\n", __func__);
#endif

    spin_lock_irqsave(&fmdev->resp_skb_lock, flags);
    skb = fmdev->response_skb;
    fmdev->response_skb = NULL;
    spin_unlock_irqrestore(&fmdev->resp_skb_lock, flags);
    skb_pull(skb, (sizeof(struct fm_event_msg_hdr) + sizeof(struct fm_cmd_complete_hdr)));
    rds_data = skb->data;
    response_len = skb->len;
#if V4L2_RDS_DEBUG
    pr_info("(fm_rds) RDS length : %d\n", response_len);
#endif

    /* Read RDS data */
    spin_lock_irqsave(&fmdev->rds_cbuff_lock, flags);
    while (response_len > 0)
    {
        /* Fill RDS buffer as per V4L2 specification.
     * Store control byte
     */

        type = (rds_data[0] & BRCM_RDS_GRP_TYPE_MASK);
        block_index = (type >> 4);
        if (block_index < V4L2_RDS_BLOCK_A|| block_index > V4L2_RDS_BLOCK_C_ALT)
        {
            pr_err("(fm_rds) Block sequence mismatch\n");
            block_index = V4L2_RDS_BLOCK_INVALID;
        }

        qlty_index = (tBRCM_RDS_QUALITY)((rds_data[0] & BRCM_RDS_GRP_QLTY_MASK) >> 2);

        tmpbuf[2] = (block_index & V4L2_RDS_BLOCK_MSK);    /* Offset name */
        tmpbuf[2] |= ((block_index & V4L2_RDS_BLOCK_MSK) << 3);  /* Reserved offset */

        switch(qlty_index)
        {
            case BRCM_RDS_NO_ERR:
                /* Set bits 7 and 8 to 0 to indicate no error / correction*/
#if V4L2_RDS_DEBUG
                pr_info("(fm_rds) qlty : BRCM_RDS_NO_ERR\n");
#endif
                //tmpbuf[2] &= ~(BRCM_RDS_BIT_6 | BRCM_RDS_BIT_7);

                break;

            case BRCM_RDS_2BIT_ERR:
            case BRCM_RDS_3BIT_ERR:
#if V4L2_RDS_DEBUG
                pr_info("(fm_rds) qlty : %s\n", ((qlty_index==BRCM_RDS_2BIT_ERR)?
                    "BRCM_RDS_2BIT_ERR":"BRCM_RDS_3BIT_ERR"));
#endif
                /* Set bit 7 to 1 and bit 8 to 0 indicate no error
                    but correction made*/
                tmpbuf[2] |= (BRCM_RDS_BIT_6);
                tmpbuf[2] &= ~(BRCM_RDS_BIT_7);
                break;

            case BRCM_RDS_UNRECOVER:
                pr_info("(fm_rds) qlty : BRCM_RDS_UNRECOVER for data [ 0x%x 0x%x 0x%x]\n",
                    rds_data[0], rds_data[1], rds_data[2]);
                /* Set bit 7 to 0 and bit 8 to 1 indicate error */
                tmpbuf[2] |= (BRCM_RDS_BIT_7);
                tmpbuf[2] &= ~(BRCM_RDS_BIT_6);
                break;
             default :
                pr_err("(fm_rds) Unknown quality code\n");
                tmpbuf[2] |= (BRCM_RDS_BIT_7);
                tmpbuf[2] &= ~(BRCM_RDS_BIT_6);

        }

        /* Store data byte. Swap bytes*/
        tmpbuf[0] = rds_data[2]; /* LSB of V4L2 spec block */
        tmpbuf[1] = rds_data[1]; /* MSB of V4L2 spec block */
#if V4L2_RDS_DEBUG
        pr_info("(fm_rds) Copying [ 0x%x 0x%x 0x%x] as [0x%x 0x%x 0x%x] to V4L2\n",
                    rds_data[0], rds_data[1], rds_data[2],
                    tmpbuf[0], tmpbuf[1], tmpbuf[2]);
#endif
        memcpy(&fmdev->rx.rds.cbuffer[fmdev->rx.rds.wr_index], &tmpbuf,
               FM_RDS_TUPLE_LENGTH);
        fmdev->rx.rds.wr_index =
            (fmdev->rx.rds.wr_index +
             FM_RDS_TUPLE_LENGTH) % fmdev->rx.rds.buf_size;

        /* Check for overflow & start over */
        if (fmdev->rx.rds.wr_index == fmdev->rx.rds.rd_index) {
            pr_err("(fm_rds) RDS buffer overflow\n");
            fmdev->rx.rds.wr_index = 0;
            fmdev->rx.rds.rd_index = 0;
            break;
        }

        /*Check for end of RDS tuple */
        if ((rds_data + FM_RDS_TUPLE_LENGTH)[FM_RDS_TUPLE_BYTE1] == FM_RDS_END_TUPLE_1ST_BYTE &&
            (rds_data + FM_RDS_TUPLE_LENGTH)[FM_RDS_TUPLE_BYTE2] == FM_RDS_END_TUPLE_2ND_BYTE &&
            (rds_data + FM_RDS_TUPLE_LENGTH)[FM_RDS_TUPLE_BYTE3] == FM_RDS_END_TUPLE_3RD_BYTE )
        {
            pr_err("(fm_rds) End of RDS tuple reached @ %d index\n", index);
            break;
        }
        response_len -= FM_RDS_TUPLE_LENGTH;
        rds_data += FM_RDS_TUPLE_LENGTH;
        index += FM_RDS_TUPLE_LENGTH;
    }
    spin_unlock_irqrestore(&fmdev->rds_cbuff_lock, flags);

    /* Set Tuner RDS capability bit as RDS data has been detected */
    fmdev->device_info.rxsubchans |= V4L2_TUNER_SUB_RDS;

    /* Wakeup read queue */
    if (fmdev->rx.rds.wr_index != fmdev->rx.rds.rd_index)
        wake_up_interruptible(&fmdev->rx.rds.read_queue);

#if V4L2_RDS_DEBUG
    pr_info("(fm_rds) Now reset the mask\n");
#endif
    fmdev->rx.fm_rds_mask |= I2C_MASK_RDS_FIFO_WLINE_BIT;

    ret = __fm_send_cmd(fmdev, FM_REG_FM_RDS_MSK, &fmdev->rx.fm_rds_mask,
                            2, REG_WR, NULL);
#if V4L2_RDS_DEBUG
    pr_info("(fm_rds) %s(): Write to FM_REG_FM_RDS_MSK done : %d\n",
							__func__, ret);
#endif
    kfree(skb);
    return 0;
}

/*
 * Read the FM_REG_FM_RDS_FLAG by sending a read command.
 * Called locally by fmdrv_main.c
 */
void send_read_intrp_cmd(struct fmdrv_ops *fmdev)
{
    unsigned char read_length;
    int ret;

    read_length = FM_READ_2_BYTE_DATA;
    ret = __fm_send_cmd(fmdev, FM_REG_FM_RDS_FLAG, &read_length,
                            sizeof(read_length), REG_RD, NULL);
    if(ret < 0)
    {
        pr_err("(fmdrv) %s(): Error reading FM_REG_FM_RDS_FLAG\n", __func__);
    }
    pr_info("(fmdrv) %s(): Sent read to Interrupt flag FM_REG_FM_RDS_FLAG\n",
					__func__);
}

/* Initiate a read to RDS register. Called locally by fmdrv_main.c */
int read_rds_data(struct fmdrv_ops *fmdev)
{
    unsigned char payload;
    int ret;

    payload = FM_RDS_FIFO_MAX;
#if V4L2_RDS_DEBUG
    pr_info("(fmdrv) %s(): Going to read RDS data from FM_REG_RDS_DATA!!\n",
					__func__);
#endif
    ret = __fm_send_cmd(fmdev, FM_SETRDSMODE_SUB_CMD, &payload, 1, REG_RD, NULL);
    return 0;
}

/*
 * Function to copy RDS data from the FM ring buffer
 * to the userspace buffer.
 */
int fmc_transfer_rds_from_cbuff(struct fmdrv_ops *fmdev, struct file *file,
                    char __user * buf, size_t count)
{
    unsigned int block_count;
    unsigned long flags;
    int ret;

    /* Block if no new data available */
    if (fmdev->rx.rds.wr_index == fmdev->rx.rds.rd_index) {
        if (file->f_flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        ret = wait_event_interruptible(fmdev->rx.rds.read_queue,
                    (fmdev->rx.rds.wr_index != fmdev->rx.rds.rd_index));
        if (ret) {
            pr_err("(fm_rds) %s(): Error : EINTR\n", __func__);
            return -EINTR;
        }
    }
    /* Calculate block count from byte count */

    spin_lock_irqsave(&fmdev->rds_cbuff_lock, flags);
	copy_to_user(buf, &fmdev->rx.rds.cbuffer[0],fmdev->rx.rds.buf_size);

	//fmdev->rx.rds.wr_index=0;
	fmdev->rx.rds.rd_index=fmdev->rx.rds.buf_size;


#if 0

    /* Copy RDS blocks from the internal buffer and to user buffer */
    while (block_count < count) {
        if (fmdev->rx.rds.wr_index == fmdev->rx.rds.rd_index)
            break;

        /* Always transfer complete RDS blocks */
        if (copy_to_user
            (buf, &fmdev->rx.rds.cbuffer[fmdev->rx.rds.rd_index],
             fmdev->rx.rds.buf_size))
            break;

        /* Increment and wrap the read pointer */
        fmdev->rx.rds.rd_index += FM_RDS_BLOCK_SIZE;

        /* Wrap read pointer */
        if (fmdev->rx.rds.rd_index >= fmdev->rx.rds.buf_size)
            fmdev->rx.rds.rd_index = 0;

        /* Increment counters */
        block_count++;
        buf += FM_RDS_BLOCK_SIZE;
        ret += FM_RDS_BLOCK_SIZE;
    }

#endif
    spin_unlock_irqrestore(&fmdev->rds_cbuff_lock, flags);
#if V4L2_RDS_DEBUG
    pr_info("(fm_rds) %s(): Done copying %d,wr_index=%d,rd_index=%d\n", __func__, fmdev->rx.rds.buf_size,fmdev->rx.rds.wr_index,fmdev->rx.rds.rd_index);
#endif
    return fmdev->rx.rds.buf_size;
}

/* Sets the frequency */
int fmc_set_frequency(struct fmdrv_ops *fmdev, unsigned int freq_to_set)
{
    int ret;

    switch (fmdev->curr_fmmode) {
        case FM_MODE_RX:
            ret = fm_rx_set_frequency(fmdev, freq_to_set);
            break;

        case FM_MODE_TX:
            /* Currently FM TX is not supported */

        default:
            ret = -EINVAL;
    }
    return ret;
}

/* Returns the current tuned frequency */
int fmc_get_frequency(struct fmdrv_ops *fmdev, unsigned int *cur_tuned_frq)
{
    int ret = 0;

    switch (fmdev->curr_fmmode) {
        case FM_MODE_RX:
            ret = fm_rx_get_frequency(fmdev, cur_tuned_frq);
            break;

        case FM_MODE_TX:
        /* Currently FM TX is not supported */

        default:
            ret = -EINVAL;
    }
    return ret;
}

/* Function to initiate SEEK operation */
int fmc_seek_station(struct fmdrv_ops *fmdev, unsigned char direction_upward,
                    unsigned char wrap_around)
{
    return fm_rx_seek_station(fmdev, direction_upward, wrap_around);
}

/* Returns current band index (0-Europe/US; 1-Japan) */
int fmc_get_region(struct fmdrv_ops *fmdev, unsigned char *region)
{
    *region = fmdev->rx.curr_region;
    return 0;
}

/* Set the world region */
int fmc_set_region(struct fmdrv_ops *fmdev, unsigned char region_to_set)
{
    int ret;

    switch (fmdev->curr_fmmode) {
        case FM_MODE_RX:
            if (region_to_set == fmdev->rx.curr_region)
            {
                pr_info("(fmdrv) %s(): Already region is set(%d)\n",
					__func__, region_to_set);
                return 0;
            }
            ret = fm_rx_set_region(fmdev, region_to_set);
            break;

        case FM_MODE_TX:
        /* Currently FM TX is not supported */

        default:
            ret = -EINVAL;
    }
    return ret;
}

/* Sets the audio mode */
int fmc_set_audio_mode(struct fmdrv_ops *fmdev, unsigned char audio_mode)
{
    int ret;

    switch (fmdev->curr_fmmode) {
        case FM_MODE_RX:
            ret = fm_rx_set_audio_mode(fmdev, audio_mode);
            break;

        case FM_MODE_TX:
            /* Currently FM TX is not supported */

        default:
            ret = -EINVAL;
    }
    return ret;
}

/* Sets the scan step */
int fmc_set_scan_step(struct fmdrv_ops *fmdev, unsigned char scan_step)
{
    int ret;

    switch (fmdev->curr_fmmode) {
        case FM_MODE_RX:
            ret = fm_rx_set_scan_step(fmdev, scan_step);
            break;

        case FM_MODE_TX:
            /* Currently FM TX is not supported */

        default:
            ret = -EINVAL;
    }
    return ret;
}

/*
* Resets RDS cache parameters
*/
void fmc_reset_rds_cache(struct fmdrv_ops *fmdev)
{
    fmdev->rx.rds.rds_flag = FM_RDS_DISABLE;
    fmdev->rx.rds.wr_index = 0;
    fmdev->rx.rds.rd_index = 0;
    fmdev->device_info.rxsubchans &= ~V4L2_TUNER_SUB_RDS;
}

/*
 * Turn FM ON by sending FM_ENABLE_SUB_CMD commmand
 */
int fmc_turn_fm_on (struct fmdrv_ops *fmdev, unsigned char rds_flag)
{
    int ret;
    //unsigned char payload; by wsh
	unsigned short payload;

    if (rds_flag != FM_RDS_ENABLE && rds_flag != FM_RDS_DISABLE) {
        pr_err("(fmdrv) %s(): Invalid rds option\n", __func__);
        return -EINVAL;
    }

    if (fmdev->softmute_blend_config.start_mute == 0x1) {
	payload=0x160;
	pr_info("(fmdrv) %s(): SOFT MUTE Enabled\n", __func__);
    }
    else{
	payload=0x60;
	pr_info("(fmdrv) %s(): SOFT MUTE Disabled start_mute = %d\n", __func__,fmdev->softmute_blend_config.start_mute);
    }
/* by wsh
    if (rds_flag == FM_RDS_ENABLE)
        payload = (FM_ON | FM_RDS_ON);
    else
        payload = FM_ON;
*/
    ret = fmc_send_cmd(fmdev, FM_ENABLE_SUB_CMD, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);
#if V4L2_FM_DEBUG
    pr_debug("(fmdrv) %s(): FM_ENABLE_SUB_CMD write done\n", __func__);
#endif
    /*fmdev->rx.rds.rds_flag = rds_flag;*/
    return ret;
}

/*
 * Turn off FM
 */
int fmc_turn_fm_off(struct fmdrv_ops *fmdev)
{
    int ret = -EINVAL;
    unsigned char payload;
#if 0 /* There is no chip side mute in sc2331 for FM*/
    /* Mute audio */
    payload = FM_MUTE_ON;    /* darrel issue_02 : mute on is value 1 */
    ret = fm_rx_set_mute_mode(fmdev, payload);

    FM_CHECK_SEND_CMD_STATUS(ret);

    if(ret < 0)
    {
        pr_err ("(fmdrv) %s(): FM mute off during FM Disable operation has failed\n",
									__func__);
        return ret;
    }
#endif
    /* Disable FM */
    payload = FM_OFF;

    ret = fmc_send_cmd(fmdev, FM_DISABLE_SUB_CMD, &payload, sizeof(payload),
            REG_WR, &fmdev->maintask_completion, NULL, NULL);
    FM_CHECK_SEND_CMD_STATUS(ret);

    return ret;
}

/*
 * Set FM Modes(TX, RX, OFF)
 * TX and RX modes are exclusive
 */
int fmc_set_mode(struct fmdrv_ops *fmdev, unsigned char fm_mode)
{
    int ret = 0;

    if (fm_mode >= FM_MODE_ENTRY_MAX) {
        pr_err("(fmdrv) %s(): Invalid FM mode : %d\n", __func__, fm_mode);
        ret = -EINVAL;
        return ret;
    }
    if (fmdev->curr_fmmode == fm_mode) {
        pr_info("(fmdrv) %s(): Already fm is in mode(%d)", __func__, fm_mode);
         return ret;
    }
    fmdev->curr_fmmode = fm_mode;
    return ret;
}

/*
 * Turn on FM, and other initialization to enable FM
 */
int fmc_enable (struct fmdrv_ops *fmdev, unsigned char opt)
{
    int ret;
    unsigned char rds_en_dis, rdbs_en_dis;
    unsigned char aud_ctrl;
    unsigned char read_length;
    unsigned char resp_buf [1];
    int resp_len;
	global_frequency=8750;

    if (!test_bit(FM_CORE_READY, &fmdev->flag))
    {
        pr_err("(fmdrv) %s(): FM core is not ready\n", __func__);
        return -EPERM;
    }

    fmc_set_mode (fmdev, FM_MODE_RX);

/*android:functionalityMask: bit4:RDS  bit5:RBDS bit6:AF  bit8:softmute default:352(5,6,8 bit=1)*/

    /* turn FM ON */
    rds_en_dis = (opt & (FM_RDS_BIT | FM_RBDS_BIT)) ?
                            FM_RDS_ENABLE : FM_RDS_DISABLE;

    ret = fmc_turn_fm_on (fmdev, rds_en_dis);

    if (ret < 0)
    {
        pr_err ("(fmdrv) %s(): FM turn on failed\n", __func__);
        return ret;
    }
    fmdev->rx.fm_func_mask = opt;
    /* wait for 50 ms before sending any more commands */
    mdelay (50);

    /* wrire rds control */
    rdbs_en_dis = (opt & FM_RBDS_BIT) ?
            FM_RDBS_ENABLE : FM_RDBS_DISABLE;
    ret = fm_rx_set_rds_system (fmdev, rdbs_en_dis);

    if (ret < 0)
    {
        pr_err ("(fmdrv) %s(): set rds mode failed\n", __func__);
        return ret;
    }
    ret = fm_rx_set_region( fmdev,(opt & FM_REGION_MASK));

    if (ret < 0)
    {
        pr_err ("(fmdrv) %s(): set region has failed\n", __func__);
        return ret;
    }

	/* fmdev->rx.curr_rssi_threshold = DEF_V4L2_FM_SIGNAL_STRENGTH;*/

    /* Read PCM Route settings */
	
/*********************don't need, beacause marlin auto check pcm, not depend on AP CMD ***

    read_length = FM_READ_1_BYTE_DATA;
    ret = fmc_send_cmd(fmdev, FM_REG_PCM_ROUTE, &read_length, sizeof(read_length), REG_RD,
                    &fmdev->maintask_completion, &resp_buf, &resp_len);
    FM_CHECK_SEND_CMD_STATUS(ret);
    fmdev->rx.pcm_reg = resp_buf[0];
    pr_debug ("(fmdrv) %s(): pcm_reg value %d\n", __func__, fmdev->rx.pcm_reg);

    // darrel : fm enable with mute state. added FM_MANUAL_MUTE

    aud_ctrl = (unsigned short)(FM_AUDIO_DAC_ON | \
                    FM_RF_MUTE | FM_Z_MUTE_LEFT_OFF | FM_Z_MUTE_RITE_OFF | \
		    FM_MANUAL_MUTE | \
                    fmdev->rx.region.deemphasis);

    ret = fm_rx_set_audio_ctrl(fmdev, aud_ctrl);

    fmdev->rx.curr_rssi_threshold = DEF_V4L2_FM_SIGNAL_STRENGTH;

    // Set world region 
    pr_debug("(fmdrv) %s(): FM Set world region option : %d\n",
				__func__, DEF_V4L2_FM_WORLD_REGION);
    ret = fmc_set_region(fmdev, DEF_V4L2_FM_WORLD_REGION);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Unable to set World region\n", __func__);
        return ret;
    }
    fmdev->rx.curr_region = DEF_V4L2_FM_WORLD_REGION;
	
*******************************************************************************************/
	
    /* Set Scan Step */
#if(defined(DEF_V4L2_FM_WORLD_REGION) && DEF_V4L2_FM_WORLD_REGION == FM_REGION_NA)
    fmdev->rx.sch_step = FM_STEP_200KHZ;
#else
    fmdev->rx.sch_step = FM_STEP_100KHZ;
#endif
    pr_debug("(fmdrv) %s(): FM Set Scan Step : 0x%x\n", __func__, fmdev->rx.sch_step);
    ret = fmc_set_scan_step(fmdev, fmdev->rx.sch_step);
    if (ret < 0) {
        pr_err("(fmdrv) %s(): Unable to set scan step\n", __func__);
        return ret;
    }

    return ret;
}

/*
* Returns current FM mode (TX, RX, OFF) */
int fmc_get_mode(struct fmdrv_ops *fmdev, unsigned char *fmmode)
{
    if (!test_bit(FM_CORE_READY, &fmdev->flag)) {
        pr_err("(fmdrv) %s(): FM core is not ready\n", __func__);
        return -EPERM;
    }
    if (fmmode == NULL) {
        pr_err("(fmdrv) %s(): Invalid memory\n", __func__);
        return -ENOMEM;
    }

    *fmmode = fmdev->curr_fmmode;
    return 0;
}

/*
* Called by LDisc layer when FM packet is available. The pointer to
* this function is registered to LDisc during brcm_sh_ldisc_register() call.*/
static long fm_st_receive(void *arg, struct sk_buff *skb)
{
    struct fmdrv_ops *fmdev;
#if V4L2_FM_DEBUG
    int len;
#endif
    __u8 pkt_type = 0x08;

    fmdev = (struct fmdrv_ops *)arg;
#if V4L2_FM_DEBUG
    pr_debug("(fmdrv): %s()\n", __func__);
#endif
    if (skb == NULL) {
        pr_err("(fmdrv) %s(): Invalid SKB received from LDisp\n", __func__);
        return -EFAULT;
    }
    if (skb->cb[0] != FM_PKT_LOGICAL_CHAN_NUMBER) {
        pr_err("(fmdrv) %s(): Received SKB (0x%p) is not FM Channel 8 pkt\n",
						__func__, skb);
        return -EINVAL;
    }
#if V4L2_FM_DEBUG
        for (len = 0; ((skb) && (len < skb->len)); len++)
            pr_info(">> 0x%02x ", skb->data[len]);
#endif

    memcpy(skb_push(skb, 1), &pkt_type, 1);
    skb_queue_tail(&fmdev->rx_q, skb);
    pr_info("\n(fmdrv) %s(): fm_st_receive: schedule recv tasklet\n",
							__func__);
    tasklet_schedule(&fmdev->rx_task);

    return 0;
}

/*
 * This function will be called from FM V4L2 open function.
 * Register with shared ldisc driver and initialize driver data.
 */
int fmc_prepare(struct fmdrv_ops *fmdev)
{
    static struct sh_proto_s fm_st_proto;
    int ret = 0;

    if (test_bit(FM_CORE_READY, &fmdev->flag)) {
        pr_info("(fmdrv) %s(): FM Core is already up\n", __func__);
        return ret;
    }

    memset(&fm_st_proto, 0, sizeof(fm_st_proto));
    fm_st_proto.type = PROTO_SH_FM;
    fm_st_proto.recv = fm_st_receive;
    fm_st_proto.match_packet = NULL;
    fm_st_proto.write = NULL; /* shared ldisc driver will fill write pointer */
    fm_st_proto.priv_data = fmdev;

    /* Register with the shared line discipline */
    ret = hci_ldisc_register(&fm_st_proto);
    if (ret == -1) {
        pr_err("(fmdrv) %s(): hci_ldisc_register failed %d\n",
							__func__, ret);
        ret = -EAGAIN;
        return ret;
    }

    if (fm_st_proto.write != NULL) {
        g_bcm_write = fm_st_proto.write;
    }
    else {
        pr_err("(fmdrv) %s(): Failed to get shared ldisc write func pointer\n", __func__);
        ret = hci_ldisc_unregister(PROTO_SH_FM);
        if (ret < 0)
            pr_err("(fmdrv) %s(): hci_ldisc_unregister failed %d\n", __func__, ret);
            ret = -EAGAIN;
            return ret;
    }

    spin_lock_init(&fmdev->resp_skb_lock);

    /* Initialize TX queue and TX tasklet */
    skb_queue_head_init(&fmdev->tx_q);
    tasklet_init(&fmdev->tx_task, __send_tasklet, (unsigned long)fmdev);

    /* Initialize RX Queue and RX tasklet */
    skb_queue_head_init(&fmdev->rx_q);
    tasklet_init(&fmdev->rx_task, __recv_tasklet, (unsigned long)fmdev);

    atomic_set(&fmdev->tx_cnt, 1);
    fmdev->response_completion = NULL;

    /* Do all the broadcom FM hardware specific initialization */
    fmdev->rx.curr_mute_mode = FM_MUTE_OFF;
    fmdev->rx.rds.rds_flag = FM_RDS_DISABLE;
    fmdev->rx.curr_region = DEF_V4L2_FM_WORLD_REGION;
    memcpy(&fmdev->rx.region, &region_configs[fmdev->rx.curr_region],
                            sizeof(struct region_info));
    fmdev->rx.curr_freq = fmdev->rx.region.low_bound;
    fmdev->rx.rds_mode = FM_RDS_SYSTEM_NONE;
    fmdev->rx.curr_snr_threshold = FM_RX_SNR_MAX + 1;
    fmdev->rx.curr_cos_threshold = FM_RX_COS_DEFAULT;
    fmdev->rx.curr_sch_mode = FM_SCAN_NONE;
    fmdev->rx.curr_noise_floor = FM_NFE_DEFAILT;
    fmdev->rx.curr_volume = FM_RX_VOLUME_MAX;
    fmdev->rx.audio_mode = FM_AUTO_MODE;
    fmdev->rx.audio_path = FM_AUDIO_NONE;
    fmdev->rx.sch_step = FM_STEP_NONE;
    fmdev->device_info.capabilities = V4L2_CAP_HW_FREQ_SEEK | V4L2_CAP_TUNER |
                                V4L2_CAP_RADIO | V4L2_CAP_MODULATOR |
                                V4L2_CAP_AUDIO | V4L2_CAP_READWRITE | V4L2_CAP_RDS_CAPTURE;
    fmdev->device_info.type = V4L2_TUNER_RADIO;
    fmdev->device_info.rxsubchans = V4L2_TUNER_SUB_MONO | V4L2_TUNER_SUB_STEREO;
    fmdev->device_info.tuner_capability =V4L2_TUNER_CAP_STEREO | V4L2_TUNER_CAP_LOW | V4L2_TUNER_CAP_RDS;

    /* RDS initialization */
    fmc_reset_rds_cache(fmdev);
    init_waitqueue_head(&fmdev->rx.rds.read_queue);

    set_bit(FM_CORE_READY, &fmdev->flag);
    return ret;
}

/* This function will be called from FM V4L2 release function.
 * Unregister from line discipline driver.
 */
int fmc_release(struct fmdrv_ops *fmdev)
{
    int ret;
    pr_info("(fmdrv) %s\n", __func__);

    if (!test_bit(FM_CORE_READY, &fmdev->flag)) {
        pr_info("(fmdrv) %s(): FM Core is already down\n", __func__);
        return 0;
    }

    ret = hci_ldisc_unregister(PROTO_SH_FM);
    if (ret < 0)
        pr_err("(fmdrv) %s(): Failed to de-register FM from HCI LDisc - %d\n",
								__func__, ret);
    else
        pr_info("(fmdrv) %s(): Successfully unregistered from  HCI LDisc\n",
								__func__);

    /* Sevice pending read */
    wake_up_interruptible(&fmdev->rx.rds.read_queue);

    tasklet_kill(&fmdev->tx_task);
    tasklet_kill(&fmdev->rx_task);

    skb_queue_purge(&fmdev->tx_q);
    skb_queue_purge(&fmdev->rx_q);

    fmdev->response_completion = NULL;
    fmdev->rx.curr_freq = 0;

    clear_bit(FM_CORE_READY, &fmdev->flag);
    return ret;
}

/* Module init function. Ask FM V4L module to register video device.
 * Allocate memory for FM driver context
 */
static int __init fm_drv_init(void)
{
    struct fmdrv_ops *fmdev = NULL;
    int ret = -ENOMEM;

    pr_info("(fmdrv) %s(): FM driver version %s\n", __func__, FM_DRV_VERSION);

    fmdev = kzalloc(sizeof(struct fmdrv_ops), GFP_KERNEL);
    if (NULL == fmdev) {
        pr_err("(fmdrv) %s(): Can't allocate operation structure memory\n",
								__func__);
        return ret;
    }

    fmdev->rx.rds.buf_size = default_rds_buf * FM_RDS_TUPLE_LENGTH;
    /* Allocate memory for RDS ring buffer */
    fmdev->rx.rds.cbuffer = kzalloc(fmdev->rx.rds.buf_size, GFP_KERNEL);
    if (fmdev->rx.rds.cbuffer == NULL) {
        pr_err("(fmdrv) %s(): Can't allocate rds ring buffer\n", __func__);
        kfree(fmdev);
        return -ENOMEM;
    }

    ret = fm_v4l2_init_video_device(fmdev, radio_nr);
    if (ret < 0)
    {
        kfree(fmdev);
        return ret;
    }

    fmdev->curr_fmmode = FM_MODE_OFF;
    return 0;
}

/* Module exit function. Ask FM V4L module to unregister video device */
static void __exit fm_drv_exit(void)
{
    struct fmdrv_ops *fmdev = NULL;
    pr_info("(fmdrv): %s\n", __func__);

    fmdev = fm_v4l2_deinit_video_device();
    if (fmdev != NULL) {
        kfree(fmdev);
    }
}

module_init(fm_drv_init);
module_exit(fm_drv_exit);

/* ------------- Module Info ------------- */
MODULE_AUTHOR("Satyajit Roy <roys@broadcom.com>, Syed Ibrahim Moosa <syedibrahim.moosa@broadcom.com>");
MODULE_DESCRIPTION("FM Driver for Connectivity chip of Broadcom Corporation. "
           FM_DRV_VERSION);
MODULE_VERSION(FM_DRV_VERSION);
MODULE_LICENSE("GPL");
