/*
 *
 *  Bluetooth HCI UART driver
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/poll.h>

#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/signal.h>
#include <linux/ioctl.h>
#include <linux/skbuff.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include "hci_uart_bcm.h"
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
#include <linux/fm.h> // add for fm
#endif

#define VERSION "2.2"
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
#define PROTO_ENTRY(type, name)	name
const unsigned char *protocol_strngs[] = {
    PROTO_ENTRY(ST_BT, "Bluetooth"),
    PROTO_ENTRY(ST_FM, "FM"),
    PROTO_ENTRY(ST_GPS, "GPS"),
};

/*******************************************************************************
**  Local type definitions
*******************************************************************************/
struct hci_uart *g_hu = NULL;
spinlock_t  reg_lock;
static int is_print_reg_error = 1;
static unsigned long jiffi1, jiffi2;

static struct hci_st *hst;
#define BT_REGISTER_TIMEOUT   msecs_to_jiffies(6000)	/* 6 sec */
/*******************************************************************************
**  Function forward-declarations and Function callback declarations
*******************************************************************************/
static void hci_uart_tty_flush_buffer(struct tty_struct *tty);
#endif
static struct hci_uart_proto *hup[HCI_UART_MAX_PROTO];

int hci_uart_register_proto(struct hci_uart_proto *p)
{
	if (p->id >= HCI_UART_MAX_PROTO)
		return -EINVAL;

	if (hup[p->id])
		return -EEXIST;

	hup[p->id] = p;

	return 0;
}

int hci_uart_unregister_proto(struct hci_uart_proto *p)
{
	if (p->id >= HCI_UART_MAX_PROTO)
		return -EINVAL;

	if (!hup[p->id])
		return -EINVAL;

	hup[p->id] = NULL;

	return 0;
}
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
// add for V4L2
void hci_uart_route_frame(enum proto_type protoid, struct hci_uart *hu,
                    struct sk_buff *skb)
{
    int err;

    if (protoid == PROTO_SH_FM)
        BT_INFO(" %s(prot:%d) ", __func__, protoid);
    else
        BT_DBG(" %s(prot:%d) ", __func__, protoid);

    if (unlikely
            (hu == NULL || skb == NULL
                || hu->list[protoid] == NULL))
    {
        BT_ERR("protocol %d not registered, no data to send?",
                            protoid);
        if (hu != NULL && skb != NULL)
            kfree_skb(skb);

        return;
    }
    /* this cannot fail
    * this shouldn't take long
    * - should be just skb_queue_tail for the
    *   protocol stack driver
    */
    if (likely(hu->list[protoid]->recv != NULL))
    {
	err = hu->list[protoid]->recv(hu->list[protoid]->priv_data, skb);

	if (unlikely(err != 0)) {
		BT_ERR(" proto stack %d's ->recv failed", protoid);

		if (protoid != PROTO_SH_BT)
			kfree_skb(skb);

            return;
        }
    }
    else
    {
        BT_ERR(" proto stack %d's ->recv null", protoid);
        kfree_skb(skb);
    }
    return;
}
#endif
static struct hci_uart_proto *hci_uart_get_proto(unsigned int id)
{
	if (id >= HCI_UART_MAX_PROTO)
		return NULL;

	return hup[id];
}

static inline void hci_uart_tx_complete(struct hci_uart *hu, int pkt_type)
{
#if !defined(CONFIG_RADIO_BCM4343S) && !defined(CONFIG_RADIO_SC2331)
	struct hci_dev *hdev = hu->hdev;
#endif
   /* Update HCI stat counters */
   switch (pkt_type)
   {
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
		case HCI_COMMAND_PKT:
			BT_DBG("HCI command packet txed");
			break;

		case HCI_ACLDATA_PKT:
			BT_DBG("HCI ACL DATA packet txed");
			break;

		case HCI_SCODATA_PKT:
			BT_DBG("HCI SCO DATA packet txed");
			break;
#else
		case HCI_COMMAND_PKT:
			hdev->stat.cmd_tx++;
			break;

		case HCI_ACLDATA_PKT:
			hdev->stat.acl_tx++;
			break;

		case HCI_SCODATA_PKT:
			hdev->stat.sco_tx++;
			break;
#endif
	}
}

static inline struct sk_buff *hci_uart_dequeue(struct hci_uart *hu)
{
	struct sk_buff *skb = hu->tx_skb;

	if (!skb)
		skb = hu->proto->dequeue(hu);
	else
		hu->tx_skb = NULL;

	return skb;
}

int hci_uart_tx_wakeup(struct hci_uart *hu)
{
	if (test_and_set_bit(HCI_UART_SENDING, &hu->tx_state)) {
		set_bit(HCI_UART_TX_WAKEUP, &hu->tx_state);
		return 0;
	}

	BT_DBG("");

	schedule_work(&hu->write_work);

	return 0;
}

static void hci_uart_write_work(struct work_struct *work)
{
	struct hci_uart *hu = container_of(work, struct hci_uart, write_work);
	struct tty_struct *tty = hu->tty;
	struct hci_dev *hdev = hu->hdev;
	struct sk_buff *skb;

	/* REVISIT: should we cope with bad skbs or ->write() returning
	 * and error value ?
	 */

restart:
	clear_bit(HCI_UART_TX_WAKEUP, &hu->tx_state);

	while ((skb = hci_uart_dequeue(hu))) {
		int len;

		set_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);

      /* dump packet */
#if 0
      for (i = 0; i < skb->len; i++)
      {
          BT_ERR ("%x ", skb->data[i]);
      }
      BT_ERR ("\n");
#endif

		len = tty->ops->write(tty, skb->data, skb->len);
		hdev->stat.byte_tx += len;

		skb_pull(skb, len);
		if (skb->len) {
			hu->tx_skb = skb;
			break;
		}

		hci_uart_tx_complete(hu, bt_cb(skb)->pkt_type);
		kfree_skb(skb);
	}

	if (test_bit(HCI_UART_TX_WAKEUP, &hu->tx_state))
		goto restart;

	clear_bit(HCI_UART_SENDING, &hu->tx_state);
}

static void hci_uart_init_work(struct work_struct *work)
{
	struct hci_uart *hu = container_of(work, struct hci_uart, init_ready);
	int err;

	if (!test_and_clear_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return;

	err = hci_register_dev(hu->hdev);
	if (err < 0) {
		BT_ERR("Can't register HCI device");
		hci_free_dev(hu->hdev);
		hu->hdev = NULL;
		hu->proto->close(hu);
	}

	set_bit(HCI_UART_REGISTERED, &hu->flags);
}

int hci_uart_init_ready(struct hci_uart *hu)
{
	if (!test_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return -EALREADY;

	schedule_work(&hu->init_ready);

	return 0;
}

#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
/*******************************************************************************
**
** Function - hci_sh_ldisc_register()
**
** Description - Register protocol
**              called from upper layer protocol stack drivers (BT or FM)
**
** Returns - 0 if success; errno otherwise
**
*******************************************************************************/
long hci_ldisc_register(struct sh_proto_s *new_proto)
{
    long err = 0;
    unsigned long flags, diff;
    if(new_proto->type != 0)
    {
        BT_INFO("%s(%d) ", __func__, new_proto->type);
    }
    spin_lock_irqsave(&reg_lock, flags);
    if (g_hu == NULL || g_hu->priv == NULL ||
                new_proto == NULL || new_proto->recv == NULL)
    {
		spin_unlock_irqrestore(&reg_lock, flags);
        if (is_print_reg_error)
        {
            BT_INFO("%s(%d) ", __func__, new_proto->type);
            BT_ERR("g_hu/g_hu priv/new_proto/recv or reg_complete_cb not ready");
            jiffi1 = jiffies;
            is_print_reg_error = 0;
        }
        else
        {
            jiffi2 = jiffies;
            diff = (long)jiffi2 - (long)jiffi1;
            if ( ((diff *1000)/HZ) >= 1000)
                is_print_reg_error = 1;
        }
        return -1;
    }

    if (new_proto->type < PROTO_SH_BT || new_proto->type >= PROTO_SH_MAX)
    {
		spin_unlock_irqrestore(&reg_lock, flags);
        BT_ERR("protocol %d not supported", new_proto->type);
        return -EPROTONOSUPPORT;
    }

    if (g_hu->list[new_proto->type] != NULL)
    {
		spin_unlock_irqrestore(&reg_lock, flags);
        BT_ERR("protocol %d already registered", new_proto->type);
        return -EALREADY;
    }

    g_hu->list[new_proto->type] = new_proto;
    g_hu->list[new_proto->type]->priv_data = new_proto->priv_data;
    g_hu->protos_registered++;
    new_proto->write = hci_ldisc_write;
	spin_unlock_irqrestore(&reg_lock, flags);

    BT_INFO("done %s(%d) ", __func__, new_proto->type);
    return err;
}
EXPORT_SYMBOL(hci_ldisc_register);

/*******************************************************************************
**
** Function - hci_sh_ldisc_unregister()
**
** Description - UnRegister protocol
**              called from upper layer protocol stack drivers (BT or FM)
**
** Returns - 0 if success; errno otherwise
**
*******************************************************************************/
long hci_ldisc_unregister(enum proto_type type)
{
    long err = 0;
    unsigned long flags;

    BT_INFO("%s: %d ", __func__, type);

    if (type < PROTO_SH_BT || type >= PROTO_SH_MAX)
    {
        BT_ERR(" protocol %d not supported", type);
        return -EPROTONOSUPPORT;
    }

    spin_lock_irqsave(&reg_lock, flags);

     if (g_hu == NULL || g_hu->list[type] == NULL)
    {
		spin_unlock_irqrestore(&reg_lock, flags);
        BT_ERR(" protocol %d not registered", type);
        return -EPROTONOSUPPORT;
    }

    g_hu->protos_registered--;
    g_hu->list[type] = NULL;

    if (g_hu->tty)
        hci_uart_tty_flush_buffer(g_hu->tty);

    spin_unlock_irqrestore(&reg_lock, flags);

    return err;
}
EXPORT_SYMBOL(hci_ldisc_unregister);


/*******************************************************************************
**
** Function - brcm_sh_ldisc_write()
**
** Description - Function to write to the shared line discipline driver
**              called from upper layer protocol stack drivers (BT or FM)
**              via the write function pointer
**
** Returns - 0 if success; errno otherwise
**
*******************************************************************************/
long hci_ldisc_write(struct sk_buff *skb)
{
    enum proto_type protoid = PROTO_SH_MAX;
    long len;

    struct hci_uart *hu = g_hu;

    BT_DBG("%s", __func__);

    if (unlikely(skb == NULL))
    {
        BT_ERR("data unavailable to perform write");
        return -1;
    }

    if (unlikely(hu == NULL || hu->tty == NULL))
    {
        BT_ERR("tty unavailable to perform write");
        return -1;
    }

    switch (sh_ldisc_cb(skb)->pkt_type)
    {
        case HCI_COMMAND_PKT:
        case HCI_ACLDATA_PKT:
        case HCI_SCODATA_PKT:
            protoid = PROTO_SH_BT;
            break;
        case FM_CH8_PKT:
            protoid = PROTO_SH_FM;
            BT_INFO("%s: FM_CH8_PKT", __func__);
            break;
    }

    if (unlikely(hu->list[protoid] == NULL))
    {
        BT_ERR(" protocol %d not registered, and writing? ",
                            protoid);
        return -1;
    }

    BT_DBG("%d to be written, type %d", skb->len, sh_ldisc_cb(skb)->pkt_type );
    len = skb->len;

    hu->proto->enqueue(hu, skb);

    hci_uart_tx_wakeup(hu);

    /* return number of bytes written */
    return len;
}

static void hci_uart_tty_flush_buffer(struct tty_struct *tty)
{
    struct hci_uart *hu = (void *)tty->disc_data;
    unsigned long flags;
    BT_DBG("%s", __func__);

    if (!hu || tty != hu->tty)
        return;

    if (!test_bit(HCI_UART_PROTO_SET, &hu->flags))
        return;

    spin_lock_irqsave(&hu->rx_lock, flags);
    hu->proto->flush(hu);
    spin_unlock(&hu->rx_lock);

    if(tty->ldisc->ops->flush_buffer)
        tty->ldisc->ops->flush_buffer(tty);

    return;
}

static void hci_st_registration_completion_cb(void *priv_data, char data)
{
    struct hci_st *lhst = (struct hci_st *)priv_data;
    BT_DBG("%s", __func__);

    /* hci_st_open() function needs value of 'data' to know
    * the registration status(success/fail),So have a back
    * up of it.
    */
    lhst->streg_cbdata = data;

    /* Got a feedback from ST for BT driver registration
    * request.Wackup hci_st_open() function to continue
    * it's open operation.
    */
    complete(&lhst->wait_for_btdrv_reg_completion);

}

/* Called by Shared Transport layer when receive data is
 * available */
static long hci_st_receive(void *priv_data, struct sk_buff *skb)
{
    int err;
    int len;
    struct hci_st *lhst = (struct hci_st *)priv_data;

    BT_DBG("%s", __func__);

    err = 0;
    len = 0;

    if (skb == NULL) {
        BT_ERR("Invalid SKB received from ST");
        return -EFAULT;
    }
    if (!lhst) {
        kfree_skb(skb);
        BT_ERR("Invalid hci_st memory,freeing SKB");
        return -EFAULT;
    }
    if (!test_bit(BT_DRV_RUNNING, &lhst->flags)) {
        kfree_skb(skb);
        BT_ERR("Device is not running,freeing SKB");
        return -EINVAL;
    }

    len = skb->len;
    skb->dev = (struct net_device *)lhst->hdev;

    /* Forward skb to HCI CORE layer */
    err = hci_recv_frame(lhst->hdev, skb);
    if (err) {
        BT_ERR("Unable to push skb to HCI CORE(%d)",
                                                    err);
        return err;
    }
    lhst->hdev->stat.byte_rx += len;

    return 0;
}
#endif
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
/* ------- Interface to HCI layer ------ */
/* Initialize device */
static int hci_uart_open(struct hci_dev *hdev)
{
   static struct sh_proto_s hci_st_proto;
   unsigned long timeleft;
   unsigned long diff;

   int err;

   err = 0;

   BT_DBG("%s %p", hdev->name, hdev);

    /* Already registered with ST ? */
    if (test_bit(BT_ST_REGISTERED, &hst->flags)) {
        BT_ERR("Registered with ST already,open called again?");
        return 0;
    }

    /* Populate BT driver info required by ST */
    memset(&hci_st_proto, 0, sizeof(hci_st_proto));

    /* BT driver ID */
    hci_st_proto.type = PROTO_SH_BT;

    /* Receive function which called from ST */
    hci_st_proto.recv = hci_st_receive;

    /* Packet match function may used in future */
    hci_st_proto.match_packet = NULL;

    /* Callback to be called when registration is pending */
    hci_st_proto.reg_complete_cb = hci_st_registration_completion_cb;

    /* This is write function pointer of ST. BT driver will make use of this
    * for sending any packets to chip. ST will assign and give to us, so
    * make it as NULL */
    hci_st_proto.write = NULL;

    /* send in the hst to be received at registration complete callback
    * and during st's receive
    */
    hci_st_proto.priv_data = hst;

    /* Register with ST layer */
    err = hci_ldisc_register(&hci_st_proto);
    if (err == -EINPROGRESS) {
        /* Prepare wait-for-completion handler data structures.
        * Needed to syncronize this and st_registration_completion_cb()
        * functions.
        */
        init_completion(&hst->wait_for_btdrv_reg_completion);

        /* Reset ST registration callback status flag , this value
        * will be updated in hci_st_registration_completion_cb()
        * function whenever it called from ST driver.
        */
        hst->streg_cbdata = -EINPROGRESS;

        /* ST is busy with other protocol registration(may be busy with
        * firmware download).So,Wait till the registration callback
        * (passed as a argument to st_register() function) getting
        * called from ST.
        */
        BT_ERR(" %s waiting for reg completion signal from ST",
                                                            __func__);

        timeleft =
                wait_for_completion_timeout
                (&hst->wait_for_btdrv_reg_completion,
                            msecs_to_jiffies(BT_REGISTER_TIMEOUT));
        if (!timeleft) {
            BT_ERR("Timeout(%ld sec),didn't get reg"
                                            "completion signal from ST",
                                                BT_REGISTER_TIMEOUT / 1000);
            return -ETIMEDOUT;
        }

        /* Is ST registration callback called with ERROR value? */
        if (hst->streg_cbdata != 0) {
            BT_ERR("ST reg completion CB called with invalid"
            "status %d", hst->streg_cbdata);
            return -EAGAIN;
        }
        err = 0;
    } else if (err == -1) {
        if (is_print_reg_error)
        {
            BT_ERR("st_register failed %d", err);
            jiffi1 = jiffies;
            is_print_reg_error = 0;
        }
        else
        {
            jiffi2 = jiffies;
            diff = (long)jiffi2 - (long)jiffi1;
            if ( ((diff *1000)/HZ) >= 1000)
                is_print_reg_error = 1;
        }
        return -EAGAIN;
    }

    /* Do we have proper ST write function? */
    if (hci_st_proto.write != NULL) {
        /* We need this pointer for sending any Bluetooth pkts */
        hst->st_write = hci_st_proto.write;
    } else {
        BT_ERR("failed to get ST write func pointer");

        /* Undo registration with ST */
        err = hci_ldisc_unregister(PROTO_SH_BT);
        if (err < 0)
            BT_ERR("st_unregister failed %d", err);

        hst->st_write = NULL;
        return -EAGAIN;
    }

	/* BEGIN TIZEN_Bluetooth */
	/* FIXME: in order to wait enough until uart init complete,
	   the below routine is added.
	*/

	msleep(100);
	/* END TIZEN_Bluetooth */


    /* Registration with ST layer is completed successfully,
    * now chip is ready to accept commands from HCI CORE.
    * Mark HCI Device flag as RUNNING
    */
    set_bit(HCI_RUNNING, &hdev->flags);

    /* Registration with ST successful */
    set_bit(BT_ST_REGISTERED, &hst->flags);

    return err;
}
#else
/* ------- Interface to HCI layer ------ */
/* Initialize device */
static int hci_uart_open(struct hci_dev *hdev)
{
	BT_DBG("%s %p", hdev->name, hdev);

	/* Nothing to do for UART driver */

	set_bit(HCI_RUNNING, &hdev->flags);

	return 0;
}
#endif

#if !defined(CONFIG_RADIO_BCM4343S) && !defined(CONFIG_RADIO_SC2331)
/* Reset device */
static int hci_uart_flush(struct hci_dev *hdev)
{
	struct hci_uart *hu  = hci_get_drvdata(hdev);
	struct tty_struct *tty = hu->tty;

	BT_DBG("hdev %p tty %p", hdev, tty);

	if (hu->tx_skb) {
		kfree_skb(hu->tx_skb); hu->tx_skb = NULL;
	}

	/* Flush any pending characters in the driver and discipline. */
	tty_ldisc_flush(tty);
	tty_driver_flush_buffer(tty);

	if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
		hu->proto->flush(hu);

	return 0;
}
#endif

#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
/* Close device */
static int hci_uart_close(struct hci_dev *hdev)
{
    int err;

    BT_DBG("hdev %p", hdev);

    err = 0;

    /* Unregister from ST layer */
    if (test_and_clear_bit(BT_ST_REGISTERED, &hst->flags)) {
        err = hci_ldisc_unregister(PROTO_SH_BT);
        if (err != 0) {
            BT_ERR("st_unregister failed %d", err);
            return -EBUSY;
        }
    }

    hst->st_write = NULL;

    /* ST layer would have moved chip to inactive state.
    * So,clear HCI device RUNNING flag.
    */
    if (!test_and_clear_bit(HCI_RUNNING, &hdev->flags)) {
        return 0;
    }
    return err;

}

/* Increments HCI counters based on pocket ID (cmd,acl,sco) */
static inline void hci_st_tx_complete(struct hci_st *hst, int pkt_type)
{
    struct hci_dev *hdev;

    hdev = hst->hdev;

    /* Update HCI stat counters */
    switch (pkt_type) {
        case HCI_COMMAND_PKT:
            hdev->stat.cmd_tx++;
            break;

        case HCI_ACLDATA_PKT:
            hdev->stat.acl_tx++;
            break;

        case HCI_SCODATA_PKT:
            hdev->stat.cmd_tx++;
            break;
    }

}


/* Send frames from HCI layer */
static int hci_uart_send_frame(struct hci_dev *hdev, struct sk_buff *skb)
{
    struct hci_st *hst;
    long len;

    if (skb == NULL) {
        BT_ERR("Invalid skb received from HCI CORE");
        return -ENOMEM;
    }

    if (!hdev) {
        BT_ERR("SKB received for invalid HCI Device (hdev=NULL)");
        return -ENODEV;
    }
    if (!test_bit(HCI_RUNNING, &hdev->flags)) {
        BT_ERR("Device is not running");
        return -EBUSY;
    }

    hst = hci_get_drvdata(hdev);

    /* Prepend skb with frame type */
    memcpy(skb_push(skb, 1), &bt_cb(skb)->pkt_type, 1);

    BT_DBG(" %s: type %d len %d", hdev->name, bt_cb(skb)->pkt_type,
                                                skb->len);

    /* Insert skb to shared transport layer's transmit queue.
    * Freeing skb memory is taken care in shared transport layer,
    * so don't free skb memory here.
    */
    if (!hst->st_write) {
        kfree_skb(skb);
        BT_ERR(" Can't write to ST, st_write null?");
        return -EAGAIN;
    }
    len = hst->st_write(skb);
    if (len < 0) {
        /* Something went wrong in st write , free skb memory */
        kfree_skb(skb);
        BT_ERR(" ST write failed (%ld)", len);
        return -EAGAIN;
    }

    /* ST accepted our skb. So, Go ahead and do rest */
    hdev->stat.byte_tx += len;
    hci_st_tx_complete(hst, bt_cb(skb)->pkt_type);

    return 0;

}
#else
/* Close device */
static int hci_uart_close(struct hci_dev *hdev)
{
	BT_DBG("hdev %p", hdev);

	if (!test_and_clear_bit(HCI_RUNNING, &hdev->flags))
		return 0;

	hci_uart_flush(hdev);
	hdev->flush = NULL;
	return 0;
}

/* Send frames from HCI layer */
static int hci_uart_send_frame(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_uart *hu = hci_get_drvdata(hdev);

	if (!test_bit(HCI_RUNNING, &hdev->flags))
		return -EBUSY;

	BT_DBG("%s: type %d len %d", hdev->name, bt_cb(skb)->pkt_type, skb->len);

	hu->proto->enqueue(hu, skb);

	hci_uart_tx_wakeup(hu);

	return 0;
}

#endif
/* ------ LDISC part ------ */
/* hci_uart_tty_open
 *
 *     Called when line discipline changed to HCI_UART.
 *
 * Arguments:
 *     tty    pointer to tty info structure
 * Return Value:
 *     0 if success, otherwise error code
 */
static int hci_uart_tty_open(struct tty_struct *tty)
{
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
   struct hci_uart *hu = (void *) tty->disc_data;
   unsigned long flags;
   BT_INFO("tty open %p", tty);

   if (hu)
       return -EEXIST;
#else
    struct hci_uart *hu;
	BT_DBG("tty %p", tty);
#endif
	/* Error if the tty has no write op instead of leaving an exploitable
	   hole */
	if (tty->ops->write == NULL)
		return -EOPNOTSUPP;

	hu = kzalloc(sizeof(struct hci_uart), GFP_KERNEL);
	if (!hu) {
		BT_ERR("Can't allocate control structure");
		return -ENFILE;
	}

	tty->disc_data = hu;
	hu->tty = tty;
	tty->receive_room = 65536;
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
   spin_lock_irqsave(&reg_lock, flags);
   g_hu = hu;
   spin_unlock_irqrestore(&reg_lock, flags);
#endif
	INIT_WORK(&hu->init_ready, hci_uart_init_work);
	INIT_WORK(&hu->write_work, hci_uart_write_work);

	spin_lock_init(&hu->rx_lock);

	/* Flush any pending characters in the driver and line discipline. */

	/* FIXME: why is this needed. Note don't use ldisc_ref here as the
	   open path is before the ldisc is referencable */

	if (tty->ldisc->ops->flush_buffer)
		tty->ldisc->ops->flush_buffer(tty);
	tty_driver_flush_buffer(tty);

	return 0;
}
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
/* hci_uart_tty_close()
 *
 *    Called when the line discipline is changed to something
 *    else, the tty is closed, or the tty detects a hangup.
 */
static void hci_uart_tty_close(struct tty_struct *tty)
{
   struct hci_uart *hu = (void *)tty->disc_data;
   struct hci_dev *hdev = hu->hdev;

   int i;
   unsigned long flags;

   BT_INFO("tty close %p", tty);

   /* Detach from the tty */
   tty->disc_data = NULL;

   if (tty->ldisc->ops->flush_buffer)
     tty->ldisc->ops->flush_buffer(tty);
   tty_driver_flush_buffer(tty);

   if (hu)
   {
     if (hdev)
	hci_uart_close(hdev);

     cancel_work_sync(&hu->write_work);

     if (test_and_clear_bit(HCI_UART_PROTO_SET, &hu->flags))
     {
         if (hdev) {
            if (test_bit(HCI_UART_REGISTERED, &hu->flags))
               hci_unregister_dev(hdev);
            hci_free_dev(hdev);
         }
         hu->proto->close(hu);
         for (i = PROTO_SH_BT; i < PROTO_SH_MAX; i++)
         {
             if (hu->list[i] != NULL)
             BT_ERR("%d not un-registered", i);
         }
         kfree(hu);
     }
   }

   spin_lock_irqsave(&reg_lock, flags);
   g_hu = NULL;
   spin_unlock_irqrestore(&reg_lock, flags);
}
#else
static void hci_uart_tty_close(struct tty_struct *tty)
{
	struct hci_uart *hu = (void *)tty->disc_data;
	struct hci_dev *hdev;

	BT_DBG("tty %p", tty);

	/* Detach from the tty */
	tty->disc_data = NULL;

	if (!hu)
		return;

	hdev = hu->hdev;
	if (hdev)
		hci_uart_close(hdev);

	cancel_work_sync(&hu->write_work);

	if (test_and_clear_bit(HCI_UART_PROTO_SET, &hu->flags)) {
		if (hdev) {
			if (test_bit(HCI_UART_REGISTERED, &hu->flags))
				hci_unregister_dev(hdev);
			hci_free_dev(hdev);
		}
		hu->proto->close(hu);
	}

	kfree(hu);
}
#endif
/* hci_uart_tty_wakeup()
 *
 *    Callback for transmit wakeup. Called when low level
 *    device driver can accept more send data.
 *
 * Arguments:        tty    pointer to associated tty instance data
 * Return Value:    None
 */
static void hci_uart_tty_wakeup(struct tty_struct *tty)
{
	struct hci_uart *hu = (void *)tty->disc_data;

	BT_DBG("");

	if (!hu)
		return;

	clear_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);

	if (tty != hu->tty)
		return;

	if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
		hci_uart_tx_wakeup(hu);
}

/* hci_uart_tty_receive()
 *
 *     Called by tty low level driver when receive data is
 *     available.
 *
 * Arguments:  tty          pointer to tty isntance data
 *             data         pointer to received data
 *             flags        pointer to flags for data
 *             count        count of received data in bytes
 *
 * Return Value:    None
 */
static void hci_uart_tty_receive(struct tty_struct *tty, const u8 *data, char *flags, int count)
{
	struct hci_uart *hu = (void *)tty->disc_data;

	if (!hu || tty != hu->tty)
		return;

	if (!test_bit(HCI_UART_PROTO_SET, &hu->flags))
		return;

	spin_lock(&hu->rx_lock);
	hu->proto->recv(hu, (void *) data, count);

#if !defined(CONFIG_RADIO_BCM4343S) && !defined(CONFIG_RADIO_SC2331)
	if (hu->hdev)
		hu->hdev->stat.byte_rx += count;
#endif
	spin_unlock(&hu->rx_lock);

	tty_unthrottle(tty);
}

static int hci_uart_register_dev(struct hci_uart *hu)
{
	struct hci_dev *hdev;

	BT_DBG("");
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
	BT_ERR("hci_uart_register_dev");

   /* Allocate local resource memory */
   hst = kzalloc(sizeof(struct hci_st), GFP_KERNEL);
   if (!hst) {
       BT_ERR("Can't allocate control structure");
       return -ENFILE;
   }
#endif

	/* Initialize and register HCI device */
	hdev = hci_alloc_dev();
	if (!hdev) {
		BT_ERR("Can't allocate HCI device");
		return -ENOMEM;
	}

	hu->hdev = hdev;

	hdev->bus = HCI_UART;
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
   hst->hdev = hdev;

   hci_set_drvdata(hdev, hst);
#else
	hci_set_drvdata(hdev, hu);
#endif
	hdev->open  = hci_uart_open;
	hdev->close = hci_uart_close;
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
	hdev->flush = NULL;
#else
    hdev->flush = hci_uart_flush;
#endif
	hdev->send  = hci_uart_send_frame;
	SET_HCIDEV_DEV(hdev, hu->tty->dev);

	if (test_bit(HCI_UART_RAW_DEVICE, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RAW_DEVICE, &hdev->quirks);

	if (test_bit(HCI_UART_EXT_CONFIG, &hu->hdev_flags))
		set_bit(HCI_QUIRK_EXTERNAL_CONFIG, &hdev->quirks);

	if (!test_bit(HCI_UART_RESET_ON_INIT, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RESET_ON_CLOSE, &hdev->quirks);

	if (test_bit(HCI_UART_CREATE_AMP, &hu->hdev_flags))
		hdev->dev_type = HCI_AMP;
	else
		hdev->dev_type = HCI_BREDR;

	if (test_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return 0;

	if (hci_register_dev(hdev) < 0) {
		BT_ERR("Can't register HCI device");
		hci_free_dev(hdev);
		return -ENODEV;
	}

	set_bit(HCI_UART_REGISTERED, &hu->flags);
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
   set_bit(BT_DRV_RUNNING, &hst->flags);
#endif
	return 0;
}

static int hci_uart_set_proto(struct hci_uart *hu, int id)
{
	struct hci_uart_proto *p;
	int err;

	p = hci_uart_get_proto(id);
	if (!p)
		return -EPROTONOSUPPORT;

	err = p->open(hu);
	if (err)
		return err;

	hu->proto = p;

	err = hci_uart_register_dev(hu);
	if (err) {
		p->close(hu);
		return err;
	}

	return 0;
}

static int hci_uart_set_flags(struct hci_uart *hu, unsigned long flags)
{
	unsigned long valid_flags = BIT(HCI_UART_RAW_DEVICE) |
				    BIT(HCI_UART_RESET_ON_INIT) |
				    BIT(HCI_UART_CREATE_AMP) |
				    BIT(HCI_UART_INIT_PENDING) |
				    BIT(HCI_UART_EXT_CONFIG);

	if ((flags & ~valid_flags))
		return -EINVAL;

	hu->hdev_flags = flags;

	return 0;
}

/* hci_uart_tty_ioctl()
 *
 *    Process IOCTL system call for the tty device.
 *
 * Arguments:
 *
 *    tty        pointer to tty instance data
 *    file       pointer to open file object for device
 *    cmd        IOCTL command code
 *    arg        argument for IOCTL call (cmd dependent)
 *
 * Return Value:    Command dependent
 */
static int hci_uart_tty_ioctl(struct tty_struct *tty, struct file * file,
					unsigned int cmd, unsigned long arg)
{
	struct hci_uart *hu = (void *)tty->disc_data;
	int err = 0;

	BT_DBG("");

	/* Verify the status of the device */
	if (!hu)
		return -EBADF;

	switch (cmd) {
	case HCIUARTSETPROTO:
		if (!test_and_set_bit(HCI_UART_PROTO_SET, &hu->flags)) {
			err = hci_uart_set_proto(hu, arg);
			if (err) {
				clear_bit(HCI_UART_PROTO_SET, &hu->flags);
				return err;
			}
		} else
			return -EBUSY;
		break;

	case HCIUARTGETPROTO:
		if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
			return hu->proto->id;
		return -EUNATCH;

	case HCIUARTGETDEVICE:
		if (test_bit(HCI_UART_REGISTERED, &hu->flags))
			return hu->hdev->id;
		return -EUNATCH;

	case HCIUARTSETFLAGS:
		if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
			return -EBUSY;
		err = hci_uart_set_flags(hu, arg);
		if (err)
			return err;
		break;

	case HCIUARTGETFLAGS:
		return hu->hdev_flags;

	default:
		err = n_tty_ioctl_helper(tty, file, cmd, arg);
		break;
	}

	return err;
}

/*
 * We don't provide read/write/poll interface for user space.
 */
static ssize_t hci_uart_tty_read(struct tty_struct *tty, struct file *file,
					unsigned char __user *buf, size_t nr)
{
	return 0;
}

static ssize_t hci_uart_tty_write(struct tty_struct *tty, struct file *file,
					const unsigned char *data, size_t count)
{
	return 0;
}

static unsigned int hci_uart_tty_poll(struct tty_struct *tty,
					struct file *filp, poll_table *wait)
{
	return 0;
}

static int __init hci_uart_init(void)
{
	static struct tty_ldisc_ops hci_uart_ldisc;
	int err;

	BT_INFO("HCI UART driver ver %s", VERSION);

	/* Register the tty discipline */

	memset(&hci_uart_ldisc, 0, sizeof (hci_uart_ldisc));
	hci_uart_ldisc.magic		= TTY_LDISC_MAGIC;
	hci_uart_ldisc.name		= "n_hci";
	hci_uart_ldisc.open		= hci_uart_tty_open;
	hci_uart_ldisc.close		= hci_uart_tty_close;
	hci_uart_ldisc.read		= hci_uart_tty_read;
	hci_uart_ldisc.write		= hci_uart_tty_write;
	hci_uart_ldisc.ioctl		= hci_uart_tty_ioctl;
	hci_uart_ldisc.poll		= hci_uart_tty_poll;
	hci_uart_ldisc.receive_buf	= hci_uart_tty_receive;
	hci_uart_ldisc.write_wakeup	= hci_uart_tty_wakeup;
	hci_uart_ldisc.owner		= THIS_MODULE;

	err = tty_register_ldisc(N_HCI, &hci_uart_ldisc);
	if (err) {
		BT_ERR("HCI line discipline registration failed. (%d)", err);
		return err;
	}

#ifdef CONFIG_BT_HCI_BCM_UART
	h4_init();
#endif
#ifdef CONFIG_BT_HCIUART_BCSP
	bcsp_init();
#endif
#ifdef CONFIG_BT_HCIUART_LL
	ll_init();
#endif
#ifdef CONFIG_BT_HCIUART_ATH3K
	ath_init();
#endif
#ifdef CONFIG_BT_HCIUART_3WIRE
	h5_init();
#endif
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
   /* initialize register lock spinlock */
   spin_lock_init(&reg_lock);
#endif
	return 0;
}

static void __exit hci_uart_exit(void)
{
	int err;

#ifdef CONFIG_BT_HCI_BCM_UART
	h4_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_BCSP
	bcsp_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_LL
	ll_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_ATH3K
	ath_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_3WIRE
	h5_deinit();
#endif

	/* Release tty registration of line discipline */
	err = tty_unregister_ldisc(N_HCI);
	if (err)
		BT_ERR("Can't unregister HCI line discipline (%d)", err);
}

module_init(hci_uart_init);
module_exit(hci_uart_exit);

MODULE_AUTHOR("Marcel Holtmann <marcel@holtmann.org>");
MODULE_DESCRIPTION("Bluetooth HCI UART driver ver " VERSION);
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
MODULE_ALIAS_LDISC(N_HCI);
