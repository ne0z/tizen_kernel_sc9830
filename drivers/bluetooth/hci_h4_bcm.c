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
#include <linux/fm.h>
#endif
#define VERSION "1.2"

struct h4_struct {
	unsigned long rx_state;
	unsigned long rx_count;
	struct sk_buff *rx_skb;
	struct sk_buff_head txq;
};

/* H4 receiver States */
#define H4_W4_PACKET_TYPE	0
#define H4_W4_EVENT_HDR		1
#define H4_W4_ACL_HDR		2
#define H4_W4_SCO_HDR		3
#define H4_W4_DATA		4
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
#define FM_W4_EVENT_HDR 5
#endif

/* Initialize protocol */
static int h4_open(struct hci_uart *hu)
{
	struct h4_struct *h4;

	BT_DBG("hu %p", hu);

	h4 = kzalloc(sizeof(*h4), GFP_KERNEL);
	if (!h4)
		return -ENOMEM;

	skb_queue_head_init(&h4->txq);

	hu->priv = h4;
	return 0;
}

/* Flush protocol data */
static int h4_flush(struct hci_uart *hu)
{
	struct h4_struct *h4 = hu->priv;

	BT_DBG("hu %p", hu);

	skb_queue_purge(&h4->txq);

	return 0;
}

/* Close protocol */
static int h4_close(struct hci_uart *hu)
{
	struct h4_struct *h4 = hu->priv;

	hu->priv = NULL;

	BT_DBG("hu %p", hu);

	skb_queue_purge(&h4->txq);

	kfree_skb(h4->rx_skb);

	hu->priv = NULL;
	kfree(h4);

	return 0;
}

/* Enqueue frame for transmittion (padding, crc, etc) */
static int h4_enqueue(struct hci_uart *hu, struct sk_buff *skb)
{
	struct h4_struct *h4 = hu->priv;

	BT_DBG("hu %p skb %p", hu, skb);

	/* Prepend skb with frame type */
#if !defined(CONFIG_RADIO_BCM4343S) && !defined(CONFIG_RADIO_SC2331)
	memcpy(skb_push(skb, 1), &bt_cb(skb)->pkt_type, 1);
#endif
	skb_queue_tail(&h4->txq, skb);

	return 0;
}

#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
/*
 * Function to check data length
 */
static inline int h4_check_data_len(struct h4_struct *h4,
                    struct hci_uart *hu, int protoid,int len)
{
    register int room = skb_tailroom(h4->rx_skb);

    BT_DBG("len %d room %d", len, room);

    if (!len) {
       hci_uart_route_frame(protoid, hu, h4->rx_skb);
    } else if (len > room) {
        BT_ERR("Data length is too large");
        kfree_skb(h4->rx_skb);
    } else {
        h4->rx_state = H4_W4_DATA;
        h4->rx_count = len;
        return len;
    }

    h4->rx_state = H4_W4_PACKET_TYPE;
    h4->rx_skb   = NULL;
    h4->rx_count = 0;

    return 0;
}
#endif
/* Recv data */
static int h4_recv(struct hci_uart *hu, void *data, int count)
{
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
    struct h4_struct *h4 = hu->priv;
    register char *ptr;
    struct hci_event_hdr *eh;
    struct hci_acl_hdr   *ah;
    struct hci_sco_hdr   *sh;
    struct fm_event_hdr *fm;
    register int len, type, dlen;
    static enum proto_type protoid = PROTO_SH_MAX;

    BT_DBG("hu %p count %d rx_state %ld rx_count %ld", hu, count, h4->rx_state, h4->rx_count);

    ptr = (char *)data;
    while (count) {
        if (h4->rx_count) {
            len = min_t(unsigned int, h4->rx_count, count);
              memcpy(skb_put(h4->rx_skb, len), ptr, len);
            h4->rx_count -= len; count -= len; ptr += len;

            if (h4->rx_count)
                continue;

            switch (h4->rx_state) {
            case H4_W4_DATA:

                BT_DBG("%2x %2x %2x %2x",h4->rx_skb->data[0], h4->rx_skb->data[1], h4->rx_skb->data[2], h4->rx_skb->data[3]);
                BT_DBG("%2x %2x %2x %2x",h4->rx_skb->data[4], h4->rx_skb->data[5], h4->rx_skb->data[6], h4->rx_skb->data[7]);

                BT_DBG("Complete data");
#if defined(CONFIG_RADIO_BCM4343S)

                if ( ( h4->rx_skb->data[3] == 0x15 && h4->rx_skb->data[4] == 0xfc )
                  || ( h4->rx_skb->data[0] == 0xff && h4->rx_skb->data[1] == 0x01 && h4->rx_skb->data[2] == 0x08 )
               )
#elif defined(CONFIG_RADIO_SC2331)
	      if ((h4->rx_skb->data[3] == 0x8C && h4->rx_skb->data[4] == 0xfc)
			|| (h4->rx_skb->data[0] == 0xff))
#endif
		{
                   BT_INFO("FM Event change to FM CH8 packet");
                   type = FM_CH8_PKT;
                   h4->rx_skb->cb[0] = FM_CH8_PKT;
                   h4->rx_state = FM_W4_EVENT_HDR;
                   protoid = PROTO_SH_FM;
		}

                hci_uart_route_frame(protoid, hu, h4->rx_skb);

                h4->rx_state = H4_W4_PACKET_TYPE;
                h4->rx_skb = NULL;
                protoid = PROTO_SH_MAX;
                continue;

            case H4_W4_EVENT_HDR:
                eh = hci_event_hdr(h4->rx_skb);

                BT_DBG("Event header: evt 0x%2.2x plen %d", eh->evt, eh->plen);

                h4_check_data_len(h4, hu, protoid, eh->plen);
                continue;

            case H4_W4_ACL_HDR:
                ah = hci_acl_hdr(h4->rx_skb);

                dlen = __le16_to_cpu(ah->dlen);

                BT_DBG("ACL header: dlen %d", dlen);

                h4_check_data_len(h4, hu, protoid, dlen);
                continue;

            case H4_W4_SCO_HDR:
                sh = hci_sco_hdr(h4->rx_skb);

                BT_DBG("SCO header: dlen %d", sh->dlen);

                h4_check_data_len(h4, hu, protoid, sh->dlen);
                continue;

            case FM_W4_EVENT_HDR:
                fm = (struct fm_event_hdr *)h4->rx_skb->data;
                BT_DBG("FM Header: evt 0x%2.2x plen %d",
                    fm->event, fm->plen);
                h4_check_data_len(h4, hu, PROTO_SH_FM, fm->plen);
                continue;

            }
        }

        /* H4_W4_PACKET_TYPE */
        switch (*ptr) {
        case HCI_EVENT_PKT:
            BT_DBG("Event packet");

            BT_DBG("%2x %2x %2x %2x",ptr[0], ptr[1], ptr[2], ptr[3]);
            BT_DBG("%2x %2x %2x %2x",ptr[4], ptr[5], ptr[6], ptr[7]);
            if ( ptr[4] == 0x15 && ptr[5] == 0xfc )
            {
               BT_DBG("FM Event change to FM CH8 packet");
               type = FM_CH8_PKT;
               h4->rx_state = FM_W4_EVENT_HDR;
               h4->rx_count = FM_EVENT_HDR_SIZE;
               protoid = PROTO_SH_FM;
            }
            else
            {
               BT_DBG("FM Event is not detected");
               h4->rx_state = H4_W4_EVENT_HDR;
               h4->rx_count = HCI_EVENT_HDR_SIZE;
               type = HCI_EVENT_PKT;
               protoid = PROTO_SH_BT;
            }
            break;

        case HCI_ACLDATA_PKT:
            BT_DBG("ACL packet");
            h4->rx_state = H4_W4_ACL_HDR;
            h4->rx_count = HCI_ACL_HDR_SIZE;
            type = HCI_ACLDATA_PKT;
            protoid = PROTO_SH_BT;
            break;

        case HCI_SCODATA_PKT:
            BT_DBG("SCO packet");
            h4->rx_state = H4_W4_SCO_HDR;
            h4->rx_count = HCI_SCO_HDR_SIZE;
            type = HCI_SCODATA_PKT;
            protoid = PROTO_SH_BT;
            break;

        /* Channel 8(FM) packet */
        case FM_CH8_PKT:
            BT_DBG("FM CH8 packet");
            type = FM_CH8_PKT;
            h4->rx_state = FM_W4_EVENT_HDR;
            h4->rx_count = FM_EVENT_HDR_SIZE;
            protoid = PROTO_SH_FM;
            break;

        default:
            BT_ERR("Unknown HCI packet type %2.2x", (__u8)*ptr);
            hu->hdev->stat.err_rx++;
            ptr++; count--;
            continue;
        };

        ptr++; count--;

        switch (protoid)
        {
            case PROTO_SH_BT:
            case PROTO_SH_FM:
                /* Allocate new packet to hold received data */
                h4->rx_skb = bt_skb_alloc(HCI_MAX_FRAME_SIZE, GFP_ATOMIC);
                if (!h4->rx_skb)
                {
                    BT_ERR("Can't allocate mem for new packet");
                    h4->rx_state = H4_W4_PACKET_TYPE;
                    h4->rx_count = 0;
                    return -ENOMEM;
                }
                h4->rx_skb->dev = (void *) hu->hdev;
                sh_ldisc_cb(h4->rx_skb)->pkt_type = type;
                break;
#if 0
            case PROTO_SH_FM:    /* for FM */
                h4->rx_skb = bt_skb_alloc(FM_MAX_FRAME_SIZE, GFP_ATOMIC);
                if (!h4->rx_skb)
                {
                    BT_ERR("Can't allocate mem for new packet");
                    h4->rx_state = H4_W4_PACKET_TYPE;
                    h4->rx_count = 0;
                    return -ENOMEM;
                }
                /* place holder 0x08 */
                /* skb_reserve(h4->rx_skb, 1); */
                sh_ldisc_cb(h4->rx_skb)->pkt_type = FM_CH8_PKT;
                break;
#endif
            case PROTO_SH_MAX:
            case PROTO_SH_GPS:
                break;
        }

    }

    return count;

#else
	int ret;

	if (!test_bit(HCI_UART_REGISTERED, &hu->flags))
		return -EUNATCH;

	ret = hci_recv_stream_fragment(hu->hdev, data, count);
	if (ret < 0) {
		BT_ERR("Frame Reassembly Failed");
		return ret;
	}

	return count;
#endif
}

static struct sk_buff *h4_dequeue(struct hci_uart *hu)
{
	struct h4_struct *h4 = hu->priv;
	return skb_dequeue(&h4->txq);
}

static struct hci_uart_proto h4p = {
	.id		= HCI_UART_H4,
	.open		= h4_open,
	.close		= h4_close,
	.recv		= h4_recv,
	.enqueue	= h4_enqueue,
	.dequeue	= h4_dequeue,
	.flush		= h4_flush,
};

int __init h4_init(void)
{
	int err = hci_uart_register_proto(&h4p);

	if (!err)
		BT_INFO("HCI H4 protocol initialized");
	else
		BT_ERR("HCI H4 protocol registration failed");

	return err;
}

int __exit h4_deinit(void)
{
	return hci_uart_unregister_proto(&h4p);
}
