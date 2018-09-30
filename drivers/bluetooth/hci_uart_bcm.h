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

#ifndef N_HCI
#define N_HCI	15
#endif

#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
#include <linux/skbuff.h>

/*******************************************************************************
**  Constants
*******************************************************************************/

/*
 * enum proto-type - The protocol on chips which share a
 *	common physical interface like UART.
 */
enum proto_type {
    PROTO_SH_BT,
    PROTO_SH_FM,
    PROTO_SH_GPS,
    PROTO_SH_MAX,
};

#define sh_ldisc_cb(skb) ((struct sh_ldisc_skb_cb *)((skb)->cb))

/*******************************************************************************
**  Type definitions
*******************************************************************************/

/*
 * Skb helpers
 */
struct sh_ldisc_skb_cb {
    __u8 pkt_type;
    __u32 lparam;
};

/**
 * struct sh_proto_s - Per Protocol structure from BT/FM/GPS to shared ldisc
 * @type: type of the protocol being registered among the
 *	available proto_type(BT, FM, GPS the protocol which share TTY).
 * @recv: the receiver callback pointing to a function in the
 *	protocol drivers called by the shared ldisc driver upon receiving
 *	relevant data.
 * @match_packet: reserved for future use, to make ST more generic
 * @reg_complete_cb: callback handler pointing to a function in protocol
 *	handler called by shared ldisc when the pending registrations are complete.
 *	The registrations are marked pending, in situations when fw
 *	download is in progress.
 * @write: pointer to function in shared ldisc provided to protocol drivers,
 *	to be made use when protocol drivers have data to send to TTY.
 * @priv_data: privdate data holder for the protocol drivers, sent
 *	from the protocol drivers during registration, and sent back on
 *	reg_complete_cb and recv.
 */
struct sh_proto_s {
    enum proto_type type;
    long (*recv) (void *, struct sk_buff *);
    unsigned char (*match_packet) (const unsigned char *data);
    void (*reg_complete_cb) (void *, char data);
    long (*write) (struct sk_buff *skb);
    void *priv_data;
};

/*******************************************************************************
**  Extern variables and functions
*******************************************************************************/

extern long hci_ldisc_register(struct sh_proto_s *);
extern long hci_ldisc_unregister(enum proto_type);
#endif
/* Ioctls */
#define HCIUARTSETPROTO		_IOW('U', 200, int)
#define HCIUARTGETPROTO		_IOR('U', 201, int)
#define HCIUARTGETDEVICE	_IOR('U', 202, int)
#define HCIUARTSETFLAGS		_IOW('U', 203, int)
#define HCIUARTGETFLAGS		_IOR('U', 204, int)

/* UART protocols */
#define HCI_UART_MAX_PROTO	6

#define HCI_UART_H4	0
#define HCI_UART_BCSP	1
#define HCI_UART_3WIRE	2
#define HCI_UART_H4DS	3
#define HCI_UART_LL	4
#define HCI_UART_ATH3K	5

#define HCI_UART_RAW_DEVICE	0
#define HCI_UART_RESET_ON_INIT	1
#define HCI_UART_CREATE_AMP	2
#define HCI_UART_INIT_PENDING	3
#define HCI_UART_EXT_CONFIG	4

struct hci_uart;

struct hci_uart_proto {
	unsigned int id;
	int (*open)(struct hci_uart *hu);
	int (*close)(struct hci_uart *hu);
	int (*flush)(struct hci_uart *hu);
	int (*recv)(struct hci_uart *hu, void *data, int len);
	int (*enqueue)(struct hci_uart *hu, struct sk_buff *skb);
	struct sk_buff *(*dequeue)(struct hci_uart *hu);
};

struct hci_uart {
	struct tty_struct	*tty;
	struct hci_dev		*hdev;
	unsigned long		flags;
	unsigned long		hdev_flags;

	struct work_struct	init_ready;
	struct work_struct	write_work;

	struct hci_uart_proto	*proto;
	void			*priv;

	struct sk_buff		*tx_skb;
	unsigned long		tx_state;
	spinlock_t		rx_lock;
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
   struct sh_proto_s *list[PROTO_SH_MAX];
   unsigned char    protos_registered;
   spinlock_t lock;
#endif

};
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
/* BT driver's local status */
#define BT_DRV_RUNNING        0
#define BT_ST_REGISTERED      1

/* BT driver operation structure */
struct hci_st {

    /* hci device pointer which binds to bt driver */
    struct hci_dev *hdev;

    /* used locally,to maintain various BT driver status */
    unsigned long flags;

    /* to hold ST registration callback  status */
    char streg_cbdata;

    /* write function pointer of ST driver */
    long (*st_write) (struct sk_buff *);

    /* Wait on comepletion handler needed to synchronize
    * hci_st_open() and hci_st_registration_completion_cb()
    * functions.*/
    struct completion wait_for_btdrv_reg_completion;
};
#endif

/* HCI_UART proto flag bits */
#define HCI_UART_PROTO_SET	0
#define HCI_UART_REGISTERED	1

/* TX states  */
#define HCI_UART_SENDING	1
#define HCI_UART_TX_WAKEUP	2

int hci_uart_register_proto(struct hci_uart_proto *p);
int hci_uart_unregister_proto(struct hci_uart_proto *p);
int hci_uart_tx_wakeup(struct hci_uart *hu);
int hci_uart_init_ready(struct hci_uart *hu);
#if defined(CONFIG_RADIO_BCM4343S) || defined(CONFIG_RADIO_SC2331)
void hci_uart_route_frame(enum proto_type protoid, struct hci_uart *hu, struct sk_buff *skb);
long hci_ldisc_write(struct sk_buff *);


#endif
#ifdef CONFIG_BT_HCI_BCM_UART
int h4_init(void);
int h4_deinit(void);
#endif

#ifdef CONFIG_BT_HCIUART_BCSP
int bcsp_init(void);
int bcsp_deinit(void);
#endif

#ifdef CONFIG_BT_HCIUART_LL
int ll_init(void);
int ll_deinit(void);
#endif

#ifdef CONFIG_BT_HCIUART_ATH3K
int ath_init(void);
int ath_deinit(void);
#endif

#ifdef CONFIG_BT_HCIUART_3WIRE
int h5_init(void);
int h5_deinit(void);
#endif
