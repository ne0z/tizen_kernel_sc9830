/*
 * Copyright (C) 2012 Spreadtrum Communications Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _SPRDFB_H_
#define _SPRDFB_H_

#include <uapi/video/sprdfb.h>

#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#endif
#include <linux/compat.h>
#include <linux/workqueue.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#ifdef CONFIG_FB_MMAP_CACHED
#include <linux/mm_types.h>
#endif
#include <linux/time.h>
#include <linux/notifier.h>
#ifdef CONFIG_DRM_SPRD
#include <drm/sprd_drm.h>
#endif
#include <linux/time.h>

#if ((!defined(CONFIG_FB_SCX35)) && (!defined(CONFIG_FB_SCX15)))
#define FB_CHECK_ESD_IN_VFP
#endif
//#define FB_CHECK_ESD_BY_TE_SUPPORT
#define BIT_PER_PIXEL_SURPPORT

#if defined(CONFIG_FB_LCD_OVERLAY_SUPPORT)
#define SPRDFB_OVERLAY_DEBUG
#endif

enum{
	SPRDFB_PANEL_IF_DBI = 0,
	SPRDFB_PANEL_IF_DPI,
	SPRDFB_PANEL_IF_EDPI,
	SPRDFB_PANEL_IF_LIMIT
};

enum {
	SPRDFB_UNKNOWN = 0,
	SPRDFB_DYNAMIC_PCLK = 0x1,
	SPRDFB_DYNAMIC_FPS,
	SPRDFB_DYNAMIC_MIPI_CLK,
	SPRDFB_FORCE_FPS,
	SPRDFB_FORCE_PCLK,
};

enum{
	MCU_LCD_REGISTER_TIMING = 0,
	MCU_LCD_GRAM_TIMING,
	MCU_LCD_TIMING_KIND_MAX
};

enum{
	RGB_LCD_H_TIMING = 0,
	RGB_LCD_V_TIMING,
	RGB_LCD_TIMING_KIND_MAX
};

#ifdef CONFIG_FB_LCD_OVERLAY_SUPPORT
enum{
	SPRD_OVERLAY_STATUS_OFF = 0,
	SPRD_OVERLAY_STATUS_ON,
	SPRD_OVERLAY_STATUS_STARTED,
	SPRD_OVERLAY_STATUS_MAX
};

enum {
	SPRD_DISPLAY_UPDATE_NONE = 0,
	SPRD_DISPLAY_UPDATE_PAN,
	SPRD_DISPLAY_UPDATE_OVERLAY,
	SPRD_DISPLAY_UPDATE_MAX
};

#ifdef SPRDFB_OVERLAY_DEBUG
struct ov_info {
	int layer_index;
	unsigned char *osd_buffer;
	unsigned char *img_buffer;
	overlay_rect rect;
	overlay_endian endian;
};
#endif

#ifdef CONFIG_COMPAT
typedef struct overlay_info32{
	int layer_index;
	int data_type;
	bool rb_switch;
	overlay_rect rect;
	overlay_endian endian;
	compat_caddr_t buffer;
}overlay_info32;
#endif
#endif

enum{
	MIPI_PLL_TYPE_NONE = 0,
	MIPI_PLL_TYPE_1,
	MIPI_PLL_TYPE_2,
	MIPI_PLL_TYPE_LIMIT
};

typedef struct fb_capability {
	uint16_t need_light_sleep;	/* enable light_sleep in fb driver*/
	uint16_t mipi_pll_type;		/* 0:none	1:for pike/pikel	2:for sharkl64/sharklT8*/
}fb_capability;

#ifdef CONFIG_DRM_SPRD
enum sprdfb_dpms {
	SPRDFB_DPMS_ON = 0,
	SPRDFB_DPMS_OFF = 3,
	SPRDFB_DPMS_MAX,
};

enum sprdfb_notifier {
	SPRDFB_SET_DPMS,
	SPRDFB_MAX_NOTI,
};

struct sprdfb_nb_event {
	int index;
	void *data;
};
#endif

struct fps_info {
	u32 enable_dmesg;
	u32 interval_ms;
	struct timespec timestamp_last;
	u32 frame_counter_last;
	u32 frame_counter;
	u32 fpks;
	int fps_checking_mode;  /*pan or overlay*/
};

struct sprdfb_device {
	struct fb_info	*fb;
	struct panel_spec	*panel;
	struct display_ctrl	*ctrl;
	void *logo_buffer_addr_v;
	void *priv1;

#ifdef CONFIG_OF
	struct device *of_dev;
#endif

	uint16_t		enable;
	uint16_t	 	dev_id; /*main_lcd, sub_lcd*/

	uint32_t	 	bpp;  /*input bit per pixel*/

#if defined(CONFIG_SEC_DEBUG) || defined(CONFIG_SEC_LOG64)
	uint32_t		framebuffer_nr; /*number of framebuffer*/
#endif

	uint16_t		panel_ready; /*panel has been inited by uboot*/
	uint16_t		panel_if_type; /*panel IF*/

#ifdef CONFIG_FB_LOW_RES_SIMU
	uint32_t display_width;
	uint32_t display_height;
#endif

	union{
		uint32_t	mcu_timing[MCU_LCD_TIMING_KIND_MAX];
		uint32_t	rgb_timing[RGB_LCD_TIMING_KIND_MAX];
	}panel_timing;

	struct fb_capability capability;
	uint32_t dpi_clock;
	struct semaphore   refresh_lock;
	uint64_t frame_count;

#ifdef CONFIG_FB_ESD_SUPPORT
	struct delayed_work ESD_work;
//	struct semaphore   ESD_lock;
	uint32_t ESD_timeout_val;
	bool ESD_work_start;
	/*for debug only*/
	uint32_t check_esd_time;
	uint32_t panel_reset_time;
	uint32_t reset_dsi_time;
#ifdef FB_CHECK_ESD_BY_TE_SUPPORT
	uint32_t esd_te_waiter;
	wait_queue_head_t  esd_te_queue;
	uint32_t esd_te_done;
#endif
#endif

	unsigned int irq;
	uint32_t logo_buffer_size;
	struct fps_info fps;

#ifdef CONFIG_DRM_DPMS_IOCTL
	struct notifier_block	nb_ctrl;
#endif
#ifdef CONFIG_HAS_EARLYSUSPEND
	struct early_suspend	early_suspend;
#endif
	/*For Special features*/
	struct ion_client *fb_ion_client;
	uint8_t csc_range;
	uint32_t dbg_cnt;
#ifdef SPRDFB_OVERLAY_DEBUG
	struct ov_info overlay_data;
#endif
};

struct display_ctrl {
	const char	*name;

	int32_t	(*early_init)	  (struct sprdfb_device *dev);
	int32_t	(*init)		  (struct sprdfb_device *dev);
	int32_t	(*uninit)		  (struct sprdfb_device *dev);

	int32_t 	(*refresh)	  (struct sprdfb_device *dev);
	void 	(*logo_proc)	  (struct sprdfb_device *dev);
	int32_t	(*shutdown)	  (struct sprdfb_device *dev);
	int32_t	(*suspend)	  (struct sprdfb_device *dev);
	int32_t 	(*resume)	  (struct sprdfb_device *dev);
	int32_t (*update_clk) (struct sprdfb_device *dev);

#ifdef CONFIG_FB_ESD_SUPPORT
	int32_t	(*ESD_check)	  (struct sprdfb_device *dev);
#endif
#ifdef CONFIG_LCD_ESD_RECOVERY
    int32_t	(*ESD_reset)	  (struct sprdfb_device *dev);
#endif
#ifdef  CONFIG_FB_LCD_OVERLAY_SUPPORT
	int32_t 	(*enable_overlay) 	(struct sprdfb_device *dev, struct overlay_info* info, int enable);
	int32_t	(*display_overlay)	(struct sprdfb_device *dev, struct overlay_display* setting);
	int32_t         (*disable_overlay)      (struct sprdfb_device *dev, int layer_index);
#endif

#ifdef CONFIG_FB_VSYNC_SUPPORT
	int32_t 	(*wait_for_vsync) 	(struct sprdfb_device *dev);
#endif

#ifdef CONFIG_FB_MMAP_CACHED
	void (*set_vma)(struct vm_area_struct *vma);
#endif
	int32_t	(*is_refresh_done)	(struct sprdfb_device *dev);
	int32_t	(*set_metadata)      (struct sprdfb_device *dev,
			struct overlay_metadata *metadata);
};

#ifndef ROUND
#define ROUND(a, b) (((a) + (b) / 2) / (b))
#endif

/* function declaration begin */
int sprdfb_create_sysfs(struct sprdfb_device *fb_dev);
void sprdfb_remove_sysfs(struct sprdfb_device *fb_dev);

#ifdef CONFIG_FB_DYNAMIC_FREQ_SCALING
int sprdfb_dispc_chg_clk(struct sprdfb_device *fb_dev,
				int type, u32 new_val);
#else
#define sprdfb_dispc_chg_clk(fb_dev, type, new_val) ( \
{ \
	int _ret = -ENXIO; \
	pr_err("dynamical clock feature hasn't been enabled yet\n"); \
	_ret; \
} \
)
#endif

#if !defined(CONFIG_FB_SCX15)
int sprdfb_dsi_chg_dphy_freq(struct sprdfb_device *fb_dev,
		u32 dphy_freq);
int32_t dsi_dpi_init(struct sprdfb_device *dev);
#else
#define sprdfb_dsi_chg_dphy_freq(fb_dev, dphy_freq) ( \
{ \
	int _ret = -ENXIO; \
	pr_err("this chip doesn't support for mipi dsi\n"); \
	_ret; \
} \
)

#define dsi_dpi_init(fb_dev) ( \
{ \
	int _ret = -ENXIO; \
	pr_err("this chip doesn't support for mipi dsi\n"); \
	_ret; \
} \
)
#endif

int sprdfb_chg_clk_intf(struct sprdfb_device *fb_dev,
			int type, u32 new_val);
/* Function declare begin */
#ifdef CONFIG_SC_FPGA
int sprdchip_lvds_init(void);
#endif
/* Function declare end */

#ifdef CONFIG_DRM_SPRD
int sprdfb_nb_register(struct notifier_block *nb);
int sprdfb_nb_unregister(struct notifier_block *nb);
int sprdfb_nb_send_event(unsigned long val, void *v);
#endif

#endif
