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
#ifndef _UAPI_SPRD_FB_H_
#define _UAPI_SPRD_FB_H_

#define SPRD_LAYER_IMG (0x1)   /*support YUV & RGB*/
#define SPRD_LAYER_OSD (0x2)   /*support RGB only*/
#define SPRD_LAYER_BOTH (0x03)	/*support RGB only*/

enum {
	SPRD_DATA_FORMAT_YUV422 = 0,
	SPRD_DATA_FORMAT_YUV420,
	SPRD_DATA_FORMAT_YUV400,
	SPRD_DATA_FORMAT_RGB888,
	SPRD_DATA_FORMAT_RGB666,
	SPRD_DATA_FORMAT_RGB565,
	SPRD_DATA_FORMAT_RGB555,
	SPRD_DATA_FORMAT_YUV422_3P = 8,
	SPRD_DATA_FORMAT_YUV420_3P,
	SPRD_DATA_FORMAT_LIMIT
};

enum{
	SPRD_DATA_ENDIAN_B0B1B2B3 = 0,
	SPRD_DATA_ENDIAN_B3B2B1B0,
	SPRD_DATA_ENDIAN_B2B3B0B1,
	SPRD_DATA_ENDIAN_B1B0B3B2,
	SPRD_DATA_ENDIAN_LIMIT
};

enum{
	SPRD_DISPLAY_OVERLAY_ASYNC = 0,
	SPRD_DISPLAY_OVERLAY_SYNC,
	SPRD_DISPLAY_OVERLAY_LIMIT
};

enum{
	SPRD_FB_POWER_OFF = 0,
	SPRD_FB_POWER_DOZE,
	SPRD_FB_POWER_NORMAL,
	SPRD_FB_POWER_SUSPEND,
	SPRD_FB_POWER_LIMIT
};

enum {
	CSC_RANGE_LIMITED,
	CSC_RANGE_FULL,
	CSC_RANGE_OFF,
};

enum {
	metadata_op_csc,
	metadata_op_max,
};

typedef struct overlay_size {
	uint16_t hsize;
	uint16_t vsize;
} overlay_size;

typedef struct overlay_rect {
	uint16_t x;
	uint16_t y;
	uint16_t w;
	uint16_t h;
} overlay_rect;

typedef struct overlay_endian {
	uint16_t y;
	uint16_t u;
	uint16_t v;
} overlay_endian;

typedef struct overlay_info {
	int layer_index;
	int data_type;
	overlay_size size;
	overlay_rect rect;
	overlay_endian endian;
	bool rb_switch;
} overlay_info;

#if defined (CONFIG_SPRDFB_USE_GEM_INDEX)
typedef struct overlay_handle {
	int handle;
	int index;
} overlay_handle;
#endif

typedef struct overlay_display {
	int layer_index;
#ifdef CONFIG_SPRDFB_USE_GEM_INDEX
	struct overlay_handle osd_handle;
	struct overlay_handle img_handle;
#else
	int osd_handle;
	int img_handle;
#endif
	int display_mode;
} overlay_display;

typedef struct overlay_metadata {
	uint32_t op;
	uint32_t flags;
	union {
		uint32_t panel_frame_rate;
		uint8_t csc_range;
	} data;
} overlay_metadata;

/*
int sprdfb_IOinit(void);
int sprdfb_IOdeinit(void);
*/


#define SPRD_FB_IOCTL_MAGIC 'm'
#define SPRD_FB_SET_OVERLAY _IOW(SPRD_FB_IOCTL_MAGIC, 1, unsigned int)
#define SPRD_FB_DISPLAY_OVERLAY _IOW(SPRD_FB_IOCTL_MAGIC, 2, unsigned int)
#define SPRD_FB_CHANGE_FPS _IOW(SPRD_FB_IOCTL_MAGIC, 3, unsigned int)
#define SPRD_FB_IS_REFRESH_DONE _IOW(SPRD_FB_IOCTL_MAGIC, 4, unsigned int)
#define SPRD_FB_SET_POWER_MODE _IOW(SPRD_FB_IOCTL_MAGIC, 5, unsigned int)
#define SPRD_FB_UNSET_OVERLAY _IOW(SPRD_FB_IOCTL_MAGIC, 6, unsigned int)
#define SPRD_FB_METADATA_SET  _IOW(SPRD_FB_IOCTL_MAGIC, 7, struct overlay_metadata)
#endif
