/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *
 * Authors:
 *	Eunchul Kim <chulspro.kim@samsung.com>
 *	Jinyoung Jeon <jy0.jeon@samsung.com>
 *	Sangmin Lee <lsmin.lee@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef _SPRD_DRM_IPP_H_
#define _SPRD_DRM_IPP_H_

#define for_each_ipp_ops(pos)	\
	for (pos = 0; pos < SPRD_DRM_OPS_MAX; pos++)
#define for_each_ipp_planar(pos)	\
	for (pos = 0; pos < SPRD_DRM_PLANAR_MAX; pos++)

#define IPP_GET_LCD_WIDTH	_IOR('F', 302, int)
#define IPP_GET_LCD_HEIGHT	_IOR('F', 303, int)
#define IPP_SET_WRITEBACK	_IOW('F', 304, u32)

#define ipp_is_m2m_cmd(c)	(c == IPP_CMD_M2M)
#define ipp_is_wb_cmd(c)	(c == IPP_CMD_WB)
#define ipp_is_output_cmd(c)	(c == IPP_CMD_OUTPUT)

/* definition of state */
enum drm_sprd_ipp_state {
	IPP_STATE_IDLE,
	IPP_STATE_START,
	IPP_STATE_STOP,
};

/*
 * A structure of command work information.
 * @work: work structure.
 * @ippdrv: current work ippdrv.
 * @c_node: command node information.
 * @ctrl: command control.
 */
struct drm_sprd_ipp_cmd_work {
	struct work_struct	work;
	struct sprd_drm_ippdrv	*ippdrv;
	struct drm_sprd_ipp_cmd_node *c_node;
	enum drm_sprd_ipp_ctrl	ctrl;
};

/*
 * A structure of command node.
 *
 * @priv: IPP private infomation.
 * @list: list head to command queue information.
 * @event_list: list head of event.
 * @mem_list: list head to source,destination memory queue information.
 * @cmd_lock: lock for synchronization of access to ioctl.
 * @mem_lock: lock for synchronization of access to memory nodes.
 * @event_lock: lock for synchronization of access to scheduled event.
 * @start_complete: completion of start of command.
 * @stop_complete: completion of stop of command.
 * @property: property information.
 * @cmd_workq: command work queue.
 * @start_work: start command work structure.
 * @stop_work: stop command work structure.
 * @event: event information structure.
 * @state: state of command node.
 */
struct drm_sprd_ipp_cmd_node {
	struct sprd_drm_ipp_private *priv;
	struct list_head	list;
	struct list_head	event_list;
	struct list_head	mem_list[SPRD_DRM_OPS_MAX];
	struct mutex	cmd_lock;
	struct mutex	mem_lock;
	struct mutex	event_lock;
	struct completion	start_complete;
	struct completion	stop_complete;
	struct drm_sprd_ipp_property	property;
	struct workqueue_struct	*cmd_workq;
	struct drm_sprd_ipp_cmd_work *start_work;
	struct drm_sprd_ipp_cmd_work *stop_work;
	struct drm_sprd_ipp_event_info *event;
	enum drm_sprd_ipp_state	state;
};

/*
 * A structure of buffer information.
 *
 * @gem_objs: Y, Cb, Cr each gem object.
 * @base: Y, Cb, Cr each planar address.
 * @size: Y, Cb, Cr each planar size.
 */
struct drm_sprd_ipp_buf_info {
	unsigned long	handles[SPRD_DRM_PLANAR_MAX];
	dma_addr_t	base[SPRD_DRM_PLANAR_MAX];
	uint64_t	size[SPRD_DRM_PLANAR_MAX];
};

/*
 * A structure of wb setting infomation.
 *
 * @enable: enable flag for wb.
 * @refresh: HZ of the refresh rate.
 */
struct drm_sprd_ipp_set_wb {
	__u32	enable;
	__u32	refresh;
};

/*
 * A structure of event information.
 *
 * @ippdrv: current work ippdrv.
 * @buf_id: id of src, dst buffer.
 */
struct drm_sprd_ipp_event_info {
	struct sprd_drm_ippdrv *ippdrv;
	u32	buf_id[SPRD_DRM_OPS_MAX];
};

/*
 * A structure of source,destination operations.
 *
 * @set_fmt: set format of image.
 * @set_transf: set transform(rotations, flip).
 * @set_size: set size of region.
 * @set_addr: set address for dma.
 */
struct sprd_drm_ipp_ops {
	int (*set_fmt)(struct device *dev, u32 fmt);
	int (*set_transf)(struct device *dev,
		enum drm_sprd_degree degree,
		enum drm_sprd_flip flip, bool *swap);
	int (*set_size)(struct device *dev, int swap,
		struct drm_sprd_pos *pos, struct drm_sprd_sz *sz);
	int (*set_addr)(struct device *dev,
		 struct drm_sprd_ipp_buf_info *buf_info, u32 buf_id,
		enum drm_sprd_ipp_buf_type buf_type);
};

/*
 * A structure of ipp driver.
 *
 * @drv_list: list head for registed sub driver information.
 * @parent_dev: parent device information.
 * @dev: platform device.
 * @drm_dev: drm device.
 * @ipp_id: id of ipp driver.
 * @dedicated: dedicated ipp device.
 * @ops: source, destination operations.
 * @c_node: current command information.
 * @cmd_list: list head for command information.
 * @prop_list: property informations of current ipp driver.
 * @drv_lock: lock for synchronization of access to start operation.
 * @check_property: check property about format, size, buffer.
 * @reset: reset ipp block.
 * @start: ipp each device start.
 * @stop: ipp each device stop.
 * @sched_event: work schedule handler.
 */
struct sprd_drm_ippdrv {
	struct list_head	drv_list;
	struct device	*parent_dev;
	struct device	*dev;
	struct drm_device	*drm_dev;
	u32	ipp_id;
	bool	dedicated;
	struct sprd_drm_ipp_ops	*ops[SPRD_DRM_OPS_MAX];
	struct drm_sprd_ipp_cmd_node *c_node;
	struct list_head	cmd_list;
	struct drm_sprd_ipp_prop_list *prop_list;
	struct mutex	drv_lock;

	int (*check_property)(struct device *dev,
		struct drm_sprd_ipp_property *property);
	int (*reset)(struct device *dev);
	int (*start)(struct device *dev, enum drm_sprd_ipp_cmd cmd);
	void (*stop)(struct device *dev, enum drm_sprd_ipp_cmd cmd);
	void (*sched_event)(struct drm_sprd_ipp_event_info *ipp_event);
};

#ifdef CONFIG_DRM_SPRD_IPP
extern int sprd_drm_ippdrv_register(struct sprd_drm_ippdrv *ippdrv);
extern int sprd_drm_ippdrv_unregister(struct sprd_drm_ippdrv *ippdrv);
extern int sprd_drm_ipp_get_property(struct drm_device *drm_dev, void *data,
					 struct drm_file *file);
extern int sprd_drm_ipp_set_property(struct drm_device *drm_dev, void *data,
					 struct drm_file *file);
extern int sprd_drm_ipp_queue_buf(struct drm_device *drm_dev, void *data,
					 struct drm_file *file);
extern int sprd_drm_ipp_cmd_ctrl(struct drm_device *drm_dev, void *data,
					 struct drm_file *file);
extern int sprd_drm_ippnb_register(struct notifier_block *nb);
extern int sprd_drm_ippnb_unregister(struct notifier_block *nb);
extern int sprd_drm_ippnb_send_event(unsigned long val, void *v);
extern void ipp_sched_cmd(struct work_struct *work);
extern void ipp_sched_event(struct drm_sprd_ipp_event_info *ipp_event);

#else
static inline int sprd_drm_ippdrv_register(struct sprd_drm_ippdrv *ippdrv)
{
	return -ENODEV;
}

static inline int sprd_drm_ippdrv_unregister(struct sprd_drm_ippdrv *ippdrv)
{
	return -ENODEV;
}

static inline int sprd_drm_ipp_get_property(struct drm_device *drm_dev,
						void *data,
						struct drm_file *file_priv)
{
	return -ENOTTY;
}

static inline int sprd_drm_ipp_set_property(struct drm_device *drm_dev,
						void *data,
						struct drm_file *file_priv)
{
	return -ENOTTY;
}

static inline int sprd_drm_ipp_queue_buf(struct drm_device *drm_dev,
						void *data,
						struct drm_file *file)
{
	return -ENOTTY;
}

static inline int sprd_drm_ipp_cmd_ctrl(struct drm_device *drm_dev,
						void *data,
						struct drm_file *file)
{
	return -ENOTTY;
}

static inline int sprd_drm_ippnb_register(struct notifier_block *nb)
{
	return -ENODEV;
}

static inline int sprd_drm_ippnb_unregister(struct notifier_block *nb)
{
	return -ENODEV;
}

static inline int sprd_drm_ippnb_send_event(unsigned long val, void *v)
{
	return -ENOTTY;
}
#endif

#endif /* _SPRD_DRM_IPP_H_ */

