/*
 * Copyright (C) 2013 Spreadtrum Communications Inc.
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

#ifndef _SPRD_DRM_IRQ_H_
#define _SPRD_DRM_IRQ_H_
#include "drmP.h"
#include "sprd_drm.h"
#include <mach/irqs.h>
#include <linux/types.h>

#define ONE_MICRO_SEC 1000000
#define VBLANK_INTERVAL(x) (ONE_MICRO_SEC / (x))
#define VBLANK_DEF_HZ	60
#define VBLANK_LIMIT	20

irqreturn_t sprd_drm_irq_handler(DRM_IRQ_ARGS);
int sprd_drm_irq_init(struct drm_device *dev, unsigned long flags);
int sprd_drm_irq_uninit(struct drm_device *dev);
u32 sprd_drm_get_vblank_counter(struct drm_device *dev, int crtc);
int sprd_prepare_vblank(struct drm_device *dev, int crtc, struct drm_file *file_priv);
int sprd_enable_vblank(struct drm_device *dev, int crtc);
void sprd_disable_vblank(struct drm_device *dev, int crtc);
void sprd_drm_handle_vblank(struct drm_device *dev, int crtc);
int sprd_drm_notifier_ctrl(struct notifier_block *this,
			unsigned long cmd, void *_data);
int sprd_drm_cpuidle_notify(struct notifier_block *nb, unsigned long event, void *dummy);
void sprd_drm_fake_vblank_handler(struct work_struct *work);
int sprd_drm_vblank_freq_show(struct device *dev, struct device_attribute *attr, char *buf);
int sprd_drm_vblank_freq_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t len);

#endif/* _SPRD_DRM_IRQ_H_ */
