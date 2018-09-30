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


#include "sprd_drm_irq.h"
#include "sprd_drm_drv.h"
#include <soc/sprd/hardware.h>
#include "sprdfb.h"
#include <soc/sprd/cpuidle.h>

extern struct drm_device *sprd_drm_dev;
extern void panel_esd_enable (bool enable);

#ifdef CONFIG_OF
extern unsigned long g_dispc_base_addr;
#define SPRD_DISPC_BASE				g_dispc_base_addr
#else
#define SPRD_DISPC_BASE				SPRD_LCDC_BASE
#endif
#define IRQ_DISPC_INT				IRQ_DISPC0_INT
#define DISPC_INT_EN				(0x0070)
#define DISPC_INT_CLR				(0x0074)
#define DISPC_INT_STATUS			(0x0078)
#define DISPC_INT_DONE_MASK          BIT(0)
#define DISPC_INT_TE_MASK            BIT(1)
#define DISPC_INT_ERR_MASK           BIT(2)
#define DISPC_INT_EDPI_TE_MASK       BIT(3)
#define DISPC_INT_UPDATE_DONE_MASK   BIT(4)
#define DISPC_INT_DPI_VSYNC_MASK     BIT(5)

#if defined(CONFIG_FB_SCX30G) || defined(CONFIG_FB_SCX35L)
#define DISPC_INT_HWVSYNC DISPC_INT_DPI_VSYNC_MASK
#else
#define DISPC_INT_HWVSYNC DISPC_INT_DONE_MASK
#endif

int sci_write(u32 reg, u32 val, u32 msk)
{
	__raw_writel((__raw_readl(reg) & ~msk) | val, reg);
	return 0;
}

static inline uint32_t dispc_read(uint32_t reg)
{
	return __raw_readl(SPRD_DISPC_BASE + reg) & 0xffffffff;
}

static inline void dispc_write(uint32_t value, uint32_t reg)
{
//      __raw_writel(value, (SPRD_DISPC_BASE + reg));
	sci_write((SPRD_DISPC_BASE + reg), value, 0xffffffff);
}

int sprd_drm_notifier_ctrl(struct notifier_block *this,
			unsigned long cmd, void *_data)
{
	struct drm_device *dev = sprd_drm_dev;
	struct sprd_drm_private *dev_priv;

	struct sprdfb_nb_event *event =
		(struct sprdfb_nb_event *)_data;
	int crtc = 0, ret = NOTIFY_DONE;

	if (!dev) {
		DRM_ERROR("failed to get drm_dev:cmd[%d]crtc[%d]\n",
			(int)cmd, crtc);
		ret = NOTIFY_BAD;
		goto out;
	}

	dev_priv = dev->dev_private;
	dev_priv->dbg_cnt = 2;

	if (atomic_read(&dev->vblank_refcount[crtc]) ||
		dev->vblank_enabled[crtc])
		DRM_INFO("[notifier_%d]cmd[%d]en[%d]r[%d]t[%d]\n",
			crtc, (int)cmd, dev->vblank_enabled[crtc],
			atomic_read(&dev->vblank_refcount[crtc]),
			atomic_read(&dev_priv->vbl_trg_cnt[crtc]));

	switch (cmd) {
	case SPRDFB_SET_DPMS:
		sprd_drm_handle_vblank(dev, crtc);

		switch ((int)event->data) {
		case SPRDFB_DPMS_ON:
			dev_priv->dpms[crtc] = SPRDFB_DPMS_ON;
			break;
		case SPRDFB_DPMS_OFF:
			dev_priv->dpms[crtc] = SPRDFB_DPMS_OFF;

			if (dev->vblank_enabled[crtc])
				drm_vblank_off(dev, crtc );
			break;
		default:
			DRM_ERROR("invalid dpms[%d]\n", (int)event->data);
			ret = NOTIFY_BAD;
			break;
		}
		break;
	default:
		DRM_ERROR("invalid command[%d]\n", (int)cmd);
		ret = NOTIFY_BAD;
		break;
	}

	DRM_INFO("[notifier_%d]cmd[%d]en[%d]r[%d]t[%d][dpms_%s]ret[%d]\n",
		crtc, (int)cmd, dev->vblank_enabled[crtc],
		atomic_read(&dev->vblank_refcount[crtc]),
		atomic_read(&dev_priv->vbl_trg_cnt[crtc]),
		dev_priv->dpms[crtc] == SPRDFB_DPMS_ON ? "on" : "off", ret);
out:
	return ret;
}

/* FIXME:!! when we not clear the register in dispc, phone doesn't bootup */
u32 dispc_int_status;

irqreturn_t sprd_drm_irq_handler(DRM_IRQ_ARGS)
{
	struct drm_device *dev = (struct drm_device *) arg;
	struct sprd_drm_private *dev_priv = dev->dev_private;
	u32 isr, crtc = DRM_CRTC_PRIMARY;

/* FIXME:!! when we not clear the register in dispc, phone doesn't bootup */
#if 0
	isr = dispc_read(DISPC_INT_STATUS);
#endif
	isr = dispc_int_status;

	if (isr == 0)
		goto irq_done;

/* FIXME:!! when we not clear the register in dispc, phone doesn't bootup */
#if 0
	mask = dispc_read(DISPC_INT_EN);
	dispc_write(mask, DISPC_INT_CLR);
#endif

	if (isr & DISPC_INT_HWVSYNC || isr & DISPC_INT_TE_MASK) {
		dispc_int_status = 0;
		sprd_drm_handle_vblank(dev, crtc);
	}

	if (isr & DISPC_INT_UPDATE_DONE_MASK) {
		if (dev_priv->dbg_cnt)
			DRM_INFO("[done_%d]r[%d]t[%d]\n", crtc,
				atomic_read(&dev->vblank_refcount[crtc]),
				atomic_read(&dev_priv->vbl_trg_cnt[crtc]));

		atomic_set(&dev_priv->vbl_trg_cnt[crtc], 0);
	}

irq_done:
	return IRQ_HANDLED;
}

void sprd_drm_handle_vblank(struct drm_device *dev, int crtc)
{
	struct sprd_drm_private *dev_priv =
		(struct sprd_drm_private *)dev->dev_private;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&dev->vbl_lock, flags);

	if (dev_priv->vbl_swap) {
		if (crtc == DRM_CRTC_PRIMARY) {
			DRM_INFO("[hdl_vbl_%d]r[%d]t[%d]bypass\n", crtc,
				atomic_read(&dev->vblank_refcount[crtc]),
				atomic_read(&dev_priv->vbl_trg_cnt[crtc]));
			goto out;
		}
		else if (crtc == DRM_CRTC_FAKE) {
			DRM_INFO("[hdl_vbl_%d]r[%d]t[%d]swap\n", crtc,
				atomic_read(&dev->vblank_refcount[crtc]),
				atomic_read(&dev_priv->vbl_trg_cnt[crtc]));
			crtc = DRM_CRTC_PRIMARY;
		}
	}

	if (atomic_read(&dev->vblank_refcount[crtc]) > 0)  {
		ret = drm_handle_vblank(dev, crtc);

		if (dev_priv->dbg_cnt) {
			DRM_INFO("[wake_vbl_%d]r[%d]t[%d]ret[%d]\n", crtc,
				atomic_read(&dev->vblank_refcount[crtc]),
				atomic_read(&dev_priv->vbl_trg_cnt[crtc]), ret);
			dev_priv->dbg_cnt--;
		}
	}

out:
	spin_unlock_irqrestore(&dev->vbl_lock, flags);
	return;
}

int sprd_prepare_vblank(struct drm_device *dev, int crtc, struct drm_file *file_priv)
{
	struct sprd_drm_private *dev_priv = dev->dev_private;
	int limit = VBLANK_LIMIT;

	if (crtc >= DRM_CRTC_ID_MAX) {
		DRM_ERROR("crtc[%d]\n", crtc);
		return -EINVAL;
	}

	if (file_priv->is_master)
		atomic_set(&dev_priv->vbl_trg_cnt[crtc], 0);
	else
		atomic_inc(&dev_priv->vbl_trg_cnt[crtc]);

	if (dev_priv->dbg_cnt)
		DRM_DEBUG("[pre_vbl_%d]r[%d]t[%d]\n", crtc,
			atomic_read(&dev->vblank_refcount[crtc]),
			atomic_read(&dev_priv->vbl_trg_cnt[crtc]));

	if (atomic_read(&dev_priv->vbl_trg_cnt[crtc]) >= limit) {
		DRM_DEBUG("[limit_vbl_%d]r[%d]t[%d]\n",
			crtc, atomic_read(&dev->vblank_refcount[crtc]),
			atomic_read(&dev_priv->vbl_trg_cnt[crtc]));
		return -EACCES;
	}

	return 0;
}

int sprd_enable_vblank(struct drm_device *dev, int crtc)
{
	struct sprd_drm_private *dev_priv = dev->dev_private;

	if (crtc >= DRM_CRTC_ID_MAX) {
		DRM_ERROR("crtc[%d]\n", crtc);
		return -EINVAL;
	}

	switch (crtc) {
	case DRM_CRTC_PRIMARY:
		if (dev_priv->dpms[crtc] != SPRDFB_DPMS_ON) {
			DRM_DEBUG("[on_vbl_%d]r[%d]t[%d]DPMS_OFF\n",
				crtc, atomic_read(&dev->vblank_refcount[crtc]),
				atomic_read(&dev_priv->vbl_trg_cnt[crtc]));
			return -EPERM;
		}
		break;
	default:
		break;
	}

	DRM_INFO("[on_vbl_%d]r[%d]t[%d]\n", crtc,
		atomic_read(&dev->vblank_refcount[crtc]),
		atomic_read(&dev_priv->vbl_trg_cnt[crtc]));

	dev_priv->dbg_cnt = 2;
#ifdef CONFIG_FB_ESD_SUPPORT
	panel_esd_enable(false);
#endif

	return 0;
}

void sprd_disable_vblank(struct drm_device *dev, int crtc)
{
	struct sprd_drm_private *dev_priv = dev->dev_private;

	if (crtc >= DRM_CRTC_ID_MAX) {
		DRM_ERROR("crtc[%d]\n", crtc);
		return;
	}

	DRM_INFO("[off_vbl_%d]r[%d]t[%d]\n", crtc,
		atomic_read(&dev->vblank_refcount[crtc]),
		atomic_read(&dev_priv->vbl_trg_cnt[crtc]));

	atomic_set(&dev_priv->vbl_trg_cnt[crtc], 0);
#ifdef CONFIG_FB_ESD_SUPPORT
	panel_esd_enable(true);
#endif
}

u32 sprd_drm_get_vblank_counter(struct drm_device *dev, int crtc)
{
	DRM_DEBUG("%s:crtc[%d]\n", __func__, crtc);

	if (crtc >= DRM_CRTC_ID_MAX) {
		DRM_ERROR("crtc[%d]\n", crtc);
		return -EINVAL;
	}

	return drm_vblank_count(dev,crtc);
}

void sprd_drm_fake_vblank_handler(struct work_struct *work)
{
	struct sprd_drm_private *dev_priv = container_of(work,
		struct sprd_drm_private, fake_vbl_work);
	struct drm_device *dev = dev_priv->drm_dev;
	int crtc = DRM_CRTC_FAKE;

	usleep_range(dev_priv->vbl_itv_us, dev_priv->vbl_itv_us + 1000);

	DRM_INFO("[fake_vbl_%d]r[%d]t[%d]\n", crtc,
		atomic_read(&dev->vblank_refcount[crtc]),
		atomic_read(&dev_priv->vbl_trg_cnt[crtc]));

	sprd_drm_handle_vblank(dev, crtc);

	if (dev_priv->vbl_swap)
		schedule_work(&dev_priv->fake_vbl_work);
}

int sprd_drm_cpuidle_notify(struct notifier_block *nb, unsigned long event, void *dummy)
{
	struct drm_device *dev = sprd_drm_dev;
	int crtc = 0, ret = 0, vbl_ref = 0;

	if (!dev) {
		DRM_ERROR("failed to get drm_dev\n");
		ret = NOTIFY_BAD;
		goto out;
	}

	if (event != SC_CPUIDLE_PREPARE){
		DRM_ERROR("invalid cpuidle notify type\n");
		goto out;
	}

	vbl_ref = atomic_read(&dev->vblank_refcount[crtc]);

	if (vbl_ref > 0)
		ret = NOTIFY_BAD;
out:
	DRM_DEBUG("%s:vbl_ref[%d]ret[%d]\n", __func__, vbl_ref, ret);
	return ret;
}

int sprd_drm_vblank_freq_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct drm_device *drm_dev = sprd_drm_dev;
	struct sprd_drm_private *dev_priv = drm_dev->dev_private;
	int freq, ret;

	if (dev_priv->vbl_swap)
		freq = dev_priv->fake_vbl_hz;
	else
		freq = VBLANK_DEF_HZ;

	DRM_INFO("[vbl_freq_get][%d]\n", freq);

	ret = sprintf(buf, "%d\n", freq);

	return ret;
}

int sprd_drm_vblank_freq_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t len)
{
	struct drm_device *drm_dev = sprd_drm_dev;
	struct sprd_drm_private *dev_priv = drm_dev->dev_private;
	int freq, ret;

	ret = kstrtoint(buf, 0, &freq);
	if (ret)
		return ret;

	DRM_INFO("[vbl_freq_set][%d]\n", freq);

	if (freq > VBLANK_DEF_HZ)
		return -EINVAL;

	if (freq == VBLANK_DEF_HZ || freq <= 0) {
		dev_priv->vbl_swap = false;
		dev_priv->fake_vbl_hz = VBLANK_DEF_HZ;
		dev_priv->vbl_itv_us = (unsigned long int)(VBLANK_INTERVAL(VBLANK_DEF_HZ));
	} else {
		dev_priv->vbl_swap = true;
		dev_priv->fake_vbl_hz = freq;
		dev_priv->vbl_itv_us = (unsigned long int)(VBLANK_INTERVAL(freq));
		schedule_work(&dev_priv->fake_vbl_work);
	}

	return len;
}
