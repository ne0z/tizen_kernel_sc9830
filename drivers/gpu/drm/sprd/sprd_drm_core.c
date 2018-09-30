/* sprd_drm_core.c
 *
 * Copyright (c) 2014 Spreadtrum Communications, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "drmP.h"
#include "sprd_drm_drv.h"

static LIST_HEAD(sprd_drm_subdrv_list);
struct drm_device *sprd_drm_dev;

static int sprd_drm_subdrv_probe(struct drm_device *dev,
					struct sprd_drm_subdrv *subdrv)
{
	DRM_DEBUG_DRIVER("%s\n", __FILE__);

	if (subdrv->probe) {
		int ret;

		/*
		 * this probe callback would be called by sub driver
		 * after setting of all resources to this sub driver,
		 * such as clock, irq and register map are done or by load()
		 * of sprd drm driver.
		 *
		 * P.S. note that this driver is considered for modularization.
		 */
		ret = subdrv->probe(dev, subdrv->dev);
		if (ret)
			return ret;
	}

	return 0;
}

static void sprd_drm_subdrv_remove(struct drm_device *dev,
				      struct sprd_drm_subdrv *subdrv)
{
	DRM_DEBUG_DRIVER("%s\n", __FILE__);

	if (subdrv->remove)
		subdrv->remove(dev, subdrv->dev);
}

int sprd_drm_device_register(struct drm_device *dev)
{
	struct sprd_drm_subdrv *subdrv, *n;
	int err;

	DRM_DEBUG_DRIVER("%s\n", __FILE__);

	if (!dev)
		return -EINVAL;

	sprd_drm_dev = dev;

	list_for_each_entry_safe(subdrv, n, &sprd_drm_subdrv_list, list) {
		subdrv->drm_dev = dev;
		err = sprd_drm_subdrv_probe(dev, subdrv);
		if (err) {
			DRM_DEBUG("sprd drm subdrv probe failed.\n");
			list_del(&subdrv->list);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(sprd_drm_device_register);

int sprd_drm_device_unregister(struct drm_device *dev)
{
	struct sprd_drm_subdrv *subdrv;

	DRM_DEBUG_DRIVER("%s\n", __FILE__);

	if (!dev) {
		WARN(1, "Unexpected drm device unregister!\n");
		return -EINVAL;
	}

	list_for_each_entry(subdrv, &sprd_drm_subdrv_list, list)
		sprd_drm_subdrv_remove(dev, subdrv);

	sprd_drm_dev = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(sprd_drm_device_unregister);

int sprd_drm_subdrv_register(struct sprd_drm_subdrv *subdrv)
{
	DRM_DEBUG_DRIVER("%s\n", __FILE__);

	if (!subdrv)
		return -EINVAL;

	list_add_tail(&subdrv->list, &sprd_drm_subdrv_list);

	return 0;
}
EXPORT_SYMBOL_GPL(sprd_drm_subdrv_register);

int sprd_drm_subdrv_unregister(struct sprd_drm_subdrv *subdrv)
{
	DRM_DEBUG_DRIVER("%s\n", __FILE__);

	if (!subdrv)
		return -EINVAL;

	list_del(&subdrv->list);

	return 0;
}
EXPORT_SYMBOL_GPL(sprd_drm_subdrv_unregister);

int sprd_drm_subdrv_open(struct drm_device *dev, struct drm_file *file)
{
	struct sprd_drm_subdrv *subdrv;
	int ret;

	list_for_each_entry(subdrv, &sprd_drm_subdrv_list, list) {
		if (subdrv->open) {
			ret = subdrv->open(dev, subdrv->dev, file);
			if (ret)
				goto err;
		}
	}

	return 0;

err:
	list_for_each_entry_reverse(subdrv, &subdrv->list, list) {
		if (subdrv->close)
			subdrv->close(dev, subdrv->dev, file);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sprd_drm_subdrv_open);

void sprd_drm_subdrv_close(struct drm_device *dev, struct drm_file *file)
{
	struct sprd_drm_subdrv *subdrv;

	list_for_each_entry(subdrv, &sprd_drm_subdrv_list, list) {
		if (subdrv->close)
			subdrv->close(dev, subdrv->dev, file);
	}
}
EXPORT_SYMBOL_GPL(sprd_drm_subdrv_close);
