/* sprd_drm_buf.h
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

#ifndef _SPRD_DRM_BUF_H_
#define _SPRD_DRM_BUF_H_

/* create and initialize buffer object. */
struct sprd_drm_gem_buf *sprd_drm_init_buf(struct drm_device *dev,
						unsigned int size);

/* destroy buffer object. */
void sprd_drm_fini_buf(struct drm_device *dev,
				struct sprd_drm_gem_buf *buffer);

/* allocate physical memory region and setup sgt and pages. */
int sprd_drm_alloc_buf(struct drm_device *dev,
				struct sprd_drm_gem_buf *buf,
				unsigned int flags);

/* release physical memory region, sgt and pages. */
void sprd_drm_free_buf(struct drm_device *dev,
				unsigned int flags,
				struct sprd_drm_gem_buf *buffer);

#endif
