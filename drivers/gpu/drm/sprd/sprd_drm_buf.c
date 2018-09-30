/* sprd_drm_buf.c
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
#include "drm.h"
#include "sprd_drm.h"
#include "video/ion_sprd.h"
#include "sprd_drm_drv.h"
#include "sprd_drm_gem.h"
#include "sprd_drm_buf.h"

static int lowlevel_buffer_allocate(struct drm_device *dev,
		unsigned int flags, struct sprd_drm_gem_buf *buf)
{
	struct scatterlist *sg = NULL;
	struct sprd_drm_private *private;
	unsigned int nr_pages = 0, i = 0, heap_id_mask;
	unsigned long sgt_size = 0;
	int ret = 0, mem_flags = 0;

	DRM_DEBUG_KMS("%s\n", __FILE__);

	if (buf->dma_addr) {
		DRM_DEBUG_KMS("already allocated.\n");
		return 0;
	}

	buf->page_size = buf->size;
	private = dev->dev_private;
	DRM_DEBUG_KMS("sprd_drm_ion_client:%p size:0x%lx\n",
			private->sprd_drm_ion_client, buf->size);

	if (IS_DEV_SYSTEM_BUFFER(flags))
		heap_id_mask = ION_HEAP_ID_MASK_SYSTEM;
	else if (IS_DEV_MM_BUFFER(flags))
		heap_id_mask = ION_HEAP_ID_MASK_MM;
	else if (IS_DEV_OVERLAY_BUFFER(flags))
		heap_id_mask = ION_HEAP_ID_MASK_OVERLAY;
	else if (IS_DEV_GSP_BUFFER(flags))
		heap_id_mask = ION_HEAP_ID_MASK_GSP;
	else
		heap_id_mask = ION_HEAP_ID_MASK_OVERLAY;

#ifdef CONFIG_SPRD_IOMMU
	if (IS_NONCONTIG_BUFFER(flags)) {
		if (heap_id_mask == ION_HEAP_ID_MASK_MM)
			heap_id_mask = ION_HEAP_ID_MASK_MM_IOMMU;
		else if (heap_id_mask == ION_HEAP_ID_MASK_GSP)
			heap_id_mask = ION_HEAP_ID_MASK_GSP_IOMMU;
		else
			heap_id_mask = ION_HEAP_ID_MASK_SYSTEM;
	}
#endif

	if (IS_CACHABLE_BUFFER(flags))
		mem_flags = ION_FLAG_CACHED;

	buf->ion_handle = ion_alloc(private->sprd_drm_ion_client, buf->size,
			SZ_4K, heap_id_mask, mem_flags);

	if (IS_ERR((void *)buf->ion_handle)) {
		DRM_ERROR("%s Could not allocate\n", __func__);
		return -ENOMEM;
	}
	buf->sgt = ion_sg_table(private->sprd_drm_ion_client, buf->ion_handle);
	if (!buf->sgt) {
		DRM_ERROR("failed to get sg table.\n");
		ret = -ENOMEM;
		goto err;
	}

	buf->dma_addr = sg_dma_address(buf->sgt->sgl);
	if (!buf->dma_addr) {
		DRM_ERROR("failed to get dma addr.\n");
		ret = -EINVAL;
		goto err;
	}
	for_each_sg(buf->sgt->sgl, sg, buf->sgt->nents, i)
		nr_pages++;

	sgt_size = sizeof(struct page) * nr_pages;
	buf->pages = kzalloc(sgt_size, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
	if (!buf->pages) {
		unsigned int order;
		order = get_order(sgt_size);
		DRM_INFO("%s:sglist kzalloc failed: order:%d, trying vzalloc\n",
					__func__, order);
		buf->pages = vzalloc(sgt_size);
		if (!buf->pages) {
			DRM_ERROR("failed to allocate pages.\n");
			ret = -ENOMEM;
			goto err;
		}
	}

	for_each_sg(buf->sgt->sgl, sg, buf->sgt->nents, i) {
		buf->pages[i] = phys_to_page(sg_dma_address(sg));
		buf->page_size = sg_dma_len(sg);
        }

	DRM_DEBUG_KMS("dma_addr(0x%lx), size(0x%lx)\n",
			(unsigned long)buf->dma_addr,
			buf->size);

	return ret;
err:
	ion_free(private->sprd_drm_ion_client, buf->ion_handle);
	buf->dma_addr = (dma_addr_t)NULL;
	buf->sgt = NULL;

	return ret;
}

static void lowlevel_buffer_deallocate(struct drm_device *dev,
		unsigned int flags, struct sprd_drm_gem_buf *buf)
{
	struct sprd_drm_private *private;

	private = dev->dev_private;
	DRM_DEBUG_KMS("%s.\n", __FILE__);

	if (is_vmalloc_addr(buf->pages))
		vfree(buf->pages);
	else
		kfree(buf->pages);
	buf->pages = NULL;

	ion_free(private->sprd_drm_ion_client, buf->ion_handle);

	buf->dma_addr = (dma_addr_t)NULL;
	buf->sgt = NULL;
}

struct sprd_drm_gem_buf *sprd_drm_init_buf(struct drm_device *dev,
						unsigned int size)
{
	struct sprd_drm_gem_buf *buffer;

	DRM_DEBUG_KMS("%s.\n", __FILE__);
	DRM_DEBUG_KMS("desired size = 0x%x\n", size);

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		DRM_ERROR("failed to allocate sprd_drm_gem_buf.\n");
		return NULL;
	}

	buffer->size = size;
	return buffer;
}

void sprd_drm_fini_buf(struct drm_device *dev,
				struct sprd_drm_gem_buf *buffer)
{
	DRM_DEBUG_KMS("%s.\n", __FILE__);

	if (!buffer) {
		DRM_DEBUG_KMS("buffer is null.\n");
		return;
	}

	kfree(buffer);
	buffer = NULL;
}

int sprd_drm_alloc_buf(struct drm_device *dev,
		struct sprd_drm_gem_buf *buf, unsigned int flags)
{

	/*
	 * allocate memory region and set the memory information
	 * to vaddr and dma_addr of a buffer object.
	 */
	if (lowlevel_buffer_allocate(dev, flags, buf) < 0)
		return -ENOMEM;

	return 0;
}

void sprd_drm_free_buf(struct drm_device *dev,
		unsigned int flags, struct sprd_drm_gem_buf *buffer)
{
	lowlevel_buffer_deallocate(dev, flags, buffer);
}
