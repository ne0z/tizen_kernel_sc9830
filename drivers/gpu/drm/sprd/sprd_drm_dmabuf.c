/* sprd_drm_dmabuf.c
 *
 * Copyright (c) 2012 Spreadtrum Electronics Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "drmP.h"
#include "drm.h"
#include "sprd_drm_drv.h"
#include "sprd_drm_gem.h"

#include <linux/fcntl.h>
#include <linux/dma-buf.h>

static struct sg_table *sprd_pages_to_sg(struct page **pages, int nr_pages,
		unsigned int page_size)
{
	struct sg_table *sgt = NULL;
	struct scatterlist *sgl;
	int i, ret;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		goto out;

	ret = sg_alloc_table(sgt, nr_pages, GFP_KERNEL);
	if (ret)
		goto err_free_sgt;

	if (page_size < PAGE_SIZE)
		page_size = PAGE_SIZE;

	for_each_sg(sgt->sgl, sgl, nr_pages, i)
		sg_set_page(sgl, pages[i], page_size, 0);

	return sgt;

err_free_sgt:
	kfree(sgt);
	sgt = NULL;
out:
	return NULL;
}

static struct sg_table *
		sprd_gem_map_dma_buf(struct dma_buf_attachment *attach,
					enum dma_data_direction dir)
{
	struct sprd_drm_gem_obj *gem_obj = attach->dmabuf->priv;
	struct drm_device *dev = gem_obj->base.dev;
	struct sprd_drm_gem_buf *buf;
	struct sg_table *sgt = NULL;
	unsigned int npages;
	int nents;

	DRM_DEBUG_PRIME("%s\n", __FILE__);

	mutex_lock(&dev->struct_mutex);

	buf = gem_obj->buffer;

	/* there should always be pages allocated. */
	if (!buf->pages) {
		DRM_ERROR("pages is null.\n");
		goto err_unlock;
	}

	npages = buf->size / buf->page_size;

	sgt = sprd_pages_to_sg(buf->pages, npages, buf->page_size);
	nents = dma_map_sg(attach->dev, sgt->sgl, sgt->nents, dir);

	DRM_DEBUG_PRIME("npages = %d buffer size = 0x%lx page_size = 0x%lx\n",
			npages, buf->size, buf->page_size);

err_unlock:
	mutex_unlock(&dev->struct_mutex);
	return sgt;
}

static void sprd_gem_unmap_dma_buf(struct dma_buf_attachment *attach,
						struct sg_table *sgt,
						enum dma_data_direction dir)
{
	dma_unmap_sg(attach->dev, sgt->sgl, sgt->nents, dir);
	sg_free_table(sgt);
	kfree(sgt);
	sgt = NULL;
}

static void sprd_dmabuf_release(struct dma_buf *dmabuf)
{
	struct sprd_drm_gem_obj *sprd_gem_obj = dmabuf->priv;

	DRM_DEBUG_PRIME("%s\n", __FILE__);

	/*
	 * sprd_dmabuf_release() call means that file object's
	 * f_count is 0 and it calls drm_gem_object_handle_unreference()
	 * to drop the references that these values had been increased
	 * at drm_prime_handle_to_fd()
	 */
	if (sprd_gem_obj->base.export_dma_buf == dmabuf) {
		sprd_gem_obj->base.export_dma_buf = NULL;

		/*
		 * drop this gem object refcount to release allocated buffer
		 * and resources.
		 */
		drm_gem_object_unreference_unlocked(&sprd_gem_obj->base);
	}
}

static void *sprd_gem_dmabuf_kmap_atomic(struct dma_buf *dma_buf,
						unsigned long page_num)
{
	struct sprd_drm_gem_obj *sprd_gem_obj = dma_buf->priv;
	struct sprd_drm_gem_buf *buf = sprd_gem_obj->buffer;
	return kmap_atomic(buf->pages[page_num]);
}

static void sprd_gem_dmabuf_kunmap_atomic(struct dma_buf *dma_buf,
						unsigned long page_num,
						void *addr)
{
	kunmap_atomic(addr);
}

static void *sprd_gem_dmabuf_kmap(struct dma_buf *dma_buf,
					unsigned long page_num)
{
	struct sprd_drm_gem_obj *sprd_gem_obj = dma_buf->priv;
	struct sprd_drm_gem_buf *buf = sprd_gem_obj->buffer;
 
	return kmap(buf->pages[page_num]);
}

static void sprd_gem_dmabuf_kunmap(struct dma_buf *dma_buf,
					unsigned long page_num, void *addr)
{
	struct sprd_drm_gem_obj *sprd_gem_obj = dma_buf->priv;
	struct sprd_drm_gem_buf *buf = sprd_gem_obj->buffer;

	kunmap(buf->pages[page_num]);
}

static int sprd_gem_dmabuf_mmap(struct dma_buf *dma_buf, struct vm_area_struct *vma)
{
	struct sprd_drm_gem_obj *sprd_gem_obj = dma_buf->priv;
	struct drm_device *dev = sprd_gem_obj->base.dev;
	struct sprd_drm_gem_buf *buf = sprd_gem_obj->buffer;
	int ret = 0;
	if (WARN_ON(!sprd_gem_obj->base.filp))
		return -EINVAL;

	/* Check for valid size. */
	if (buf->size < vma->vm_end - vma->vm_start) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!dev->driver->gem_vm_ops) {
		ret = -EINVAL;
		goto out_unlock;
	}

	vma->vm_flags |= VM_IO | VM_MIXEDMAP | VM_DONTEXPAND;
	vma->vm_ops = dev->driver->gem_vm_ops;
	vma->vm_private_data = sprd_gem_obj;
	vma->vm_page_prot =  pgprot_writecombine(vm_get_page_prot(vma->vm_flags));

	/* Take a ref for this mapping of the object, so that the fault
	 * handler can dereference the mmap offset's pointer to the object.
	 * This reference is cleaned up by the corresponding vm_close
	 * (which should happen whether the vma was created by this call, or
	 * by a vm_open due to mremap or partial unmap or whatever).
	 */
	vma->vm_ops->open(vma);

out_unlock:
	return ret;
}

static struct dma_buf_ops sprd_dmabuf_ops = {
	.map_dma_buf		= sprd_gem_map_dma_buf,
	.unmap_dma_buf		= sprd_gem_unmap_dma_buf,
	.kmap			= sprd_gem_dmabuf_kmap,
	.kmap_atomic		= sprd_gem_dmabuf_kmap_atomic,
	.kunmap			= sprd_gem_dmabuf_kunmap,
	.kunmap_atomic		= sprd_gem_dmabuf_kunmap_atomic,
	.mmap			= sprd_gem_dmabuf_mmap,
	.release		= sprd_dmabuf_release,
};

struct dma_buf *sprd_dmabuf_prime_export(struct drm_device *drm_dev,
				struct drm_gem_object *obj, int flags)
{
	struct sprd_drm_gem_obj *sprd_gem_obj = to_sprd_gem_obj(obj);

	return dma_buf_export(sprd_gem_obj, &sprd_dmabuf_ops,
				sprd_gem_obj->base.size, O_RDWR);
}

struct drm_gem_object *sprd_dmabuf_prime_import(struct drm_device *drm_dev,
				struct dma_buf *dma_buf)
{
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct scatterlist *sgl;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_buf *buffer;
	struct page *page;
	unsigned long sgt_size = 0;
	int ret, i = 0;

	DRM_DEBUG_PRIME("%s\n", __FILE__);

	/* is this one of own objects? */
	if (dma_buf->ops == &sprd_dmabuf_ops) {
		struct drm_gem_object *obj;

		sprd_gem_obj = dma_buf->priv;
		obj = &sprd_gem_obj->base;

		/* is it from our device? */
		if (obj->dev == drm_dev) {
			drm_gem_object_reference(obj);
			return obj;
		}
	}

	attach = dma_buf_attach(dma_buf, drm_dev->dev);
	if (IS_ERR(attach))
		return ERR_PTR(-EINVAL);


	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto err_buf_detach;
	}

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		DRM_ERROR("failed to allocate sprd_drm_gem_buf.\n");
		ret = -ENOMEM;
		goto err_unmap_attach;
	}
	sgt_size = sizeof(*page) * sgt->nents;
	buffer->pages = kzalloc(sgt_size, GFP_KERNEL | __GFP_NOWARN);
	if (!buffer->pages) {
		unsigned int order;
		order = get_order(sgt_size);
		DRM_ERROR("%s: kzalloc failed for sg list: order:%d\n",
						__func__, order);
		buffer->pages = vzalloc(sgt_size);
		if (!buffer->pages) {
			DRM_ERROR("failed to allocate pages.\n");
			ret = -ENOMEM;
			goto err_free_buffer;
		}
	}

	sprd_gem_obj = sprd_drm_gem_init(drm_dev, dma_buf->size);
	if (!sprd_gem_obj) {
		ret = -ENOMEM;
		goto err_free_pages;
	}

	sgl = sgt->sgl;
	buffer->dma_addr = sg_dma_address(sgl);

	while (i < sgt->nents) {
		buffer->pages[i] = sg_page(sgl);
		buffer->size += sg_dma_len(sgl);
		sgl = sg_next(sgl);
		i++;
	}

	sprd_gem_obj->buffer = buffer;
	buffer->sgt = sgt;
	sprd_gem_obj->base.import_attach = attach;

	DRM_DEBUG_PRIME("dma_addr = 0x%x, size = 0x%lx\n", buffer->dma_addr,
								buffer->size);

	return &sprd_gem_obj->base;

err_free_pages:
	if (is_vmalloc_addr(buffer->pages))
		vfree(buffer->pages);
	else
		kfree(buffer->pages);
	buffer->pages = NULL;
err_free_buffer:
	kfree(buffer);
	buffer = NULL;
err_unmap_attach:
	dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);
err_buf_detach:
	dma_buf_detach(dma_buf, attach);
	return ERR_PTR(ret);
}

MODULE_AUTHOR("Rohit");
MODULE_DESCRIPTION("Spreadtrum SoC DRM DMABUF Module");
MODULE_LICENSE("GPL");
