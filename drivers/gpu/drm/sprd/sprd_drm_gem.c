/* sprd_drm_gem.c
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

#include <linux/shmem_fs.h>
#include <drm/sprd_drm.h>
#include <linux/sprd_iommu.h>

#include "video/ion_sprd.h"
#include "sprd_drm_drv.h"
#include "sprd_drm_gem.h"
#include "sprd_drm_buf.h"

static unsigned int convert_to_vm_err_msg(int msg)
{
	unsigned int out_msg;

	switch (msg) {
	case 0:
	case -ERESTARTSYS:
	case -EINTR:
		out_msg = VM_FAULT_NOPAGE;
		break;

	case -ENOMEM:
		out_msg = VM_FAULT_OOM;
		break;

	default:
		out_msg = VM_FAULT_SIGBUS;
		break;
	}

	return out_msg;
}

static int check_gem_flags(unsigned int flags)
{
	if (flags & ~(SPRD_BO_MASK | SPRD_BO_DEV_MASK))
		goto err;

#ifdef CONFIG_SPRD_IOMMU
	if (IS_NONCONTIG_BUFFER(flags)) {
		 if (IS_DEV_OVERLAY_BUFFER(flags))
			goto err;
	} else {
		 if (IS_DEV_SYSTEM_BUFFER(flags))
			goto err;
	}
#endif

	return 0;
err:
	DRM_ERROR("invalid flags[0x%x]\n", flags);
	return -EINVAL;
}

static void update_vm_cache_attr(struct sprd_drm_gem_obj *obj,
					struct vm_area_struct *vma)
{
	DRM_DEBUG_KMS("flags = 0x%x\n", obj->flags);

	/* non-cachable as default. */
	if (obj->flags & SPRD_BO_CACHABLE)
		vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	else if (obj->flags & SPRD_BO_WC)
		vma->vm_page_prot =
			pgprot_writecombine(vm_get_page_prot(vma->vm_flags));
	else
		vma->vm_page_prot =
			pgprot_noncached(vm_get_page_prot(vma->vm_flags));
}

static unsigned long roundup_gem_size(unsigned long size, unsigned int flags)
{
	if (!IS_NONCONTIG_BUFFER(flags)) {
#ifndef CONFIG_CMA_ALIGNMENT
		if (size >= SZ_1M)
			return roundup(size, SECTION_SIZE);
#endif
		/* ToDo: need to sync with additional align size */
		if (size >= SZ_64K)
			return roundup(size, SZ_64K);
		else
			goto out;
	}
out:
	return roundup(size, PAGE_SIZE);
}

struct page **sprd_gem_get_pages(struct drm_gem_object *obj,
						gfp_t gfpmask)
{
	struct inode *inode;
	struct address_space *mapping;
	struct page *p, **pages;
	int i, npages;

	/* This is the shared memory object that backs the GEM resource */
	inode = obj->filp->f_path.dentry->d_inode;
	mapping = inode->i_mapping;

	npages = obj->size >> PAGE_SHIFT;

	pages = drm_malloc_ab(npages, sizeof(struct page *));
	if (pages == NULL)
		return ERR_PTR(-ENOMEM);

	gfpmask |= mapping_gfp_mask(mapping);

	for (i = 0; i < npages; i++) {
		p = shmem_read_mapping_page_gfp(mapping, i, gfpmask);
		if (IS_ERR(p))
			goto fail;
		pages[i] = p;
	}

	return pages;

fail:
	while (i--)
		page_cache_release(pages[i]);

	drm_free_large(pages);
	return ERR_PTR(PTR_ERR(p));
}

static int sprd_drm_gem_map_pages(struct drm_gem_object *obj,
					struct vm_area_struct *vma,
					unsigned long f_vaddr,
					pgoff_t page_offset)
{
	struct sprd_drm_gem_obj *sprd_gem_obj = to_sprd_gem_obj(obj);
	struct sprd_drm_gem_buf *buf = sprd_gem_obj->buffer;
	unsigned long pfn;

	if (sprd_gem_obj->flags & SPRD_BO_NONCONTIG) {
		if (!buf->pages)
			return -EINTR;

		pfn = page_to_pfn(buf->pages[page_offset++]);
	} else
		pfn = (buf->dma_addr >> PAGE_SHIFT) + page_offset;

	return vm_insert_mixed(vma, f_vaddr, pfn);
}

static int sprd_drm_gem_handle_create(struct drm_gem_object *obj,
					struct drm_file *file_priv,
					unsigned int *handle)
{
	int ret;

	/*
	 * allocate a id of idr table where the obj is registered
	 * and handle has the id what user can see.
	 */
	ret = drm_gem_handle_create(file_priv, obj, handle);
	if (ret)
		return ret;

	DRM_DEBUG_KMS("gem handle = 0x%x\n", *handle);

	/* drop reference from allocate - handle holds it now. */
	drm_gem_object_unreference_unlocked(obj);

	return 0;
}

void sprd_drm_gem_destroy(struct sprd_drm_gem_obj *sprd_gem_obj)
{
	struct drm_gem_object *obj;
	struct sprd_drm_gem_buf *buf;

	obj = &sprd_gem_obj->base;
	buf = sprd_gem_obj->buffer;

	if (!buf->pages)
		return;

	DRM_INFO("%s:o[0x%x]a[0x%x]\n", "gf",
		(int)obj, (int)sprd_gem_obj->buffer->dma_addr);

	sprd_drm_free_buf(obj->dev, sprd_gem_obj->flags, buf);

	sprd_drm_fini_buf(obj->dev, buf);
	sprd_gem_obj->buffer = NULL;

	if (obj->map_list.map)
		drm_gem_free_mmap_offset(obj);

	/* release file pointer to gem object. */
	drm_gem_object_release(obj);

	kfree(sprd_gem_obj);
	sprd_gem_obj = NULL;
}

struct sprd_drm_gem_obj *sprd_drm_gem_init(struct drm_device *dev,
						      unsigned long size)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_gem_object *obj;
	int ret;

	sprd_gem_obj = kzalloc(sizeof(*sprd_gem_obj), GFP_KERNEL);
	if (!sprd_gem_obj) {
		DRM_ERROR("failed to allocate sprd gem object\n");
		return NULL;
	}

	sprd_gem_obj->size = size;
	obj = &sprd_gem_obj->base;

	ret = drm_gem_object_init(dev, obj, size);
	if (ret < 0) {
		DRM_ERROR("failed to initialize gem object\n");
		kfree(sprd_gem_obj);
		return NULL;
	}

	DRM_DEBUG_KMS("created file object = 0x%x\n", (unsigned int)obj->filp);

	return sprd_gem_obj;
}

struct sprd_drm_gem_obj *sprd_drm_gem_create(struct drm_device *dev,
						struct sprd_drm_gem_index *args)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_buf *buf;
	int ret, i=0, j, tsize = 0;

	ret = check_gem_flags(args->flags);
	if (ret)
		return ERR_PTR(ret);

	/* ToDo: need to check align */
	for (i = 0; i < args->bufcount; i++)
		tsize += args->idx_size[i];

	if (!tsize) {
		DRM_ERROR("invalid size.\n");
		return ERR_PTR(-EINVAL);
	}

	tsize = roundup_gem_size(tsize, args->flags);

	buf = sprd_drm_init_buf(dev, tsize);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	sprd_gem_obj = sprd_drm_gem_init(dev, tsize);
	if (!sprd_gem_obj) {
		ret = -ENOMEM;
		goto err_fini_buf;
	}

	sprd_gem_obj->buffer = buf;

	/* set memory type and cache attribute from user side. */
	sprd_gem_obj->flags = args->flags;

	ret = sprd_drm_alloc_buf(dev, buf, args->flags);
	if (ret < 0)
		goto err_gem_fini;

	memset(buf->idx_addr, 0x00, sizeof(buf->idx_addr));
	buf->idx_addr[0] = buf->dma_addr;
	buf->bufcount = args->bufcount;

	for (i = 0; i < buf->bufcount; i++) {
		j = i + 1;
		if (buf->bufcount > j)
			buf->idx_addr[j] = buf->idx_addr[i] + args->idx_size[i];
	}

	sprd_gem_obj->lockpid=0;
	INIT_LIST_HEAD(&sprd_gem_obj->wait_list);

	for (i = 0; i < DRM_SPRD_HANDLE_WAIT_ENTRIES; i++) {
		INIT_LIST_HEAD((struct list_head *) &sprd_gem_obj->wait_entries[i]);
		sprd_gem_obj->wait_entries[i].pid = 0;
		init_waitqueue_head(&sprd_gem_obj->wait_entries[i].process_wait_q);
	}

	return sprd_gem_obj;

err_gem_fini:
	drm_gem_object_release(&sprd_gem_obj->base);
	kfree(sprd_gem_obj);
err_fini_buf:
	sprd_drm_fini_buf(dev, buf);
	return ERR_PTR(ret);
}

int sprd_drm_gem_create_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv)
{
	struct drm_sprd_gem_create *args = data;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_index gem_idx;
	struct timeval val_start, val_end;
	uint64_t time_start, time_end;
	int ret;

	do_gettimeofday(&val_start);
	time_start = (uint64_t)(val_start.tv_sec * 1000000 + val_start.tv_usec);

	gem_idx.bufcount= 1;
	gem_idx.idx_size[0] = args->size;
	gem_idx.flags = args->flags;

	sprd_gem_obj = sprd_drm_gem_create(dev, &gem_idx);
	if (IS_ERR(sprd_gem_obj)) {
		DRM_ERROR("failed to sprd_drm_gem_create:s[%d]f[0x%x]\n",
			(int)args->size, args->flags);
		return PTR_ERR(sprd_gem_obj);
	}

	ret = sprd_drm_gem_handle_create(&sprd_gem_obj->base, file_priv,
			&args->handle);
	if (ret) {
		DRM_ERROR("failed to sprd_drm_gem_handle_create:s[%d]f[0x%x]\n",
			(int)args->size, args->flags);
		sprd_drm_gem_destroy(sprd_gem_obj);
		return ret;
	}

	do_gettimeofday(&val_end);
	time_end = (uint64_t)(val_end.tv_sec * 1000000 + val_end.tv_usec);

	DRM_INFO("%s:h[%d]s[%d]f[0x%x]o[0x%x]a[0x%x][%lld us]\n",
		"ga",args->handle, (int)args->size, args->flags,
		(int)&sprd_gem_obj->base,
		(int)sprd_gem_obj->buffer->dma_addr, time_end - time_start);

	return 0;
}

int sprd_drm_gem_create_index_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv)
{
	struct sprd_drm_gem_index *args = data;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	int ret;

	if (args->flags & SPRD_BO_NONCONTIG) {
		DRM_ERROR("does not support non-contig memory\n");
		return -EINVAL;
	}

	sprd_gem_obj = sprd_drm_gem_create(dev, args);
	if (IS_ERR(sprd_gem_obj))
		return PTR_ERR(sprd_gem_obj);

	ret = sprd_drm_gem_handle_create(&sprd_gem_obj->base, file_priv,
			&args->handle);
	if (ret) {
		sprd_drm_gem_destroy(sprd_gem_obj);
		return ret;
	}

	DRM_INFO("%s:h[%d]cnt[%d]sz[%d %d %d]f[0x%x]o[0x%x]a[0x%x]\n",
		__func__,args->handle, args->bufcount,
		(int)args->idx_size[0], (int)args->idx_size[1], (int)args->idx_size[2],
		args->flags, (int)&sprd_gem_obj->base,
		(int)sprd_gem_obj->buffer->dma_addr);

	return 0;
}

int sprd_drm_gem_prime_handle_to_fd(struct drm_device *dev,
		struct drm_file *file_priv, uint32_t handle,
		uint32_t flags, int *prime_fd)
{
	int ret = 0;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_gem_object *obj;
	struct sprd_drm_gem_buf *buf;
	struct sprd_drm_private *private;

	if (!handle) {
		DRM_ERROR("%s: Handle to fd failed. Null handle\n", __func__);
		return -EINVAL;
	}

	obj = drm_gem_object_lookup(dev, file_priv, handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object.\n");
		return -EINVAL;
	}

	private = dev->dev_private;
	sprd_gem_obj = to_sprd_gem_obj(obj);
	buf = sprd_gem_obj->buffer;
	*prime_fd = ion_share_dma_buf_fd(private->sprd_drm_ion_client,
					buf->ion_handle);
	drm_gem_object_unreference_unlocked(obj);

	if (*prime_fd == -EINVAL) {
		prime_fd = NULL;
		return -EINVAL;
	}

	return ret;
}

int sprd_drm_gem_prime_fd_to_handle(struct drm_device *dev,
		struct drm_file *file_priv, int prime_fd, uint32_t *handle)
{
	struct ion_handle *ion_handle;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	unsigned long size;
	struct sprd_drm_gem_buf *buf = NULL;
	unsigned int i = 0, nr_pages = 0, heap_id;
	int ret = 0, gem_handle;
	struct sprd_drm_private *private;
	struct scatterlist *sg = NULL;
	struct drm_gem_object *obj;
	unsigned long sgt_size;

	private = dev->dev_private;
	ion_handle = ion_import_dma_buf(private->sprd_drm_ion_client, prime_fd);
	if (IS_ERR_OR_NULL(ion_handle)) {
		DRM_ERROR("Unable to import dmabuf\n");
		return -EINVAL;
	}

	ion_handle_get_size(private->sprd_drm_ion_client,
					ion_handle, &size, &heap_id);
	if (size == 0) {
		DRM_ERROR(
			"cannot create GEM object from zero size ION buffer\n");
		ret = -EINVAL;
		goto err;
	}

	buf = sprd_drm_init_buf(dev, size);
	if (!buf) {
		DRM_ERROR("Unable to allocate the GEM buffer\n");
		ret = -ENOMEM;
		goto err;
	}

	sprd_gem_obj = sprd_drm_gem_init(dev, size);
	if (!sprd_gem_obj) {
		DRM_ERROR("Unable to initialize GEM object\n");
		ret = -ENOMEM;
		goto err_fini_buf;
	}
	sprd_gem_obj->buffer = buf;
	obj = &sprd_gem_obj->base;

	ret = ion_is_phys(private->sprd_drm_ion_client, ion_handle);
	if (ret == -1)
		sprd_gem_obj->flags = SPRD_BO_NONCONTIG;
	else if (ret == 0)
		sprd_gem_obj->flags = SPRD_BO_CONTIG;
	else {
		DRM_ERROR("Unable to get flag, Invalid handle\n");
		goto err_gem_obj;
	}

	/* ion_handle is validated in ion_is_phys, no need to check again */
	ret = ion_is_cached(private->sprd_drm_ion_client, ion_handle);
	if (ret)
		sprd_gem_obj->flags |= SPRD_BO_CACHABLE;

	if ((heap_id == ION_HEAP_ID_MASK_GSP) || (heap_id == ION_HEAP_ID_MASK_GSP_IOMMU))
		sprd_gem_obj->flags |= SPRD_BO_DEV_GSP;
	else if ((heap_id == ION_HEAP_ID_MASK_MM) || (heap_id == ION_HEAP_ID_MASK_MM_IOMMU))
		sprd_gem_obj->flags |= SPRD_BO_DEV_MM;
	else if (heap_id == ION_HEAP_ID_MASK_OVERLAY)
		sprd_gem_obj->flags |= SPRD_BO_DEV_OVERLAY;
	else if (heap_id == ION_HEAP_ID_MASK_SYSTEM)
		sprd_gem_obj->flags |= SPRD_BO_DEV_SYSTEM;
	else {
		DRM_ERROR("Heap id not supported\n");
		ret = -ENOMEM;
		goto err_gem_obj;
	}

	buf->ion_handle = ion_handle;
	buf->sgt = ion_sg_table(private->sprd_drm_ion_client, buf->ion_handle);
	if (!buf->sgt) {
		DRM_ERROR("failed to allocate sg table.\n");
		ret = -EINVAL;
		goto err_gem_obj;
	}

	buf->dma_addr = sg_dma_address(buf->sgt->sgl);
	for_each_sg(buf->sgt->sgl, sg, buf->sgt->nents, i)
		nr_pages++;

	sgt_size = sizeof(struct page) * nr_pages;
	buf->pages = kzalloc(sgt_size, GFP_KERNEL | __GFP_NOWARN);
	if (!buf->pages) {
		unsigned int order;
		order = get_order(sgt_size);
		DRM_ERROR("%s: kzalloc failed for sg list: order:%d\n",
					__func__, order);
		buf->pages = vzalloc(sgt_size);
		if (!buf->pages) {
			DRM_ERROR("failed to allocate pages.\n");
			ret = -ENOMEM;
			goto err_buf;
		}
	}

	for_each_sg(buf->sgt->sgl, sg, buf->sgt->nents, i)
		buf->pages[i] = phys_to_page(sg_dma_address(sg));

	DRM_DEBUG_KMS("dma_addr(0x%lx), size(0x%lx)\n",
		(unsigned long)buf->dma_addr, buf->size);

	ret = sprd_drm_gem_handle_create(&sprd_gem_obj->base, file_priv,
					&gem_handle);
	if (ret) {
		sprd_drm_gem_destroy(sprd_gem_obj);
		return ret;
	}
	*handle = gem_handle;
	return 0;

err_buf:
	buf->dma_addr = (dma_addr_t)NULL;
	buf->sgt = NULL;
err_gem_obj:
	sprd_gem_obj->buffer = NULL;
	/* release file pointer to gem object. */
	drm_gem_object_release(obj);
	kfree(sprd_gem_obj);
	sprd_gem_obj = NULL;
err_fini_buf:
	sprd_drm_fini_buf(dev, buf);
err:
	ion_free(private->sprd_drm_ion_client, ion_handle);

	return ret;
}

void *sprd_drm_gem_get_dma_addr(struct drm_device *dev,
					unsigned int gem_handle,
					struct drm_file *file_priv)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_gem_object *obj;
	struct ion_handle *ion_handle;
	struct sprd_drm_gem_buf *buf;
	int domain_num = 0;

	obj = drm_gem_object_lookup(dev, file_priv, gem_handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object:h[%d]\n", gem_handle);
		return ERR_PTR(-EINVAL);
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);

	if (sprd_gem_obj->flags & SPRD_BO_NONCONTIG) {
		buf = sprd_gem_obj->buffer;
		if (IS_DEV_MM_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_MM;
		else if (IS_DEV_GSP_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_GSP;

		ion_handle = buf->ion_handle;
		if (sprd_map_iommu(ion_handle, domain_num,
				(unsigned long *)&sprd_gem_obj->buffer->dma_addr)) {
			DRM_ERROR("failed to map iommu:h[%d]o[0x%x]\n",
				gem_handle, (int)obj);
			drm_gem_object_unreference_unlocked(obj);
			return ERR_PTR(-EINVAL);
		}
	}

	DRM_DEBUG("%s:h[%d]o[0x%x]a[0x%x]\n",
		__func__,gem_handle, (int)obj,
		(int)sprd_gem_obj->buffer->dma_addr);

	return &sprd_gem_obj->buffer->dma_addr;
}

void sprd_drm_gem_put_dma_addr(struct drm_device *dev,
					unsigned int gem_handle,
					struct drm_file *file_priv)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_gem_object *obj;
	struct ion_handle *ion_handle;
	struct sprd_drm_gem_buf *buf;
	int domain_num = 0;

	obj = drm_gem_object_lookup(dev, file_priv, gem_handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object:h[%d]\n", gem_handle);
		return;
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);

	if (sprd_gem_obj->flags & SPRD_BO_NONCONTIG) {
		buf = sprd_gem_obj->buffer;
		if (IS_DEV_MM_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_MM;
		else if (IS_DEV_GSP_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_GSP;

		ion_handle = buf->ion_handle;
		if (sprd_unmap_iommu(ion_handle, domain_num))
			DRM_ERROR("failed to unmap iommu:h[%d]o[0x%x]\n",
				gem_handle, (int)obj);
	}

	drm_gem_object_unreference_unlocked(obj);

	DRM_DEBUG("%s:h[%d]o[0x%x]\n",
		__func__,gem_handle, (int)obj);
	/*
	 * decrease obj->refcount one more time because we has already
	 * increased it at sprd_drm_gem_get_dma_addr().
	 */
	drm_gem_object_unreference_unlocked(obj);
}

unsigned long sprd_drm_gem_get_size(struct drm_device *dev,
						unsigned int gem_handle,
						struct drm_file *file_priv)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_gem_object *obj;

	obj = drm_gem_object_lookup(dev, file_priv, gem_handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object:h[%d]\n", gem_handle);
		return 0;
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);

	drm_gem_object_unreference_unlocked(obj);

	return sprd_gem_obj->buffer->size;
}

void *sprd_drm_gem_get_obj_addr(unsigned int name, unsigned int index)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_gem_object *obj;
	struct ion_handle *ion_handle;
	struct sprd_drm_gem_buf *buf;
	int domain_num = 0;

	spin_lock(&sprd_drm_dev->object_name_lock);
	obj = idr_find(&sprd_drm_dev->object_name_idr, (int) name);
	spin_unlock(&sprd_drm_dev->object_name_lock);

	if (!obj) {
		DRM_ERROR("name[%d]failed to lookup gem object.\n", name);
		return ERR_PTR(-EFAULT);
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);
	buf = sprd_gem_obj->buffer;

	if (index >= buf->bufcount) {
		DRM_ERROR("invalid index[%d],bufcount[%d]\n",
			index, buf->bufcount);
		return ERR_PTR(-EINVAL);
	}

	if (sprd_gem_obj->flags & SPRD_BO_NONCONTIG) {
		if (IS_DEV_MM_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_MM;
		else if (IS_DEV_GSP_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_GSP;

		ion_handle = buf->ion_handle;
		if (sprd_map_iommu(ion_handle, domain_num,
				(unsigned long *)&sprd_gem_obj->buffer->dma_addr)) {
			DRM_ERROR("failed to map iommu\n");
			return ERR_PTR(-EINVAL);
		}
	}

	DRM_DEBUG("%s:name[%d]o[0x%x]idx[%d]a[0x%x]\n",
		__func__, name, (int)obj, index, (int)buf->idx_addr[index]);

	return &buf->idx_addr[index];
}
EXPORT_SYMBOL(sprd_drm_gem_get_obj_addr);

int sprd_drm_gem_map_offset_ioctl(struct drm_device *dev, void *data,
				    struct drm_file *file_priv)
{
	struct drm_sprd_gem_map_off *args = data;

	DRM_DEBUG_KMS("handle = 0x%x, offset = 0x%lx\n",
			args->handle, (unsigned long)args->offset);

	if (!(dev->driver->driver_features & DRIVER_GEM)) {
		DRM_ERROR("does not support GEM.\n");
		return -ENODEV;
	}

	return sprd_drm_gem_dumb_map_offset(file_priv, dev, args->handle,
			&args->offset);
}

static int sprd_drm_gem_mmap_buffer(struct file *filp,
				      struct vm_area_struct *vma)
{
	struct drm_gem_object *obj = filp->private_data;
	struct sprd_drm_gem_obj *sprd_gem_obj = to_sprd_gem_obj(obj);
	struct sprd_drm_gem_buf *buffer;
	unsigned long pfn, vm_size;

	vma->vm_flags |= (VM_IO | VM_DONTEXPAND | VM_DONTDUMP);

	update_vm_cache_attr(sprd_gem_obj, vma);

	vm_size = vma->vm_end - vma->vm_start;

	/*
	 * a buffer contains information to physically continuous memory
	 * allocated by user request or at framebuffer creation.
	 */
	buffer = sprd_gem_obj->buffer;

	/* check if user-requested size is valid. */
	if (vm_size > buffer->size)
		return -EINVAL;

	if (sprd_gem_obj->flags & SPRD_BO_NONCONTIG) {
		unsigned long addr = vma->vm_start;
		unsigned long offset = vma->vm_pgoff * PAGE_SIZE;
		struct scatterlist *sg;
		int i;

		for_each_sg(buffer->sgt->sgl, sg, buffer->sgt->nents, i) {
			struct page *page = sg_page(sg);
			unsigned long remainder = vma->vm_end - addr;
			unsigned long len = sg_dma_len(sg);

			if (offset >= sg_dma_len(sg)) {
				offset -= sg_dma_len(sg);
				continue;
			} else if (offset) {
				page += offset / PAGE_SIZE;
				len = sg_dma_len(sg) - offset;
				offset = 0;
			}
			len = min(len, remainder);
			remap_pfn_range(vma, addr, page_to_pfn(page), len,
					vma->vm_page_prot);
			addr += len;
			if (addr >= vma->vm_end) {
				break;
			}
		}
	} else {
		/*
		 * get page frame number to physical memory to be mapped
		 * to user space.
		 */
		pfn = ((unsigned long)sprd_gem_obj->buffer->dma_addr) >>
								PAGE_SHIFT;

		DRM_DEBUG_KMS("pfn = 0x%lx\n", pfn);

		if (remap_pfn_range(vma, vma->vm_start, pfn, vm_size,
					vma->vm_page_prot)) {
			DRM_ERROR("failed to remap pfn range.\n");
			return -EAGAIN;
		}
	}

	return 0;
}

static const struct file_operations sprd_drm_gem_fops = {
	.mmap = sprd_drm_gem_mmap_buffer,
};

int sprd_drm_gem_mmap_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv)
{
	struct drm_sprd_gem_mmap *args = data;
	struct drm_gem_object *obj;
	unsigned long addr;

	if (!(dev->driver->driver_features & DRIVER_GEM)) {
		DRM_ERROR("does not support GEM.\n");
		return -ENODEV;
	}

	obj = drm_gem_object_lookup(dev, file_priv, args->handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object:h[%d]\n", args->handle);
		return -EINVAL;
	}

	obj->filp->f_op = &sprd_drm_gem_fops;
	obj->filp->private_data = obj;

	addr = vm_mmap(obj->filp, 0, args->size,
			PROT_READ | PROT_WRITE, MAP_SHARED, 0);

	drm_gem_object_unreference_unlocked(obj);

	if (IS_ERR_VALUE(addr))
		return (int)addr;

	args->mapped = addr;

	DRM_DEBUG("%s:h[%d]s[%d]o[0x%x]mapped[0x%x]\n", __func__,
		args->handle, (int)args->size, (int)obj, (int)args->mapped);

	return 0;
}

int sprd_drm_gem_mmap_iommu_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv)
{
	struct drm_sprd_gem_mmap *args = data;
	struct drm_gem_object *obj;
	struct ion_handle *ion_handle;
	unsigned long addr;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_buf *buf;
	int domain_num = 0;

	if (!(dev->driver->driver_features & DRIVER_GEM)) {
		DRM_ERROR("does not support GEM.\n");
		return -ENODEV;
	}

	obj = drm_gem_object_lookup(dev, file_priv, args->handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object.\n");
		return -EINVAL;
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);
	buf = sprd_gem_obj->buffer;
	if (sprd_gem_obj->flags & SPRD_BO_NONCONTIG) {
		if (IS_DEV_MM_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_MM;
		else if (IS_DEV_GSP_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_GSP;

		ion_handle = buf->ion_handle;
		sprd_map_iommu(ion_handle, domain_num, &addr);
	} else {
		DRM_ERROR("MMAP_IOMMU not applicable on CONTIG HEAP\n");
		drm_gem_object_unreference_unlocked(obj);
		return -EINVAL;
	}

	args->mapped = addr;
	return 0;
}

int sprd_drm_gem_unmap_iommu_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file_priv)
{
	struct drm_sprd_gem_mmap *args = data;
	struct drm_gem_object *obj;
	struct ion_handle *ion_handle;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_buf *buf;
	int ret = 0, domain_num = 0;

	if (!(dev->driver->driver_features & DRIVER_GEM)) {
		DRM_ERROR("does not support GEM.\n");
		return -ENODEV;
	}

	obj = drm_gem_object_lookup(dev, file_priv, args->handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object.\n");
		return -EINVAL;
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);
	buf = sprd_gem_obj->buffer;
	if (sprd_gem_obj->flags & SPRD_BO_NONCONTIG) {
		if (IS_DEV_MM_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_MM;
		else if (IS_DEV_GSP_BUFFER(sprd_gem_obj->flags))
			domain_num = IOMMU_GSP;

		ion_handle = buf->ion_handle;
		sprd_unmap_iommu(ion_handle, domain_num);
	} else {
		DRM_ERROR("UNMAP_IOMMU not applicable on CONTIG HEAP\n");
		ret = -EINVAL;
	}

	drm_gem_object_unreference_unlocked(obj);
	/*
	 * decrease obj->refcount one more time because we has already
	 * increased it at sprd_drm_gem_mmap_iommu_ioctl().
	 */
	drm_gem_object_unreference_unlocked(obj);
	return ret;
}

int sprd_drm_gem_get_ioctl(struct drm_device *dev, void *data,
				      struct drm_file *file_priv)
{	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_sprd_gem_info *args = data;
	struct drm_gem_object *obj;

	mutex_lock(&dev->struct_mutex);

	obj = drm_gem_object_lookup(dev, file_priv, args->handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object.\n");
		mutex_unlock(&dev->struct_mutex);
		return -EINVAL;
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);

	args->flags = sprd_gem_obj->flags;
	args->size = sprd_gem_obj->size;

	drm_gem_object_unreference(obj);
	mutex_unlock(&dev->struct_mutex);

	return 0;
}

int sprd_drm_gem_init_object(struct drm_gem_object *obj)
{
	return 0;
}

void sprd_drm_gem_free_object(struct drm_gem_object *obj)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_buf *buf;

	sprd_gem_obj = to_sprd_gem_obj(obj);
	buf = sprd_gem_obj->buffer;

	if (obj->import_attach)
		drm_prime_gem_destroy(obj, buf->sgt);

	sprd_drm_gem_destroy(to_sprd_gem_obj(obj));
}

int sprd_drm_gem_dumb_create(struct drm_file *file_priv,
			       struct drm_device *dev,
			       struct drm_mode_create_dumb *args)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_index gem_idx;
	int ret;

	/*
	 * alocate memory to be used for framebuffer.
	 * - this callback would be called by user application
	 *	with DRM_IOCTL_MODE_CREATE_DUMB command.
	 */

	args->pitch = args->width * args->bpp >> 3;
	args->size = PAGE_ALIGN(args->pitch * args->height);

	gem_idx.bufcount= 1;
	gem_idx.idx_size[0] = args->size;
	gem_idx.flags = args->flags;

	sprd_gem_obj = sprd_drm_gem_create(dev, &gem_idx);
	if (IS_ERR(sprd_gem_obj))
		return PTR_ERR(sprd_gem_obj);

	ret = sprd_drm_gem_handle_create(&sprd_gem_obj->base, file_priv,
			&args->handle);
	if (ret) {
		sprd_drm_gem_destroy(sprd_gem_obj);
		return ret;
	}

	return 0;
}

int sprd_drm_gem_dumb_map_offset(struct drm_file *file_priv,
				   struct drm_device *dev, uint32_t handle,
				   uint64_t *offset)
{
	struct drm_gem_object *obj;
	int ret = 0;

	mutex_lock(&dev->struct_mutex);

	/*
	 * get offset of memory allocated for drm framebuffer.
	 * - this callback would be called by user application
	 *	with DRM_IOCTL_MODE_MAP_DUMB command.
	 */

	obj = drm_gem_object_lookup(dev, file_priv, handle);
	if (!obj) {
		DRM_ERROR("failed to lookup gem object.\n");
		ret = -EINVAL;
		goto unlock;
	}

	if (!obj->map_list.map) {
		ret = drm_gem_create_mmap_offset(obj);
		if (ret)
			goto out;
	}

	*offset = (u64)obj->map_list.hash.key << PAGE_SHIFT;
	DRM_DEBUG_KMS("offset = 0x%lx\n", (unsigned long)*offset);

out:
	drm_gem_object_unreference(obj);
unlock:
	mutex_unlock(&dev->struct_mutex);
	return ret;
}

int sprd_drm_gem_dumb_destroy(struct drm_file *file_priv,
				struct drm_device *dev,
				unsigned int handle)
{
	int ret;

	/*
	 * obj->refcount and obj->handle_count are decreased and
	 * if both them are 0 then sprd_drm_gem_free_object()
	 * would be called by callback to release resources.
	 */
	ret = drm_gem_handle_delete(file_priv, handle);
	if (ret < 0) {
		DRM_ERROR("failed to delete drm_gem_handle.\n");
		return ret;
	}

	return 0;
}

int sprd_drm_gem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct drm_gem_object *obj = vma->vm_private_data;
	struct drm_device *dev = obj->dev;
	unsigned long f_vaddr;
	pgoff_t page_offset;
	int ret;

	page_offset = ((unsigned long)vmf->virtual_address -
			vma->vm_start) >> PAGE_SHIFT;
	f_vaddr = (unsigned long)vmf->virtual_address;

	mutex_lock(&dev->struct_mutex);

	ret = sprd_drm_gem_map_pages(obj, vma, f_vaddr, page_offset);
	if (ret < 0)
		DRM_ERROR("failed to map pages.\n");

	mutex_unlock(&dev->struct_mutex);

	return convert_to_vm_err_msg(ret);
}

int sprd_drm_gem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_gem_object *obj;
	int ret;

	/* set vm_area_struct. */
	ret = drm_gem_mmap(filp, vma);
	if (ret < 0) {
		DRM_ERROR("failed to mmap.\n");
		return ret;
	}

	obj = vma->vm_private_data;
	sprd_gem_obj = to_sprd_gem_obj(obj);

	ret = check_gem_flags(sprd_gem_obj->flags);
	if (ret) {
		drm_gem_vm_close(vma);
		drm_gem_free_mmap_offset(obj);
		return ret;
	}

	vma->vm_flags &= ~VM_PFNMAP;
	vma->vm_flags |= VM_MIXEDMAP;

	update_vm_cache_attr(sprd_gem_obj, vma);

	return ret;
}

int sprd_gem_lock_handle_ioctl(struct drm_device *dev, void *data,
                                      struct drm_file *file_priv)
{
	struct drm_sprd_gem_lock_handle *args = data;
	struct drm_gem_object *obj;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct drm_sprd_gem_object_wait_list_entry *lock_item;
	int i;
	int result = 0;

	DRM_DEBUG_DRIVER("%s line:%d\n", __func__, __LINE__);
	mutex_lock(&dev->struct_mutex);

	obj = drm_gem_object_lookup(dev, file_priv, args->handle);

	if (obj == NULL) {
		DRM_ERROR("Invalid GEM handle %x\n", args->handle);
		result = -EBADF;
		goto out_unlock;
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);

	if (sprd_gem_obj->lockpid) {
		/* if a pid already had it locked */
		/* create and add to wait list */
		for (i = 0; i < DRM_SPRD_HANDLE_WAIT_ENTRIES; i++) {
			if (sprd_gem_obj->wait_entries[i].in_use == 0) {
				/* this one is empty */
				lock_item = &sprd_gem_obj->wait_entries[i];
				lock_item->in_use = 1;
				lock_item->pid = args->pid;
				INIT_LIST_HEAD((struct list_head *)
						&sprd_gem_obj->wait_entries[i]);
				break;
			}
		}

		if (i == DRM_SPRD_HANDLE_WAIT_ENTRIES) {

			result =  -EFAULT;
			drm_gem_object_unreference(obj);
			goto out_unlock;
		}
		list_add_tail((struct list_head *)&lock_item->list,
				&sprd_gem_obj->wait_list);
		mutex_unlock(&dev->struct_mutex);
		/* here we need to block */
		wait_event_interruptible_timeout(
				sprd_gem_obj->wait_entries[i].process_wait_q,
				(sprd_gem_obj->lockpid == 0),
				msecs_to_jiffies(20000));
		mutex_lock(&dev->struct_mutex);
		lock_item->in_use = 0;
	}
	sprd_gem_obj->lockpid = args->pid;
	DRM_DEBUG_DRIVER("%s lockpid:%d\n", __func__, sprd_gem_obj->lockpid);

out_unlock:
	mutex_unlock(&dev->struct_mutex);

	return result;
}

int sprd_gem_unlock_handle_ioctl(struct drm_device *dev, void *data,
                                      struct drm_file *file_priv)
{

	struct drm_sprd_gem_unlock_handle *args = data;
	struct drm_gem_object *obj;
	struct sprd_drm_gem_obj *unlock_obj;
	struct drm_sprd_gem_object_wait_list_entry *lock_next;
	int result = 0;

	DRM_DEBUG_DRIVER("%s line:%d\n", __func__, __LINE__);
	mutex_lock(&dev->struct_mutex);

	obj = drm_gem_object_lookup(dev, file_priv, args->handle);

	if (obj == NULL) {
		DRM_ERROR("Invalid GEM handle %x\n", args->handle);
		result = -EBADF;
		goto out_unlock;
	}

	unlock_obj = to_sprd_gem_obj(obj);
	if (!list_empty(&unlock_obj->wait_list)) {
		lock_next =
			(struct drm_sprd_gem_object_wait_list_entry *)
			unlock_obj->wait_list.prev;

		list_del((struct list_head *)&lock_next->list);

		unlock_obj->lockpid = 0;
		wake_up_interruptible(
				&lock_next->process_wait_q);
		lock_next->pid = 0;

	} else {
		/* List is empty so set pid to 0 */
		unlock_obj->lockpid = 0;
	}
	drm_gem_object_unreference(obj);

	drm_gem_object_unreference(obj);
out_unlock:
	mutex_unlock(&dev->struct_mutex);

	return result;
}

int sprd_gem_cache_op_ioctl(struct drm_device *dev, void *data,
                                      struct drm_file *file_priv)
{
	struct drm_sprd_gem_cache_op *args = data;
	int result = 0;
	struct drm_gem_object *obj;
	struct sprd_drm_gem_obj *sprd_gem_obj;
	struct sprd_drm_gem_buf *buf;
	struct sg_table         *sgt;
	unsigned int cache_op = args->flags &(~SPRD_DRM_ALL_CACHE);

	mutex_lock(&dev->struct_mutex);
	obj = drm_gem_object_lookup(dev, file_priv, args->gem_handle);

	if (obj == NULL) {
		DRM_ERROR("invalid handle[%d]\n", args->gem_handle);
		result = -EBADF;
		goto err_invalid_handle;
	}

	sprd_gem_obj = to_sprd_gem_obj(obj);
	buf = sprd_gem_obj->buffer;
	sgt = buf->sgt;

	DRM_DEBUG("%s:h[%d]s[%d]f[0x%x]a[0x%x]o[0x%x]\n",
		"gc",args->gem_handle, (int)args->size, args->flags,
		(int)args->usr_addr, (int)obj);

	if (!IS_CACHABLE_BUFFER(sprd_gem_obj->flags)) {
		DRM_ERROR("invalid flags[0x%x]for h[%d]\n",
			sprd_gem_obj->flags, args->gem_handle);
		goto out;
	}

	switch (cache_op) {
		case SPRD_DRM_CACHE_INV:
			dma_sync_sg_for_cpu(NULL, sgt->sgl, sgt->nents,
							DMA_FROM_DEVICE);
			break;
		case SPRD_DRM_CACHE_CLN:
			dma_sync_sg_for_device(NULL, sgt->sgl, sgt->nents,
							DMA_TO_DEVICE);
			break;
		case SPRD_DRM_CACHE_FSH:
			dma_sync_sg_for_device(NULL, sgt->sgl, sgt->nents,
							DMA_TO_DEVICE);
			dma_sync_sg_for_cpu(NULL, sgt->sgl, sgt->nents,
							DMA_FROM_DEVICE);
			break;
		default:
			DRM_ERROR("invalid op[0x%x]for h[%d]\n", cache_op, args->gem_handle);
			result = -EINVAL;
			goto out;
	}

out:
	drm_gem_object_unreference(obj);

err_invalid_handle:
	mutex_unlock(&dev->struct_mutex);
	return result;
}
