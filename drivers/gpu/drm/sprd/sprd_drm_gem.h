/* sprd_drm_gem.h
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

#ifndef _SPRD_DRM_GEM_H_
#define _SPRD_DRM_GEM_H_

#define to_sprd_gem_obj(x)	container_of(x,\
			struct sprd_drm_gem_obj, base)

#define IS_NONCONTIG_BUFFER(f)		(f & SPRD_BO_NONCONTIG)
#define IS_CACHABLE_BUFFER(f)           (f & SPRD_BO_CACHABLE)
#define IS_NONCACHABLE_BUFFER(f)	(f & SPRD_BO_NONCACHABLE)

#define IS_DEV_SYSTEM_BUFFER(f)				(f & SPRD_BO_DEV_SYSTEM)
#define IS_DEV_MM_BUFFER(f)				(f & SPRD_BO_DEV_MM)
#define IS_DEV_OVERLAY_BUFFER(f)		(f & SPRD_BO_DEV_OVERLAY)
#define IS_DEV_GSP_BUFFER(f)			(f & SPRD_BO_DEV_GSP)

#define ENTRY_EMPTY -1
#define DRM_SPRD_HANDLE_WAIT_ENTRIES 10
#define SPRD_DRM_GEM_MAX_INDEX_ADDR 3

extern struct drm_device *sprd_drm_dev;

/*
 * sprd drm gem buffer structure.
 *
 * @dma_addr: bus address(accessed by dma) to allocated memory region.
 *	- this address could be physical address without IOMMU and
 *	device address with IOMMU.
 * @sgt: sg table to transfer page data.
 * @pages: contain all pages to allocated memory region.
 * @page_size: could be 4K, 64K or 1MB.
 * @size: size of allocated memory region.
 */
struct sprd_drm_gem_buf {
	dma_addr_t		dma_addr;
	struct sg_table		*sgt;
	struct page		**pages;
	unsigned long		page_size;
	unsigned long		size;
	struct ion_handle	*ion_handle;
	bool			pfnmap;
	unsigned int		bufcount;
	dma_addr_t		idx_addr[SPRD_DRM_GEM_MAX_INDEX_ADDR];
};

struct drm_sprd_gem_object_wait_list_entry {
        struct list_head list;
        int pid;
        int in_use;
        wait_queue_head_t process_wait_q;
};

/*
 * sprd drm buffer structure.
 *
 * @base: a gem object.
 *	- a new handle to this gem object would be created
 *	by drm_gem_handle_create().
 * @buffer: a pointer to sprd_drm_gem_buffer object.
 *	- contain the information to memory region allocated
 *	by user request or at framebuffer creation.
 *	continuous memory region allocated by user request
 *	or at framebuffer creation.
 * @size: total memory size to physically non-continuous memory region.
 * @flags: indicate memory type to allocated buffer and cache attruibute.
 *
 * P.S. this object would be transfered to user as kms_bo.handle so
 *	user can access the buffer through kms_bo.handle.
 */
struct sprd_drm_gem_obj {
	struct drm_gem_object		base;
	struct sprd_drm_gem_buf	*buffer;
	unsigned long			size;
	unsigned int			flags;

        int lockpid;
        struct drm_sprd_gem_object_wait_list_entry
        wait_entries[DRM_SPRD_HANDLE_WAIT_ENTRIES];

        struct list_head wait_list;
};

struct page **sprd_gem_get_pages(struct drm_gem_object *obj, gfp_t gfpmask);

/* destroy a buffer with gem object */
void sprd_drm_gem_destroy(struct sprd_drm_gem_obj *sprd_gem_obj);

/* create a private gem object and initialize it. */
struct sprd_drm_gem_obj *sprd_drm_gem_init(struct drm_device *dev,
						      unsigned long size);

/* create a new buffer with gem object */
struct sprd_drm_gem_obj *sprd_drm_gem_create(struct drm_device *dev,
						struct sprd_drm_gem_index *args);

/*
 * request gem object creation and buffer allocation as the size
 * that it is calculated with framebuffer information such as width,
 * height and bpp.
 */
int sprd_drm_gem_create_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv);
int sprd_drm_gem_create_index_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv);

int sprd_drm_gem_prime_handle_to_fd(struct drm_device *dev,
		struct drm_file *file_priv, uint32_t handle, uint32_t flags,
		int *prime_fd);

int sprd_drm_gem_prime_fd_to_handle(struct drm_device *dev,
		struct drm_file *file_priv, int prime_fd, uint32_t *handle);


/*
 * get dma address from gem handle and this function could be used for
 * other drivers such as 2d/3d acceleration drivers.
 * with this function call, gem object reference count would be increased.
 */
void *sprd_drm_gem_get_dma_addr(struct drm_device *dev,
					unsigned int gem_handle,
					struct drm_file *file_priv);

/*
 * put dma address from gem handle and this function could be used for
 * other drivers such as 2d/3d acceleration drivers.
 * with this function call, gem object reference count would be decreased.
 */
void sprd_drm_gem_put_dma_addr(struct drm_device *dev,
					unsigned int gem_handle,
					struct drm_file *file_priv);

unsigned long sprd_drm_gem_get_size(struct drm_device *dev,
						unsigned int gem_handle,
						struct drm_file *file_priv);

void *sprd_drm_gem_get_obj_addr(unsigned int name, unsigned int index);

/* get buffer offset to map to user space. */
int sprd_drm_gem_map_offset_ioctl(struct drm_device *dev, void *data,
				    struct drm_file *file_priv);

/*
 * mmap the physically continuous memory that a gem object contains
 * to user space.
 */
int sprd_drm_gem_mmap_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);

/* get buffer information to memory region allocated by gem. */
int sprd_drm_gem_get_ioctl(struct drm_device *dev, void *data,
				      struct drm_file *file_priv);

/* initialize gem object. */
int sprd_drm_gem_init_object(struct drm_gem_object *obj);

/* free gem object. */
void sprd_drm_gem_free_object(struct drm_gem_object *gem_obj);

/* create memory region for drm framebuffer. */
int sprd_drm_gem_dumb_create(struct drm_file *file_priv,
			       struct drm_device *dev,
			       struct drm_mode_create_dumb *args);

/* map memory region for drm framebuffer to user space. */
int sprd_drm_gem_dumb_map_offset(struct drm_file *file_priv,
				   struct drm_device *dev, uint32_t handle,
				   uint64_t *offset);

/*
 * destroy memory region allocated.
 *	- a gem handle and physical memory region pointed by a gem object
 *	would be released by drm_gem_handle_delete().
 */
int sprd_drm_gem_dumb_destroy(struct drm_file *file_priv,
				struct drm_device *dev,
				unsigned int handle);

/* page fault handler and mmap fault address(virtual) to physical memory. */
int sprd_drm_gem_fault(struct vm_area_struct *vma, struct vm_fault *vmf);

/* set vm_flags and we can change the vm attribute to other one at here. */
int sprd_drm_gem_mmap(struct file *filp, struct vm_area_struct *vma);

void init_fence(void);

int sprd_gem_lock_handle_ioctl(struct drm_device *dev, void *data, struct drm_file *file_priv);

int sprd_gem_unlock_handle_ioctl(struct drm_device *dev, void *data, struct drm_file *file_priv);

int sprd_gem_cache_op_ioctl(struct drm_device *dev, void *data, struct drm_file *file_priv);

int sprd_drm_gem_mmap_iommu_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv);

int sprd_drm_gem_unmap_iommu_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv);
#endif
