/* sprd_drm.h
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 * Authors:
 *	Inki Dae <inki.dae@samsung.com>
 *	Joonyoung Shim <jy0922.shim@samsung.com>
 *	Seung-Woo Kim <sw0312.kim@samsung.com>
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

#ifndef _UAPI_SPRD_DRM_H_
#define _UAPI_SPRD_DRM_H_

#include <drm/drm.h>

#define SPRD_DRM_GEM_MAX_INDEX 3

struct sprd_drm_gem_index {
	unsigned int	bufcount;
	uint64_t	idx_size[SPRD_DRM_GEM_MAX_INDEX];
	unsigned int	flags;
	unsigned int	handle;
};

/**
 * User-desired buffer creation information structure.
 *
 * @size: user-desired memory allocation size.
 *	- this size value would be page-aligned internally.
 * @flags: user request for setting memory type or cache attributes.
 * @handle: returned a handle to created gem object.
 *	- this handle will be set by gem module of kernel side.
 */
struct drm_sprd_gem_create {
	uint64_t size;
	unsigned int flags;
	unsigned int handle;
};

/**
 * A structure for getting buffer offset.
 *
 * @handle: a pointer to gem object created.
 * @pad: just padding to be 64-bit aligned.
 * @offset: relatived offset value of the memory region allocated.
 *	- this value should be set by user.
 */
struct drm_sprd_gem_map_off {
	unsigned int handle;
	unsigned int pad;
	uint64_t offset;
};

/**
 * A structure for mapping buffer.
 *
 * @handle: a handle to gem object created.
 * @pad: just padding to be 64-bit aligned.
 * @size: memory size to be mapped.
 * @mapped: having user virtual address mmaped.
 *	- this variable would be filled by sprd gem module
 *	of kernel side with user virtual address which is allocated
 *	by do_mmap().
 */
struct drm_sprd_gem_mmap {
	unsigned int handle;
	unsigned int pad;
	uint64_t size;
	uint64_t mapped;
};

/**
 * A structure to gem information.
 *
 * @handle: a handle to gem object created.
 * @flags: flag value including memory type and cache attribute and
 *	this value would be set by driver.
 * @size: size to memory region allocated by gem and this size would
 *	be set by driver.
 */
struct drm_sprd_gem_info {
	unsigned int handle;
	unsigned int flags;
	uint64_t size;
};

struct drm_sprd_gem_lock_handle {
        uint32_t handle;
        uint32_t pid;
};

struct drm_sprd_gem_unlock_handle {
        uint32_t handle;
};

/* indicate cache units. */
enum e_drm_sprd_gem_cache_sel {
        SPRD_DRM_L1_CACHE        = 1,
        SPRD_DRM_L2_CACHE        = 2,
        SPRD_DRM_ALL_CACHE        = 3
};

/* indicate cache operation types. */
enum e_drm_sprd_gem_cache_op {
        SPRD_DRM_CACHE_INV        = 4,
        SPRD_DRM_CACHE_CLN        = 8,
        SPRD_DRM_CACHE_FSH        = 0xC
};

/**
 * A structure for cache operation.
 *
 * @usr_addr: user space address.
 *      P.S. it SHOULD BE user space.
 * @size: buffer size for cache operation.
 * @flags: select cache unit and cache operation.
 * @gem_handle: a handle to a gem object.
 *      this gem handle is needed for cache range operation to L2 cache.
 */
struct drm_sprd_gem_cache_op {
        uint64_t usr_addr;
        unsigned int size;
        unsigned int flags;
        unsigned int gem_handle;
};

/* memory type definitions. */
enum e_drm_sprd_gem_mem_type {
	/* Physically Continuous memory and used as default. */
	SPRD_BO_CONTIG	= 0 << 0,
	/* Physically Non-Continuous memory. */
	SPRD_BO_NONCONTIG	= 1 << 0,
	/* non-cachable mapping and used as default. */
	SPRD_BO_NONCACHABLE	= 0 << 1,
	/* cachable mapping. */
	SPRD_BO_CACHABLE	= 1 << 1,
	/* write-combine mapping. */
	SPRD_BO_WC		= 1 << 2,
	SPRD_BO_MASK		= SPRD_BO_NONCONTIG | SPRD_BO_CACHABLE |
					SPRD_BO_WC,

	/* System type */
	SPRD_BO_DEV_SYSTEM = 1 << 16,
	/* Multimedia type */
	SPRD_BO_DEV_MM = 1 << 17,
	/* Overlay type */
	SPRD_BO_DEV_OVERLAY = 1 << 18,
	/* GSP type */
	SPRD_BO_DEV_GSP = 1 << 19,
	SPRD_BO_DEV_MASK	= SPRD_BO_DEV_SYSTEM | SPRD_BO_DEV_MM |
					SPRD_BO_DEV_OVERLAY | SPRD_BO_DEV_GSP,
};

enum drm_sprd_ops_id {
	SPRD_DRM_OPS_SRC,
	SPRD_DRM_OPS_DST,
	SPRD_DRM_OPS_MAX,
};

struct drm_sprd_sz {
	__u32	hsize;
	__u32	vsize;
};

struct drm_sprd_pos {
	__u32	x;
	__u32	y;
	__u32	w;
	__u32	h;
};
enum drm_sprd_flip {
	SPRD_DRM_FLIP_NONE = (0 << 0),
	SPRD_DRM_FLIP_VERTICAL = (1 << 0),
	SPRD_DRM_FLIP_HORIZONTAL = (1 << 1),
	SPRD_DRM_FLIP_BOTH = SPRD_DRM_FLIP_VERTICAL |
			SPRD_DRM_FLIP_HORIZONTAL,
};

enum drm_sprd_degree {
	SPRD_DRM_DEGREE_0,
	SPRD_DRM_DEGREE_90,
	SPRD_DRM_DEGREE_180,
	SPRD_DRM_DEGREE_270,
};

enum drm_sprd_planer {
	SPRD_DRM_PLANAR_Y,
	SPRD_DRM_PLANAR_CB,
	SPRD_DRM_PLANAR_CR,
	SPRD_DRM_PLANAR_MAX,
};

/**
 * A structure for ipp supported property list.
 *
 * @version: version of this structure.
 * @ipp_id: id of ipp driver.
 * @count: count of ipp driver.
 * @writeback: flag of writeback supporting.
 * @flip: flag of flip supporting.
 * @degree: flag of degree information.
 * @csc: flag of csc supporting.
 * @crop: flag of crop supporting.
 * @scale: flag of scale supporting.
 * @refresh_min: min hz of refresh.
 * @refresh_max: max hz of refresh.
 * @crop_min: crop min resolution.
 * @crop_max: crop max resolution.
 * @scale_min: scale min resolution.
 * @scale_max: scale max resolution.
 */
struct drm_sprd_ipp_prop_list {
	__u32	version;
	__u32	ipp_id;
	__u32	count;
	__u32	writeback;
	__u32	flip;
	__u32	degree;
	__u32	csc;
	__u32	crop;
	__u32	scale;
	__u32	refresh_min;
	__u32	refresh_max;
	__u32	reserved;
	struct drm_sprd_sz	crop_min;
	struct drm_sprd_sz	crop_max;
	struct drm_sprd_sz	scale_min;
	struct drm_sprd_sz	scale_max;
};

/**
 * A structure for ipp config.
 *
 * @ops_id: property of operation directions.
 * @flip: property of mirror, flip.
 * @degree: property of rotation degree.
 * @fmt: property of image format.
 * @sz: property of image size.
 * @pos: property of image position(src-cropped,dst-scaler).
 */
struct drm_sprd_ipp_config {
	enum drm_sprd_ops_id ops_id;
	enum drm_sprd_flip	flip;
	enum drm_sprd_degree	degree;
	__u32	fmt;
	struct drm_sprd_sz	sz;
	struct drm_sprd_pos	pos;
};

enum drm_sprd_ipp_cmd {
	IPP_CMD_NONE,
	IPP_CMD_M2M,
	IPP_CMD_WB,
	IPP_CMD_OUTPUT,
	IPP_CMD_MAX,
};

/* define of ipp operation type */
enum drm_sprd_ipp_type {
	IPP_SYNC_WORK = 0x0,
	IPP_EVENT_DRIVEN = 0x1,
	IPP_TYPE_MAX = 0x2,
};

/**
 * A structure for ipp property.
 *
 * @config: source, destination config.
 * @cmd: definition of command.
 * @ipp_id: id of ipp driver.
 * @prop_id: id of property.
 * @refresh_rate: refresh rate.
 * @type: definition of operation type.
 */
struct drm_sprd_ipp_property {
	struct drm_sprd_ipp_config config[SPRD_DRM_OPS_MAX];
	enum drm_sprd_ipp_cmd	cmd;
	__u32	ipp_id;
	__u32	prop_id;
	__u32	refresh_rate;
	enum drm_sprd_ipp_type	type;
};

enum drm_sprd_ipp_buf_type {
	IPP_BUF_ENQUEUE,
	IPP_BUF_DEQUEUE,
};

/**
 * A structure for ipp buffer operations.
 *
 * @ops_id: operation directions.
 * @buf_type: definition of buffer.
 * @prop_id: id of property.
 * @buf_id: id of buffer.
 * @handle: Y, Cb, Cr each planar handle.
 * @user_data: user data.
 */
struct drm_sprd_ipp_queue_buf {
	enum drm_sprd_ops_id	ops_id;
	enum drm_sprd_ipp_buf_type	buf_type;
	__u32	prop_id;
	__u32	buf_id;
	__u32	handle[SPRD_DRM_PLANAR_MAX];
	__u32	reserved;
	__u64	user_data;
};

enum drm_sprd_ipp_ctrl {
	IPP_CTRL_PLAY,
	IPP_CTRL_STOP,
	IPP_CTRL_PAUSE,
	IPP_CTRL_RESUME,
	IPP_CTRL_MAX,
};

/**
 * A structure for ipp start/stop operations.
 *
 * @prop_id: id of property.
 * @ctrl: definition of control.
 */
struct drm_sprd_ipp_cmd_ctrl {
	__u32	prop_id;
	enum drm_sprd_ipp_ctrl	ctrl;
};

#define DRM_SPRD_GEM_CREATE		0x00
#define DRM_SPRD_GEM_MAP_OFFSET	0x01
#define DRM_SPRD_GEM_MMAP		0x02
/* Reserved 0x03 ~ 0x05 for sprd specific gem ioctl */
#define DRM_SPRD_GEM_USERPTR            0x03
#define DRM_SPRD_GEM_GET		0x04
#define DRM_SPRD_GEM_MMAP_IOMMU		0x08
#define DRM_SPRD_GEM_UNMAP_IOMMU	0x09
#define DRM_SPRD_GEM_LOCK_HANDLE 0x0B
#define DRM_SPRD_GEM_UNLOCK_HANDLE 0x0C
#define DRM_SPRD_GEM_CACHE_OP 0x12
#define DRM_SPRD_GEM_INDEX_CREATE 0x13

/* IPP - Image Post Processing */
#define DRM_SPRD_IPP_GET_PROPERTY	0x30
#define DRM_SPRD_IPP_SET_PROPERTY	0x31
#define DRM_SPRD_IPP_QUEUE_BUF	0x32
#define DRM_SPRD_IPP_CMD_CTRL	0x33

#define DRM_IOCTL_SPRD_GEM_CREATE		DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_GEM_CREATE, struct drm_sprd_gem_create)
#define DRM_IOCTL_SPRD_GEM_MAP_OFFSET	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_GEM_MAP_OFFSET, struct drm_sprd_gem_map_off)
#define DRM_IOCTL_SPRD_GEM_MMAP	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_GEM_MMAP, struct drm_sprd_gem_mmap)
#define DRM_IOCTL_SPRD_GEM_MMAP_IOMMU	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_GEM_MMAP_IOMMU, struct drm_sprd_gem_mmap)
#define DRM_IOCTL_SPRD_GEM_UNMAP_IOMMU	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_GEM_UNMAP_IOMMU, struct drm_sprd_gem_mmap)
#define DRM_IOCTL_SPRD_GEM_GET	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_GEM_GET,	struct drm_sprd_gem_info)
#define DRM_IOCTL_SPRD_GEM_LOCK_HANDLE DRM_IOWR(DRM_COMMAND_BASE + \
                DRM_SPRD_GEM_LOCK_HANDLE, struct drm_sprd_gem_lock_handle)
#define DRM_IOCTL_SPRD_GEM_UNLOCK_HANDLE DRM_IOWR(DRM_COMMAND_BASE + \
                DRM_SPRD_GEM_UNLOCK_HANDLE, struct drm_sprd_gem_unlock_handle)
#define DRM_IOCTL_SPRD_GEM_CACHE_OP DRM_IOWR(DRM_COMMAND_BASE + \
                DRM_SPRD_GEM_CACHE_OP, struct drm_sprd_gem_cache_op)
#define DRM_IOCTL_SPRD_GEM_INDEX_CREATE		DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_GEM_INDEX_CREATE, struct sprd_drm_gem_index)

#define DRM_IOCTL_SPRD_IPP_GET_PROPERTY	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_IPP_GET_PROPERTY, struct drm_sprd_ipp_prop_list)
#define DRM_IOCTL_SPRD_IPP_SET_PROPERTY	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_IPP_SET_PROPERTY, struct drm_sprd_ipp_property)
#define DRM_IOCTL_SPRD_IPP_QUEUE_BUF	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_IPP_QUEUE_BUF, struct drm_sprd_ipp_queue_buf)
#define DRM_IOCTL_SPRD_IPP_CMD_CTRL		DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_SPRD_IPP_CMD_CTRL, struct drm_sprd_ipp_cmd_ctrl)

/* SPRD specific events */
#define DRM_SPRD_IPP_EVENT		0x80000001

struct drm_sprd_ipp_event {
	struct drm_event	base;
	__u64			user_data;
	__u32			tv_sec;
	__u32			tv_usec;
	__u32			prop_id;
	__u32			reserved;
	__u32			buf_id[SPRD_DRM_OPS_MAX];
};

enum drm_crtc_id {
	DRM_CRTC_PRIMARY,
	DRM_CRTC_FAKE,
	DRM_CRTC_ID_MAX,
};

#ifdef CONFIG_DRM_DPMS_IOCTL
#define DRM_DPMS_CONTROL		0x50

#define DRM_IOCTL_DPMS_CONTROL	DRM_IOWR(DRM_COMMAND_BASE + \
		DRM_DPMS_CONTROL, struct drm_control_dpms)

#define DRM_DPMS_EVENT		0x80000002

enum drm_dpms_type {
	DPMS_SYNC_WORK = 0x0,
	DPMS_EVENT_DRIVEN = 0x1,
};

struct drm_control_dpms {
	enum drm_crtc_id	crtc_id;
	__u32	dpms;
	__u32	user_data;
	enum drm_dpms_type	type;
};

struct drm_control_dpms_event {
	struct drm_event	base;
	enum drm_crtc_id	crtc_id;
	__u32	dpms;
	__u32	user_data;
};
#endif

#endif	/* _UAPI_SPRD_DRM_H_ */
