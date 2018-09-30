#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrastructure (DRI) in XFree86 4.1.0 and higher.

ccflags-y := -Iinclude/uapi/drm -Idrivers/gpu/drm/sprd -Iinclude/drm
ccflags-y += -Idrivers/video/sprdfb -Idrivers/staging/android/ion
sprddrm-y := sprd_drm_drv.o sprd_drm_buf.o sprd_drm_gem.o \
		sprd_drm_core.o	sprd_drm_irq.o

sprddrm-$(CONFIG_DRM_SPRD_DMABUF) += sprd_drm_dmabuf.o
sprddrm-$(CONFIG_DRM_SPRD_IPP)	+= sprd_drm_ipp.o
sprddrm-$(CONFIG_DRM_SPRD_GSP)	+= sprd_drm_gsp.o
obj-$(CONFIG_DRM_SPRD)		+= sprddrm.o
