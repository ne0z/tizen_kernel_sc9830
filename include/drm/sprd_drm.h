/* sprd_drm.h
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef _SPRD_DRM_H_
#define _SPRD_DRM_H_

#include <uapi/drm/sprd_drm.h>

#ifdef CONFIG_DRM_DPMS_IOCTL
enum sprd_drm_notifier {
	SPRD_DRM_DPMS_CTRL,
	SPRD_DRM_MAX_NOTI,
};

struct sprd_drm_nb_event {
	int index;
	void *data;
};

int sprd_drm_nb_register(struct notifier_block *nb);
int sprd_drm_nb_unregister(struct notifier_block *nb);
int sprd_drm_nb_send_event(unsigned long val, void *v);
#endif

#endif	/* _SPRD_DRM_H_ */
