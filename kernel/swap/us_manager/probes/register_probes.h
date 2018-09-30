#ifndef __REGISTER_PROBES_H__
#define __REGISTER_PROBES_H__

#include "probes.h"

struct us_ip;

struct probe_iface {
	void (*init)(struct us_ip *);
	void (*uninit)(struct us_ip *);
	int (*reg)(struct us_ip *);
	void (*unreg)(struct us_ip *, int);
	struct uprobe *(*get_uprobe)(struct us_ip *);
	int (*copy)(struct probe_info *, const struct probe_info *);
	void (*cleanup)(struct probe_info *);
};

int swap_register_probe_type(enum probe_t probe_type, struct probe_iface *pi);
void swap_unregister_probe_type(enum probe_t probe_type);

#endif /* __REGISTER_PROBES_H__ */
