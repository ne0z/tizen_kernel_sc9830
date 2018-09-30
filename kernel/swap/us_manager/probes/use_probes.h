#ifndef __USE_PROBES_H__
#define __USE_PROBES_H__

#include "probes.h"

struct us_ip;

void probe_info_init(struct probe_info *pi, struct us_ip *ip);
void probe_info_uninit(struct probe_info *pi, struct us_ip *ip);
int probe_info_register(struct probe_info *pi, struct us_ip *ip);
void probe_info_unregister(struct probe_info *pi, struct us_ip *ip, int disarm);
struct uprobe *probe_info_get_uprobe(struct probe_info *pi, struct us_ip *ip);
int probe_info_copy(const struct probe_info *pi, struct probe_info *dest);
void probe_info_cleanup(struct probe_info *pi);

#endif /* __USE_PROBES_H__ */
