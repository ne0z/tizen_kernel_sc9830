#ifndef __PRELOAD_MODULE_H__
#define __PRELOAD_MODULE_H__

#include <linux/types.h>

struct us_ip;
struct dentry;
struct probe_info_new;

bool preload_module_is_ready(void);
bool preload_module_is_running(void);
bool preload_module_is_not_ready(void);
void preload_module_set_ready(void);
void preload_module_set_running(void);
void preload_module_set_not_ready(void);

int preload_module_uprobe_init(struct us_ip *ip);
void preload_module_uprobe_exit(struct us_ip *ip);

int preload_module_get_caller_init(struct us_ip *ip);
void preload_module_get_caller_exit(struct us_ip *ip);
int preload_module_get_call_type_init(struct us_ip *ip);
void preload_module_get_call_type_exit(struct us_ip *ip);
int preload_module_write_msg_init(struct us_ip *ip);
void preload_module_write_msg_exit(struct us_ip *ip);

struct dentry *get_dentry(const char *filepath);
void put_dentry(struct dentry *dentry);

struct probe_info_new *uihv_pin_main(void);


#endif /* __PRELOAD_MODULE_H__ */
