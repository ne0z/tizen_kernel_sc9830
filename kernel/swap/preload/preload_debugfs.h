#ifndef __PRELOAD_DEBUGFS_H__
#define __PRELOAD_DEBUGFS_H__

struct dentry;

int preload_debugfs_init(void);
void preload_debugfs_exit(void);

struct dentry *preload_debugfs_get_loader_dentry(void);
unsigned long preload_debugfs_get_loader_offset(void);

struct dentry *preload_debugfs_create_new_thread(unsigned long tid);

unsigned long preload_debugfs_r_debug_offset(void);

#endif /* __PRELOAD_DEBUGFS_H__ */
