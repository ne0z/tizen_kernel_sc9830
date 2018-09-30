#ifndef __PRELOAD_STORAGE_H__
#define __PRELOAD_STORAGE_H__

struct bin_info {
	char *path;
	/* ghot */
	struct dentry *dentry;
};

int preload_storage_set_handlers_info(char *path);
struct bin_info *preload_storage_get_handlers_info(void);
void preload_storage_put_handlers_info(struct bin_info *info);

int preload_storage_set_ui_viewer_info(char *path);
struct bin_info *preload_storage_get_ui_viewer_info(void);
void preload_storage_put_ui_viewer_info(struct bin_info *info);

int preload_storage_set_linker_info(char *path);
struct bin_info *preload_storage_get_linker_info(void);
void preload_storage_put_linker_info(struct bin_info *info);

struct bin_info *preload_storage_get_libc_info(void);
void preload_storage_put_libc_info(struct bin_info *info);

struct bin_info *preload_storage_get_libpthread_info(void);
void preload_storage_put_libpthread_info(struct bin_info *info);

struct bin_info *preload_storage_get_libsmack_info(void);
void preload_storage_put_libsmack_info(struct bin_info *info);

int preload_storage_init(void);
void preload_storage_exit(void);

#endif /* __PRELOAD_HANDLERS_H__ */
