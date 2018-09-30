#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <ks_features/ks_map.h>
#include <linux/fs.h>
#include "preload.h"
#include "preload_module.h"
#include "preload_storage.h"

static struct bin_info __handlers_info = { NULL, NULL };
static struct bin_info __ui_viewer_info = { NULL, NULL };
static struct bin_info __linker_info = { NULL, NULL };
static struct bin_info __libc_info;
static struct bin_info __libpthread_info;
static struct bin_info __libsmack_info;

static inline struct bin_info *__get_handlers_info(void)
{
	return &__handlers_info;
}

static inline bool __check_handlers_info(void)
{
	return (__handlers_info.dentry != NULL); /* TODO */
}

static inline int __init_handlers_info(char *path)
{
	struct dentry *dentry;
	size_t len = strnlen(path, PATH_MAX);
	int ret = 0;

	__handlers_info.path = kmalloc(len + 1, GFP_KERNEL);
	if (__handlers_info.path == NULL) {
		ret = -ENOMEM;
		goto init_handlers_fail;
	}

	dentry = get_dentry(path);
	if (!dentry) {
		ret = -ENOENT;
		goto init_handlers_fail_free;
	}

	strncpy(__handlers_info.path, path, len);
	__handlers_info.path[len] = '\0';
	__handlers_info.dentry = dentry;

	return ret;

init_handlers_fail_free:
	kfree(__handlers_info.path);

init_handlers_fail:
	return ret;
}

static inline void __drop_handlers_info(void)
{
	kfree(__handlers_info.path);
	__handlers_info.path = NULL;

	if (__handlers_info.dentry)
		put_dentry(__handlers_info.dentry);
	__handlers_info.dentry = NULL;
}

static inline struct bin_info *__get_ui_viewer_info(void)
{
	return &__ui_viewer_info;
}

static inline bool __check_ui_viewer_info(void)
{
	return (__ui_viewer_info.dentry != NULL); /* TODO */
}

static inline int __init_ui_viewer_info(char *path)
{
	struct dentry *dentry;
	size_t len = strnlen(path, PATH_MAX);
	int ret = 0;

	__ui_viewer_info.path = kmalloc(len + 1, GFP_KERNEL);
	if (__ui_viewer_info.path == NULL) {
		ret = -ENOMEM;
		goto init_ui_viewer_fail;
	}

	dentry = get_dentry(path);
	if (!dentry) {
		ret = -ENOENT;
		goto init_ui_viewer_fail_free;
	}

	strncpy(__ui_viewer_info.path, path, len);
	__ui_viewer_info.path[len] = '\0';
	__ui_viewer_info.dentry = dentry;

	return ret;

init_ui_viewer_fail_free:
	kfree(__ui_viewer_info.path);

init_ui_viewer_fail:
	return ret;
}

static inline void __drop_ui_viewer_info(void)
{
	kfree(__ui_viewer_info.path);
	__ui_viewer_info.path = NULL;

	if (__ui_viewer_info.dentry)
		put_dentry(__ui_viewer_info.dentry);
	__ui_viewer_info.dentry = NULL;
}

static inline struct bin_info *__get_linker_info(void)
{
	return &__linker_info;
}

static inline bool __check_linker_info(void)
{
	return (__linker_info.dentry != NULL); /* TODO */
}

static inline int __init_linker_info(char *path)
{
	struct dentry *dentry;
	size_t len = strnlen(path, PATH_MAX);
	int ret = 0;


	__linker_info.path = kmalloc(len + 1, GFP_KERNEL);
	if (__linker_info.path == NULL) {
		ret = -ENOMEM;
		goto init_linker_fail;
	}

	dentry = get_dentry(path);
	if (!dentry) {
		ret = -ENOENT;
		goto init_linker_fail_free;
	}

	strncpy(__linker_info.path, path, len);
	__linker_info.path[len] = '\0';
	__linker_info.dentry = dentry;

	return ret;

init_linker_fail_free:
	kfree(__linker_info.path);

init_linker_fail:

	return ret;
}

static inline void __drop_linker_info(void)
{
	kfree(__linker_info.path);
	__linker_info.path = NULL;

	if (__linker_info.dentry)
		put_dentry(__linker_info.dentry);
	__linker_info.dentry = NULL;
}




int preload_storage_set_handlers_info(char *path)
{
	return __init_handlers_info(path);
}

struct bin_info *preload_storage_get_handlers_info(void)
{
	struct bin_info *info = __get_handlers_info();

	if (__check_handlers_info())
		return info;

	return NULL;
}

void preload_storage_put_handlers_info(struct bin_info *info)
{
}

int preload_storage_set_ui_viewer_info(char *path)
{
	return __init_ui_viewer_info(path);
}

struct bin_info *preload_storage_get_ui_viewer_info(void)
{
	struct bin_info *info = __get_ui_viewer_info();

	if (__check_ui_viewer_info())
		return info;

	return NULL;
}

void preload_storage_put_ui_viewer_info(struct bin_info *info)
{
}

int preload_storage_set_linker_info(char *path)
{
	return __init_linker_info(path);
}

struct bin_info *preload_storage_get_linker_info(void)
{
	struct bin_info *info = __get_linker_info();

	if (__check_linker_info())
		return info;

	return NULL;
}

static inline void __drop_libc_info(void)
{
	if (__libc_info.dentry)
		put_dentry(__libc_info.dentry);

	__libc_info.path = NULL;
	__libc_info.dentry = NULL;
}

static inline void __drop_libpthread_info(void)
{
	if (__libpthread_info.dentry)
		put_dentry(__libpthread_info.dentry);

	__libpthread_info.path = NULL;
	__libpthread_info.dentry = NULL;
}

static inline void __drop_libsmack_info(void)
{
	if (__libsmack_info.dentry)
		put_dentry(__libsmack_info.dentry);

	__libsmack_info.path = NULL;
	__libsmack_info.dentry = NULL;
}

void preload_storage_put_linker_info(struct bin_info *info)
{
}

struct bin_info *preload_storage_get_libc_info(void)
{
	return &__libc_info;
}

struct bin_info *preload_storage_get_libpthread_info(void)
{
	return &__libpthread_info;
}

struct bin_info *preload_storage_get_libsmack_info(void)
{
	return &__libsmack_info;
}

void preload_storage_put_libc_info(struct bin_info *info)
{
}

void preload_storage_put_libpthread_info(struct bin_info *info)
{
}

void preload_storage_put_libsmack_info(struct bin_info *info)
{
}

int preload_storage_init(void)
{
	__libc_info.path = "/lib/libc.so.6";
	__libc_info.dentry = get_dentry(__libc_info.path);

	if (!__libc_info.dentry)
		return -ENOENT;

	/* TODO check if we have not library */
	__libpthread_info.path = "/lib/libpthread.so.0";
	__libpthread_info.dentry = get_dentry(__libpthread_info.path);

	if (!__libpthread_info.dentry)
		return -ENOENT;

	/* TODO check if we have not library */
	__libsmack_info.path = "/usr/lib/libsmack.so.1.0.0";
	__libsmack_info.dentry = get_dentry(__libsmack_info.path);

	if (!__libsmack_info.dentry)
		return -ENOENT;

	return 0;
}

void preload_storage_exit(void)
{
	__drop_libsmack_info();
	__drop_libpthread_info();
	__drop_libc_info();
	__drop_handlers_info();
	__drop_ui_viewer_info();
	__drop_linker_info();
}
