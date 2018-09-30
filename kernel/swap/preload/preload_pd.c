#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/hardirq.h>
#include <us_manager/us_manager_common.h>
#include <us_manager/sspt/sspt_proc.h>
#include "preload_pd.h"
#include "preload_threads.h"
#include "preload_debugfs.h"
#include "preload_storage.h"
#include "preload.h"


struct process_data {
	enum preload_state_t state;
	enum preload_state_t ui_viewer_state;
	unsigned long loader_base;
	unsigned long handlers_base;
	unsigned long ui_viewer_base;
	unsigned long data_page;
	unsigned long ui_viewer_offset;
	void __user *handle;
	long attempts;
	long refcount;
};

static struct bin_info *handlers_info;
static struct bin_info *ui_viewer_info;



static inline bool check_vma(struct vm_area_struct *vma, struct dentry *dentry)
{
	struct file *file = vma->vm_file;

	return (file && (vma->vm_flags & VM_EXEC) && (file->f_dentry == dentry));
}

static inline enum preload_state_t __get_state(struct process_data *pd)
{
	return pd->state;
}

static inline void __set_state(struct process_data *pd,
				   enum preload_state_t state)
{
	pd->state = state;
}

static inline unsigned long __get_loader_base(struct process_data *pd)
{
	return pd->loader_base;
}

static inline void __set_loader_base(struct process_data *pd,
				     unsigned long addr)
{
	pd->loader_base = addr;
}

static inline unsigned long __get_handlers_base(struct process_data *pd)
{
	return pd->handlers_base;
}

static inline void __set_handlers_base(struct process_data *pd,
				       unsigned long addr)
{
	pd->handlers_base = addr;
}

static inline char __user *__get_path(struct process_data *pd)
{
	return (char *)pd->data_page;
}

static inline unsigned long __get_data_page(struct process_data *pd)
{
	return pd->data_page;
}

static inline void __set_data_page(struct process_data *pd, unsigned long page)
{
	pd->data_page = page;
}

static inline void *__get_handle(struct process_data *pd)
{
	return pd->handle;
}

static inline void __set_handle(struct process_data *pd, void __user *handle)
{
	pd->handle = handle;
}

static inline long __get_attempts(struct process_data *pd)
{
	return pd->attempts;
}

static inline void __set_attempts(struct process_data *pd, long attempts)
{
	pd->attempts = attempts;
}

static inline long __get_refcount(struct process_data *pd)
{
	return pd->refcount;
}

static inline void __set_refcount(struct process_data *pd, long refcount)
{
	pd->refcount = refcount;
}

static inline enum preload_state_t __get_ui_viewer_state(struct process_data *pd)
{
	return pd->ui_viewer_state;
}

static inline void __set_ui_viewer_state(struct process_data *pd,
				   enum preload_state_t state)
{
	pd->ui_viewer_state = state;
}

static inline void __set_ui_viewer_base(struct process_data *pd,
				        unsigned long addr)
{
	pd->ui_viewer_base = addr;
}

static inline unsigned long __get_ui_viewer_base(struct process_data *pd)
{
	return pd->ui_viewer_base;
}

static inline void __set_ui_viewer_offset(struct process_data *pd,
					  unsigned long offset)
{
	pd->ui_viewer_offset = offset;
}

static inline char __user *__get_ui_viewer_path(struct process_data *pd)
{
	return (char *)(pd->data_page + pd->ui_viewer_offset);
}



static int __pd_create_on_demand(void)
{
	if (handlers_info == NULL) {
		handlers_info = preload_storage_get_handlers_info();
		if (handlers_info == NULL)
			return -EINVAL;
	}

	if (ui_viewer_info == NULL) {
		ui_viewer_info = preload_storage_get_ui_viewer_info();
		if (ui_viewer_info == NULL)
			return -EINVAL;
	}

	return 0;
}



enum preload_state_t preload_pd_get_state(struct process_data *pd)
{
	if (pd == NULL)
		return 0;

	return __get_state(pd);
}

void preload_pd_set_state(struct process_data *pd, enum preload_state_t state)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
		       current->tgid, current->comm);
		return;
	}

	__set_state(pd, state);
}

enum preload_state_t preload_pd_get_ui_viewer_state(struct process_data *pd)
{
	if (pd == NULL)
		return 0;

	return __get_ui_viewer_state(pd);
}

void preload_pd_set_ui_viewer_state(struct process_data *pd,
				    enum preload_state_t state)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
		       current->tgid, current->comm);
		return;
	}

	__set_ui_viewer_state(pd, state);
}

char __user *preload_pd_get_path(struct process_data *pd)
{
	char __user *path = __get_path(pd);

	return path;
}

char __user *preload_pd_get_ui_viewer_path(struct process_data *pd)
{
	char __user *path = __get_ui_viewer_path(pd);

	return path;
}

unsigned long preload_pd_get_loader_base(struct process_data *pd)
{
	if (pd == NULL)
		return 0;

	return __get_loader_base(pd);
}

void preload_pd_set_loader_base(struct process_data *pd, unsigned long vaddr)
{
	__set_loader_base(pd, vaddr);
}

unsigned long preload_pd_get_handlers_base(struct process_data *pd)
{
	if (pd == NULL)
		return 0;

	return __get_handlers_base(pd);
}

void preload_pd_set_handlers_base(struct process_data *pd, unsigned long vaddr)
{
	__set_handlers_base(pd, vaddr);
}

unsigned long preload_pd_get_ui_viewer_base(struct process_data *pd)
{
	if (pd == NULL)
		return 0;

	return __get_ui_viewer_base(pd);
}

void preload_pd_set_ui_viewer_base(struct process_data *pd, unsigned long vaddr)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
		       current->tgid, current->comm);
		return;
	}

	__set_ui_viewer_base(pd, vaddr);
}

void preload_pd_put_path(struct process_data *pd)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
		       current->tgid, current->comm);
		return;
	}

	if (__get_data_page(pd) == 0)
		return;

	__set_data_page(pd, 0);
}

void *preload_pd_get_handle(struct process_data *pd)
{
	if (pd == NULL)
		return NULL;

	return __get_handle(pd);
}

void preload_pd_set_handle(struct process_data *pd, void __user *handle)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	__set_handle(pd, handle);
}

long preload_pd_get_attempts(struct process_data *pd)
{
	if (pd == NULL)
		return -EINVAL;

	return __get_attempts(pd);
}

void preload_pd_dec_attempts(struct process_data *pd)
{
	long attempts;

	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	attempts = __get_attempts(pd);
	attempts--;
	__set_attempts(pd, attempts);
}

void preload_pd_inc_refs(struct process_data *pd)
{
	long refs;

	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	refs = __get_refcount(pd);
	refs++;
	__set_refcount(pd, refs);
}

void preload_pd_dec_refs(struct process_data *pd)
{
	long refs;

	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	refs = __get_refcount(pd);
	refs--;
	__set_refcount(pd, refs);
}

long preload_pd_get_refs(struct process_data *pd)
{
	if (pd == NULL)
		return -EINVAL;

	return __get_refcount(pd);
}

struct process_data *preload_pd_get(struct sspt_proc *proc)
{
	return (struct process_data *)proc->private_data;
}

static unsigned long make_preload_path(unsigned long *offset)
{
	unsigned long page = -EINVAL;

	if (handlers_info && ui_viewer_info) {
		const char *probe_path = handlers_info->path;
		size_t probe_len = strnlen(probe_path, PATH_MAX);
		const char *ui_viewer_path = ui_viewer_info->path;
		size_t ui_viewer_len = strnlen(ui_viewer_path, PATH_MAX);

		down_write(&current->mm->mmap_sem);
		page = swap_do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
				    MAP_ANONYMOUS | MAP_PRIVATE, 0);
		up_write(&current->mm->mmap_sem);

		if (IS_ERR_VALUE(page)) {
			printk(KERN_ERR PRELOAD_PREFIX
			       "Cannot alloc page for %u\n", current->tgid);
			goto out;
		}

		/* set preload_libraries paths */
		if (copy_to_user((void __user *)page, probe_path,
				 probe_len) != 0)
			printk(KERN_ERR PRELOAD_PREFIX
			       "Cannot copy string to user!\n");

		/* split paths with 0 value */
		*offset = probe_len + 1;

		if (copy_to_user((void __user *)(page + *offset),
				 ui_viewer_path, ui_viewer_len) != 0)
			printk(KERN_ERR PRELOAD_PREFIX
			       "Cannot copy string to user!\n");
	}

out:
	return page;
}

static struct vm_area_struct *find_vma_by_dentry(struct mm_struct *mm,
						 struct dentry *dentry)
{
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next)
		if (check_vma(vma, dentry))
			return vma;

        return NULL;
}

static void set_already_mapp(struct process_data *pd, struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct dentry *ld = preload_debugfs_get_loader_dentry();
	struct dentry *handlers = handlers_info->dentry;

	down_read(&mm->mmap_sem);
	if (ld) {
		vma = find_vma_by_dentry(mm, ld);
		if (vma)
			__set_loader_base(pd, vma->vm_start);
	}

	if (handlers) {
		vma = find_vma_by_dentry(mm, handlers);
		if (vma) {
			__set_handlers_base(pd, vma->vm_start);
			__set_state(pd, LOADED);
		}
	}
	up_read(&mm->mmap_sem);
}

static struct process_data *do_create_pd(struct task_struct *task)
{
	struct process_data *pd;
	unsigned long page, offset = 0;
	int ret;

	ret = __pd_create_on_demand();
	if (ret)
		goto create_pd_exit;

	pd = kzalloc(sizeof(*pd), GFP_ATOMIC);
	if (pd == NULL) {
		ret = -ENOMEM;
		goto create_pd_exit;
	}

	page = make_preload_path(&offset);
	if (IS_ERR_VALUE(page)) {
		ret = (long)page;
		goto free_pd;
	}

	__set_data_page(pd, page);
	__set_ui_viewer_offset(pd, offset);
	__set_attempts(pd, PRELOAD_MAX_ATTEMPTS);
	set_already_mapp(pd, task->mm);

	return pd;

free_pd:
	kfree(pd);

create_pd_exit:
	printk(KERN_ERR PRELOAD_PREFIX "do_pd_create_pd: error=%d\n", ret);
	return NULL;
}

static void *pd_create(struct sspt_proc *proc)
{
	struct process_data *pd;

	pd = do_create_pd(proc->task);

	return (void *)pd;
}

static void pd_destroy(struct sspt_proc *proc, void *data)
{
	/* FIXME: to be implemented */
}

struct sspt_proc_cb pd_cb = {
	.priv_create = pd_create,
	.priv_destroy = pd_destroy
};

int preload_pd_init(void)
{
	int ret;

	ret = sspt_proc_cb_set(&pd_cb);

	return ret;
}

void preload_pd_uninit(void)
{
	sspt_proc_cb_set(NULL);

	if (handlers_info)
		preload_storage_put_handlers_info(handlers_info);
	handlers_info = NULL;

	if (ui_viewer_info)
		preload_storage_put_ui_viewer_info(ui_viewer_info);
	ui_viewer_info = NULL;
}
