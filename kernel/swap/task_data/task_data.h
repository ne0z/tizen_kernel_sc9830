#ifndef __TASK_DATA__
#define __TASK_DATA__

#define SWAP_TD_FREE 0x1 /* kfree task data automatically */

struct task_struct;

void *swap_task_data_get(struct task_struct *task, int *ok);
void swap_task_data_set(struct task_struct *task, void *data,
			unsigned long flags);

static inline void swap_task_data_clean(struct task_struct *task)
{
	swap_task_data_set(task, NULL, 0);
}

#endif /* __TASK_DATA__ */
