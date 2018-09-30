#ifndef __PRELOAD_CONTROL_H__
#define __PRELOAD_CONTROL_H__

enum preload_call_type {
	NOT_INSTRUMENTED,
	EXTERNAL_CALL,
	INTERNAL_CALL
};

int preload_control_init(void);
void preload_control_exit(void);

enum preload_call_type preload_control_call_type_always_inst(void *caller);
enum preload_call_type preload_control_call_type(struct us_ip *ip, void *caller);
int preload_control_add_instrumented_binary(char *filename);
int preload_control_clean_instrumented_bins(void);

unsigned int preload_control_get_bin_names(char ***filenames_p);
void preload_control_release_bin_names(char ***filenames_p);

#endif /* __PRELOAD_CONTROL_H__ */
