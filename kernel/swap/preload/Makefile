ccflags-y := -Ikernel/swap

ifeq ($(CONFIG_ARM), y)
    link = arm
endif

ifeq ($(CONFIG_X86), y)
    link = x86
endif

ccflags-y += -Ikernel/swap/kprobe/arch/$(link) \
             -Ikernel/swap/uprobe/arch/$(link)

obj-$(CONFIG_SWAP_DA) := swap_preload.o
swap_preload-y := preload_module.o \
                  preload_debugfs.o \
                  preload_storage.o \
                  preload_probe.o \
                  preload_control.o \
                  preload_threads.o \
                  preload_pd.o \
                  uihv.o
