#ifndef __ESD_DETECT_H__
#define __ESD_DETECT_H__

#include <linux/interrupt.h>
#include <linux/gpio.h>

#define SPRDFB_LCD_ESD_DETECT_GPIO 140
/*#define SPRDFB_LCD_ERR_FG_GPIO 51*/
#define SPRDFB_ESD_IRQ_EN_DELAY 120

enum esd_status {
	ESD_NONE, ESD_DETECTED,
};

struct esd_det_info {
	struct work_struct uevent_notifier;
	struct delayed_work irq_enable;
#ifdef SPRDFB_LCD_ESD_DETECT_GPIO
	int esd_det_gpio;
	int esd_det_irq;
#endif
#ifdef SPRDFB_LCD_ERR_FG_GPIO
	int err_fg_gpio;
	int err_fg_irq;
#endif
	int status;
	int irq_enable_count;
	int notify_in_progress;
	struct sprdfb_device *fbdev;
	struct class *class;
	struct device *device;
};

static int sprdfb_panel_esd_detect_init();
#ifdef SPRDFB_LCD_ESD_DETECT_GPIO
static irqreturn_t sprdfb_panel_esd_det_irq_handler(int irq, void *handle);
#endif
#ifdef SPRDFB_LCD_ERR_FG_GPIO
static irqreturn_t sprdfb_panel_err_fg_irq_handler(int irq, void *handle);
#endif

#endif	/* __ESD_DETECT_H__ */
