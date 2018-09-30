/*
 * Samsung Elec.
 *
 * drivers/gpio/secgpio_dvs_sc9830.c - Read GPIO for sc9830 of SPRD
 *
 * Copyright (C) 2014, Samsung Electronics.
 *
 * This program is free software. You can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */

#include <asm/io.h>
#include <soc/sprd/sci_glb_regs.h>
#include <soc/sprd/gpio.h>
#include <soc/sprd/pinmap.h>

/********************* Fixed Code Area !***************************/
#include <linux/secgpio_dvs.h>
#include <linux/platform_device.h>
#if defined (CONFIG_GPIO_MON)
#include <linux/gpio_state_mon.h>
#endif
#define GET_RESULT_GPIO(a, b, c)    \
    (((a)<<10 & 0xFC00) |((b)<<4 & 0x03F0) | ((c) & 0x000F))

#define GET_GPIO_IO(value)  \
    (unsigned char)((0xFC00 & (value)) >> 10)
#define GET_GPIO_PUPD(value)    \
    (unsigned char)((0x03F0 & (value)) >> 4)
#define GET_GPIO_LH(value)  \
    (unsigned char)(0x000F & (value))
/****************************************************************/


typedef struct {
    unsigned int gpio_num;
    unsigned int ctrl_offset;
} gpio_ctrl_info;

static gpio_ctrl_info available_gpios_sc9830[] = {
	{ 1, REG_PIN_RFSDA0 },
	{ 2, REG_PIN_RFSCK0 },
	{ 3, REG_PIN_RFSEN0 },
	{ 4, REG_PIN_RFSDA1 },
	{ 5, REG_PIN_RFSCK1 },
	{ 6, REG_PIN_RFSEN1 },
	{ 7, REG_PIN_RFCTL15 },
	{ 8, REG_PIN_RFCTL16 },
	{ 9, REG_PIN_RFCTL17 },
	{ 10, REG_PIN_RFCTL18 },
	{ 11, REG_PIN_RFCTL19 },
	{ 12, REG_PIN_RFCTL20 },
	{ 13, REG_PIN_RFCTL21 },
	{ 14, REG_PIN_RFCTL22 },
	{ 15, REG_PIN_RFCTL23 },
	{ 16, REG_PIN_RFCTL24 },
	{ 17, REG_PIN_RFCTL25 },
	{ 18, REG_PIN_RFCTL26 },
	{ 19, REG_PIN_RFCTL0 },
	{ 20, REG_PIN_RFCTL1 },
	{ 21, REG_PIN_RFCTL2 },
	{ 22, REG_PIN_RFCTL3 },
	{ 23, REG_PIN_RFCTL4 },
	{ 24, REG_PIN_RFCTL5 },
	{ 25, REG_PIN_RFCTL6 },
	{ 26, REG_PIN_RFCTL7 },
	{ 27, REG_PIN_RFCTL8 },
	{ 28, REG_PIN_RFCTL9 },
	{ 29, REG_PIN_RFCTL10 },
	{ 30, REG_PIN_RFCTL11 },
	{ 31, REG_PIN_RFCTL12 },
	{ 32, REG_PIN_RFCTL13 },
	{ 33, REG_PIN_RFCTL14 },
	{ 34, REG_PIN_RFCTL27 },
	{ 35, REG_PIN_XTL_EN },
	{ 36, REG_PIN_RFFE_SCK0 },
	{ 37, REG_PIN_RFFE_SDA0 },
	{ 38, REG_PIN_RFCTL28 },
	{ 39, REG_PIN_RFCTL29 },
	{ 40, REG_PIN_CCIRD0 },
	{ 41, REG_PIN_CCIRD1 },
	{ 42, REG_PIN_CMMCLK },
	{ 43, REG_PIN_CMPCLK },
	{ 44, REG_PIN_CMRST0 },
	{ 45, REG_PIN_CMRST1 },
	{ 46, REG_PIN_CMPD0 },
	{ 47, REG_PIN_CMPD1 },
	{ 48, REG_PIN_SCL0 },
	{ 49, REG_PIN_SDA0 },
	{ 50, REG_PIN_LCM_RSTN },
	{ 51, REG_PIN_DSI_TE },
	{ 52, REG_PIN_SPI2_CSN },
	{ 53, REG_PIN_SPI2_DO },
	{ 54, REG_PIN_SPI2_DI },
	{ 55, REG_PIN_SPI2_CLK },
	{ 56, REG_PIN_IIS0DI },
	{ 57, REG_PIN_IIS0DO },
	{ 58, REG_PIN_IIS0CLK },
	{ 59, REG_PIN_IIS0LRCK },
	{ 60, REG_PIN_U0TXD },
	{ 61, REG_PIN_U0RXD },
	{ 62, REG_PIN_U0CTS },
	{ 63, REG_PIN_U0RTS },
	{ 64, REG_PIN_SD1_CLK },
	{ 65, REG_PIN_SD1_CMD },
	{ 66, REG_PIN_SD1_D0 },
	{ 67, REG_PIN_SD1_D1 },
	{ 68, REG_PIN_SD1_D2 },
	{ 69, REG_PIN_SD1_D3 },
	{ 70, REG_PIN_U1TXD },
	{ 71, REG_PIN_U1RXD },
	{ 72, REG_PIN_U2TXD },
	{ 73, REG_PIN_U2RXD	},
	{ 74, REG_PIN_U3TXD },
	{ 75, REG_PIN_U3RXD },
	{ 76, REG_PIN_U3CTS },
	{ 77, REG_PIN_U3RTS },
	{ 78, REG_PIN_U4TXD },
	{ 79, REG_PIN_U4RXD },
	{ 82, REG_PIN_MTCK_ARM },
	{ 83, REG_PIN_MTMS_ARM },
	{ 85, REG_PIN_DTDO_LTE },
	{ 86, REG_PIN_DTDI_LTE },
	{ 87, REG_PIN_DTCK_LTE },
	{ 88, REG_PIN_DTMS_LTE },
	{ 89, REG_PIN_DRTCK_LTE },
	{ 90, REG_PIN_SPI0_CSN },
	{ 91, REG_PIN_SPI0_DO },
	{ 92, REG_PIN_SPI0_DI },
	{ 93, REG_PIN_SPI0_CLK },
	{ 94, REG_PIN_MEMS_MIC_CLK0 },
	{ 95, REG_PIN_MEMS_MIC_DATA0 },
	{ 96, REG_PIN_MEMS_MIC_CLK1 },
	{ 97, REG_PIN_MEMS_MIC_DATA1 },
	{ 98, REG_PIN_NFWPN },
	{ 99, REG_PIN_NFRB },
	{ 100, REG_PIN_NFCLE },
	{ 101, REG_PIN_NFALE },
	{ 102, REG_PIN_NFREN },
	{ 103, REG_PIN_NFD4 },
	{ 104, REG_PIN_NFD5 },
	{ 105, REG_PIN_NFD6 },
	{ 106, REG_PIN_NFD7 },
	{ 107, REG_PIN_NFD10 },
	{ 108, REG_PIN_NFD11 },
	{ 109, REG_PIN_NFD14 },
	{ 112, REG_PIN_NFD0 },
	{ 113, REG_PIN_NFD1 },
	{ 114, REG_PIN_NFD2 },
	{ 115, REG_PIN_NFD3 },
	{ 121, REG_PIN_KEYOUT0 },
	{ 122, REG_PIN_KEYOUT1 },
	{ 123, REG_PIN_KEYOUT2 },
	{ 124, REG_PIN_KEYIN0 },
	{ 125, REG_PIN_KEYIN1 },
	{ 126, REG_PIN_KEYIN2 },
	{ 127, REG_PIN_SCL2 },
	{ 128, REG_PIN_SDA2 },
	{ 129, REG_PIN_CLK_AUX0 },
	{ 130, REG_PIN_IIS1DI },
	{ 131, REG_PIN_IIS1DO },
	{ 132, REG_PIN_IIS1CLK },
	{ 133, REG_PIN_IIS1LRCK },
	{ 134, REG_PIN_TRACECLK },
	{ 135, REG_PIN_TRACECTRL },
	{ 136, REG_PIN_TRACEDAT0 },
	{ 137, REG_PIN_TRACEDAT1 },
	{ 138, REG_PIN_TRACEDAT2 },
	{ 139, REG_PIN_TRACEDAT3 },
	{ 140, REG_PIN_TRACEDAT4 },
	{ 141, REG_PIN_TRACEDAT5 },
	{ 142, REG_PIN_TRACEDAT6 },
	{ 143, REG_PIN_TRACEDAT7 },
	{ 144, REG_PIN_EXTINT0 },
	{ 145, REG_PIN_EXTINT1 },
	{ 146, REG_PIN_SCL3 },
	{ 147, REG_PIN_SDA3 },
	{ 148, REG_PIN_SD0_D3 },
	{ 149, REG_PIN_SD0_D2 },
	{ 150, REG_PIN_SD0_CMD },
	{ 151, REG_PIN_SD0_D0 },
	{ 152, REG_PIN_SD0_D1 },
	{ 153, REG_PIN_SD0_CLK0 },
	{ 154, REG_PIN_SIMCLK2 },
	{ 155, REG_PIN_SIMDA2 },
	{ 156, REG_PIN_SIMRST2 },
	{ 157, REG_PIN_SIMCLK0 },
	{ 158, REG_PIN_SIMDA0 },
	{ 159, REG_PIN_SIMRST0 },
	{ 160, REG_PIN_SIMCLK1 },
	{ 161, REG_PIN_SIMDA1 },
	{ 162, REG_PIN_SIMRST1 },
};

#define GPIO_CTRL_ADDR  (SPRD_PIN_BASE)
#define GPIO_DATA_ADDR  (SPRD_GPIO_BASE)

#define GPIODATA_OFFSET     0x0
#define GPIODIR_OFFSET      0x8

#define GetBit(dwData, i)   (dwData & (0x1 << i))
#define SetBit(dwData, i)   (dwData | (0x1 << i))
#define ClearBit(dwData, i) (dwData & ~(0x1 << i))

#define GPIO_COUNT  (ARRAY_SIZE(available_gpios_sc9830))

/****************************************************************/
/* Define value in accordance with
    the specification of each BB vendor. */
#define AP_GPIO_COUNT   GPIO_COUNT
/****************************************************************/
#if defined (CONFIG_GPIO_MON)
unsigned int gpio_mon_gpio_count = AP_GPIO_COUNT;
#endif

/****************************************************************/
/* Pre-defined variables. (DO NOT CHANGE THIS!!) */
static uint16_t checkgpiomap_result[GDVS_PHONE_STATUS_MAX][AP_GPIO_COUNT];
static struct gpiomap_result_t gpiomap_result = {
    .init = checkgpiomap_result[PHONE_INIT],
    .sleep = checkgpiomap_result[PHONE_SLEEP]
};

#ifdef SECGPIO_SLEEP_DEBUGGING
static struct sleepdebug_gpiotable sleepdebug_table;
#endif
/****************************************************************/

unsigned int get_gpio_io(unsigned int value)
{
    switch(value) {
    case 0x0: /* in fact, this is hi-z */
        return GDVS_IO_FUNC; //GDVS_IO_HI_Z;
    case 0x1:
        return GDVS_IO_OUT;
    case 0x2:
        return GDVS_IO_IN;
    default:
        return GDVS_IO_ERR;
    }
}

unsigned int get_gpio_pull_value(unsigned int value)
{
    switch(value) {
    case 0x0:
        return GDVS_PUPD_NP;
    case 0x1:
        return GDVS_PUPD_PD;
    case 0x2:
        return GDVS_PUPD_PU;
    default:
        return GDVS_PUPD_ERR;
    }
}

unsigned int get_gpio_data(unsigned int value)
{
    if (value == 0)
        return GDVS_HL_L;
    else
        return GDVS_HL_H;
}

void get_gpio_group(unsigned int num, unsigned int* grp_offset, unsigned int* bit_pos)
{
    if (num < 16) {
        *grp_offset = 0x0;
        *bit_pos = num;
    } else if (num < 32) {
        *grp_offset = 0x80;
        *bit_pos = num - 16;
    } else if (num < 48) {
        *grp_offset = 0x100;
        *bit_pos = num - 32;
    } else if (num < 64) {
        *grp_offset = 0x180;
        *bit_pos = num - 48;
    } else if (num < 80) {
        *grp_offset = 0x200;
        *bit_pos = num - 64;
    } else if (num < 96) {
        *grp_offset = 0x280;
        *bit_pos = num - 80;
    } else if (num < 112) {
        *grp_offset = 0x300;
        *bit_pos = num - 96;
    } else if (num < 128) {
        *grp_offset = 0x380;
        *bit_pos = num - 112;
    } else if (num < 144) {
        *grp_offset = 0x400;
        *bit_pos = num - 128;
    } else if (num < 160) {
        *grp_offset = 0x480;
        *bit_pos = num - 144;
    } else if (num < 176) {
        *grp_offset = 0x500;
        *bit_pos = num - 160;
    } else if (num < 192) {
        *grp_offset = 0x580;
        *bit_pos = num - 176;
    } else if (num < 208) {
        *grp_offset = 0x600;
        *bit_pos = num - 192;
    } else if (num < 224) {
        *grp_offset = 0x680;
        *bit_pos = num - 208;
    } else if (num < 240) {
        *grp_offset = 0x700;
        *bit_pos = num - 224;
    } else {
        *grp_offset = 0x780;
        *bit_pos = num - 240;
    }
}

void get_gpio_registers(unsigned char phonestate)
{
	unsigned int i, status;
	unsigned int ctrl_reg, dir_reg;
	unsigned int PIN_NAME_sel;
	unsigned int temp_io, temp_pud, temp_lh;
	unsigned int grp_offset, bit_pos;
	unsigned int PIN_NAME_wpus;
	for (i = 0; i < GPIO_COUNT; i++) {
		ctrl_reg = readl((void __iomem*)GPIO_CTRL_ADDR + available_gpios_sc9830[i].ctrl_offset);
		PIN_NAME_sel = ((GetBit(ctrl_reg,5)|GetBit(ctrl_reg,4)) >> 4);
		PIN_NAME_wpus = (GetBit(ctrl_reg,12) >> 5);

		if (phonestate == PHONE_SLEEP)
			temp_pud = get_gpio_pull_value((GetBit(ctrl_reg,3)|GetBit(ctrl_reg,2)) >> 2);
		else
			/* Week pull(WPUS) setting is applicable only if WPU setting
			is enabled,refer section 3.1.7 of SC9830I spec file */
			temp_pud = get_gpio_pull_value(((GetBit(ctrl_reg,7))|GetBit(ctrl_reg,6)) >> 6);

		if (PIN_NAME_sel == 0x3) {  // GPIO mode
			get_gpio_group(available_gpios_sc9830[i].gpio_num, &grp_offset, &bit_pos);
			if (phonestate == PHONE_SLEEP) {
				temp_io = get_gpio_io(GetBit(ctrl_reg,1)| GetBit(ctrl_reg,0));
				if (temp_io == 0)
					temp_io = GDVS_IO_HI_Z;
			} else {
				dir_reg = readl((void __iomem*)GPIO_DATA_ADDR + grp_offset + GPIODIR_OFFSET);
				temp_io = GDVS_IO_IN + (GetBit(dir_reg, bit_pos) >> bit_pos);
			}

			status = gpio_request(available_gpios_sc9830[i].gpio_num, NULL);
			temp_lh = gpio_get_value(available_gpios_sc9830[i].gpio_num); /* 0: L, 1: H */
			if (!status)
				gpio_free(available_gpios_sc9830[i].gpio_num);
		} else {    // Func mode
			temp_io = GDVS_IO_FUNC;
			temp_lh = GDVS_HL_UNKNOWN;
		}

#if defined (CONFIG_GPIO_MON)
        gpio_mon_save_gpio_state(phonestate,i,available_gpios_sc9830[i].gpio_num,PIN_NAME_sel,temp_io,temp_pud,temp_lh);
#endif
		checkgpiomap_result[phonestate][i] = GET_RESULT_GPIO(temp_io, temp_pud, temp_lh);
	}
}

/****************************************************************/
/* Define this function in accordance with the specification of each BB vendor */
static void check_gpio_status(unsigned char phonestate)
{
    pr_info("[GPIO_DVS][%s] ++\n", __func__);

    get_gpio_registers(phonestate);

    pr_info("[GPIO_DVS][%s] --\n", __func__);

    return;
}
/****************************************************************/


#ifdef SECGPIO_SLEEP_DEBUGGING
/****************************************************************/
/* Define this function in accordance with the specification of each BB vendor */
void setgpio_for_sleepdebug(int gpionum, uint16_t  io_pupd_lh)
{
    unsigned char temp_io, temp_pupd, temp_lh, ctrl_reg;

    if (gpionum >= GPIO_COUNT) {
        pr_info("[GPIO_DVS][%s] gpio num is out of boundary.\n", __func__);
        return;
    }

    pr_info("[GPIO_DVS][%s] gpionum=%d, io_pupd_lh=0x%x\n", __func__, gpionum, io_pupd_lh);

    temp_io = GET_GPIO_IO(io_pupd_lh);
    temp_pupd = GET_GPIO_PUPD(io_pupd_lh);
    temp_lh = GET_GPIO_LH(io_pupd_lh);

    pr_info("[GPIO_DVS][%s] io=%d, pupd=%d, lh=%d\n", __func__, temp_io, temp_pupd, temp_lh);

    /* in case of 'INPUT', set PD/PU */
    if (temp_io == GDVS_IO_IN) {
        ctrl_reg = readl((void __iomem*)GPIO_CTRL_ADDR + available_gpios_sc9830[gpionum].ctrl_offset);
        ctrl_reg = ClearBit(ctrl_reg, 3);
        ctrl_reg = ClearBit(ctrl_reg, 2);

        /* 0x0:NP, 0x1:PD, 0x2:PU */
        if (temp_pupd == GDVS_PUPD_NP)
            temp_pupd = 0x0;
        else if (temp_pupd == GDVS_PUPD_PD)
            ctrl_reg = SetBit(ctrl_reg, 2);
        else if (temp_pupd == GDVS_PUPD_PU)
            ctrl_reg = SetBit(ctrl_reg, 3);

        writel(ctrl_reg, (void __iomem*)GPIO_CTRL_ADDR + available_gpios_sc9830[gpionum].ctrl_offset);
        pr_info("[GPIO_DVS][%s] %d gpio set IN_PUPD to %d\n",
                __func__, available_gpios_sc9830[gpionum].gpio_num, temp_pupd);
    } else if (temp_io == GDVS_IO_OUT) { /* in case of 'OUTPUT', set L/H */
        unsigned int grp_offset, bit_pos, data_reg1, data_reg2;
        get_gpio_group(available_gpios_sc9830[gpionum].gpio_num, &grp_offset, &bit_pos);
        data_reg1 = readl((void __iomem*)GPIO_DATA_ADDR + grp_offset + GPIODATA_OFFSET);

        gpio_set_value(available_gpios_sc9830[gpionum].gpio_num, temp_lh);

        data_reg2 = readl((void __iomem*)GPIO_DATA_ADDR + grp_offset + GPIODATA_OFFSET);
        if(data_reg1 != data_reg2)
            pr_info("[GPIO_DVS][%s] %d gpio set OUT_LH to %d\n",
                __func__, available_gpios_sc9830[gpionum].gpio_num, temp_lh);
        else
            pr_info("[GPIO_DVS][%s] %d gpio failed to set OUT_LH to %d\n",
                __func__, available_gpios_sc9830[gpionum].gpio_num, temp_lh);
    }
}
/****************************************************************/

/****************************************************************/
/* Define this function in accordance with the specification of each BB vendor */
static void undo_sleepgpio(void)
{
    int i;
    int gpio_num;

    pr_info("[GPIO_DVS][%s] ++\n", __func__);

    for (i = 0; i < sleepdebug_table.gpio_count; i++) {
        gpio_num = sleepdebug_table.gpioinfo[i].gpio_num;
        /*
         * << Caution >>
         * If it's necessary,
         * change the following function to another appropriate one
         * or delete it
         */
        setgpio_for_sleepdebug(gpio_num, gpiomap_result.sleep[gpio_num]);
    }

    pr_info("[GPIO_DVS][%s] --\n", __func__);
    return;
}
/****************************************************************/
#endif

/********************* Fixed Code Area !***************************/
#ifdef SECGPIO_SLEEP_DEBUGGING
static void set_sleepgpio(void)
{
    int i;
    int gpio_num;
    uint16_t set_data;

    pr_info("[GPIO_DVS][%s] ++, cnt=%d\n",
        __func__, sleepdebug_table.gpio_count);

    for (i = 0; i < sleepdebug_table.gpio_count; i++) {
        pr_info("[GPIO_DVS][%d] gpio_num(%d), io(%d), pupd(%d), lh(%d)\n",
            i, sleepdebug_table.gpioinfo[i].gpio_num,
            sleepdebug_table.gpioinfo[i].io,
            sleepdebug_table.gpioinfo[i].pupd,
            sleepdebug_table.gpioinfo[i].lh);

        gpio_num = sleepdebug_table.gpioinfo[i].gpio_num;

        // to prevent a human error caused by "don't care" value
        if( sleepdebug_table.gpioinfo[i].io == 1)       /* IN */
            sleepdebug_table.gpioinfo[i].lh =
                GET_GPIO_LH(gpiomap_result.sleep[gpio_num]);
        else if( sleepdebug_table.gpioinfo[i].io == 2)      /* OUT */
            sleepdebug_table.gpioinfo[i].pupd =
                GET_GPIO_PUPD(gpiomap_result.sleep[gpio_num]);

        set_data = GET_RESULT_GPIO(
            sleepdebug_table.gpioinfo[i].io,
            sleepdebug_table.gpioinfo[i].pupd,
            sleepdebug_table.gpioinfo[i].lh);

        setgpio_for_sleepdebug(gpio_num, set_data);
    }

    pr_info("[GPIO_DVS][%s] --\n", __func__);
    return;
}
#endif

static struct gpio_dvs_t gpio_dvs = {
    .result = &gpiomap_result,
    .count = AP_GPIO_COUNT,
    .check_init = false,
    .check_sleep = false,
    .check_gpio_status = check_gpio_status,
#ifdef SECGPIO_SLEEP_DEBUGGING
    .sdebugtable = &sleepdebug_table,
    .set_sleepgpio = set_sleepgpio,
    .undo_sleepgpio = undo_sleepgpio,
#endif
};

static struct platform_device secgpio_dvs_device = {
    .name   = "secgpio_dvs",
    .id     = -1,
    .dev.platform_data = &gpio_dvs,
};

static struct platform_device *secgpio_dvs_devices[] __initdata = {
    &secgpio_dvs_device,
};

static int __init secgpio_dvs_device_init(void)
{
    return platform_add_devices(
        secgpio_dvs_devices, ARRAY_SIZE(secgpio_dvs_devices));
}
arch_initcall(secgpio_dvs_device_init);
/****************************************************************/


