/* drivers/gpu/drm/sprd/regs-gsp.h
 *
 * Register definition file for GSP driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef SPRD_REGS_GSP_H
#define SPRD_REGS_GSP_H

/*
 * Register part
 */
#include <linux/types.h>

#define SPRD_GSP_CFG			(0x0000)
#define SPRD_GSP_INT_CFG		(0x0004)
#define SPRD_GSP_CMD_ADDR		(0x0008)
#define SPRD_GSP_CMD_CFG		(0x000c)
#define SPRD_DES_DATA_CFG		(0x0010)
#define SPRD_DES_Y_ADDR			(0x0014)
#define	SPRD_DES_UV_ADDR		(0x0018)
#define SPRD_DES_V_ADDR			(0x001c)
#define	SPRD_DES_PITCH			(0x0020)
#define	SPRD_DES_DATA_ENDIAN	(0x0024)
#define SPRD_LAYER0_DES_SIZE	(0x0028)

// Layer0
#define SPRD_LAYER0_CFG			(0x0030)
#define SPRD_LAYER0_Y_ADDR		(0x0034)
#define SPRD_LAYER0_UV_ADDR		(0x0038)
#define SPRD_LAYER0_VA_ADDR		(0x003c)
#define SPRD_LAYER0_PITCH		(0x0040)
#define SPRD_LAYER0_CLIP_START	(0x0044)
#define SPRD_LAYER0_CLIP_SIZE	(0x0048)
#define SPRD_LAYER0_DES_START	(0x004c)
#define SPRD_LAYER0_GREY_RGB	(0x0050)
#define SPRD_LAYER0_ENDIAN		(0x0054)
#define SPRD_LAYER0_ALPHA		(0x0058)
#define SPRD_LAYER0_CK			(0x005c)

//Layer1
#define SPRD_LAYER1_CFG			(0x0060)
#define SPRD_LAYER1_Y_ADDR		(0x0064)
#define SPRD_LAYER1_UV_ADDR		(0x0068)
#define SPRD_LAYER1_VA_ADDR		(0x006c)
#define SPRD_LAYER1_PITCH		(0x0070)
#define SPRD_LAYER1_CLIP_START	(0x0074)
#define SPRD_LAYER1_CLIP_SIZE	(0x0078)
#define SPRD_LAYER1_DES_START	(0x007c)
#define SPRD_LAYER1_GREY_RGB	(0x0080)
#define SPRD_LAYER1_ENDIAN		(0x0084)
#define SPRD_LAYER1_ALPHA		(0x0088)
#define SPRD_LAYER1_CK			(0x008c)

#define SPRD_GSP_CFG_SCALE_EN_MASK				(1 << 12)
#define SPRD_GSP_CFG_SCALE_STATUS_CLEAR_MASK	(1 << 15)
#define SPRD_GSP_INT_CFG_INT_CLR_MASK			(1 << 16)
#define SPRD_GSP_CFG_ERR_FLAG_MASK	 			(0x1 << 2)
#define SPRD_GSP_CFG_ERR_CODE_MASK	 			(0x1f << 3)
#define SPRD_GSP_CFG_L0_EN_MASK					(1 << 16)
#define SPRD_LAYER0_CFG_IMG_FORMAT_L0_MASK		(0xf << 0)
#define SPRD_LAYER0_CFG_ROT_ANGLE_MASK	 		(0x7 << 16)
#define SPRD_LAYER0_CFG_ROW_TAP_MODE_MASK 		(0x3 << 24)
#define SPRD_LAYER0_CFG_COL_TAP_MODE_MASK 		(0x3 << 26)
#define SPRD_DEST_DATA_CFG_IMG_FORMAT_MASK		(0x7 << 0)

#define SPRD_GSP_CFG_SCALE_EN_SET(x)			((x) << 12)
#define SPRD_GSP_CFG_SCALE_STATUS_CLEAR_SET(x)	((x) << 15)
#define SPRD_GSP_INT_CFG_INT_CLR_SET(x)			((x) << 16)
#define SPRD_GSP_INT_CFG_INT_EN_SET(x)			((x) << 0)
#define SPRD_GSP_INT_CFG_INT_MODE_SET(x)		((x) << 8)
#define SPRD_GSP_CFG_L0_EN_SET(x)				((x) << 16)
#define SPRD_GSP_CFG_RUN_SET(x)					((x) << 0)
#define SPRD_LAYER0_CFG_IMG_FORMAT_L0_SET(x)	((x) << 0)
#define SPRD_LAYER0_CFG_ROT_ANGLE_SET(x) 		((x) << 16)
#define SPRD_LAYER0_CFG_ROW_TAP_MODE_SET(x)		((x) << 24)
#define SPRD_LAYER0_CFG_COL_TAP_MODE_SET(x)		((x) << 26)
#define SPRD_DEST_DATA_CFG_IMG_FORMAT_SET(x)	((x) << 0)

#define SPRD_GSP_CFG_ERR_FLAG_GET(x) 			((x) >> 2)
#define SPRD_GSP_CFG_ERR_CODE_GET(x) 			((x) >> 3)

typedef enum _GSP_IRQ_MODE_ {
	GSP_IRQ_MODE_PULSE = 0x00, GSP_IRQ_MODE_LEVEL, GSP_IRQ_MODE_LEVEL_INVALID,
} GSP_IRQ_MODE_E;

typedef enum _GSP_IRQ_TYPE_ {
	GSP_IRQ_TYPE_DISABLE = 0x00, GSP_IRQ_TYPE_ENABLE, GSP_IRQ_TYPE_INVALID,
} GSP_IRQ_TYPE_E;

typedef enum _GSP_ROT_ANGLE_TAG_ {
	GSP_ROT_ANGLE_0 = 0x00,
	GSP_ROT_ANGLE_90,
	GSP_ROT_ANGLE_180,
	GSP_ROT_ANGLE_270,
	GSP_ROT_ANGLE_0_M,
	GSP_ROT_ANGLE_90_M,
	GSP_ROT_ANGLE_180_M,
	GSP_ROT_ANGLE_270_M,
	GSP_ROT_ANGLE_MAX_NUM,
} GSP_ROT_ANGLE_E;

/*Original: B3B2B1B0*/
typedef enum _GSP_WORD_ENDIAN_TAG_ {
	GSP_WORD_ENDN_0 = 0x00, /*B3B2B1B0*/
	GSP_WORD_ENDN_1, /*B0B1B2B3*/
	GSP_WORD_ENDN_2, /*B2B3B0B1*/
	GSP_WORD_ENDN_3, /*B1B0B3B2*/
	GSP_WORD_ENDN_MAX_NUM,
} GSP_WORD_ENDN_E;

/*Original: B7B6B5B4B3B2B1B0*/
typedef enum _GSP_LONG_WORD_ENDN_TAG_ {
	GSP_LNG_WRD_ENDN_0, /*B7B6B5B4B3B2B1B0*/
	GSP_LNG_WRD_ENDN_1, GSP_LNG_WRD_ENDN_MAX, /*B3B2B1B0_B7B6B5B4*/
} GSP_LNG_WRD_ENDN_E;

typedef enum _GSP_RGB_SWAP_MOD_TAG_ {
	GSP_RGB_SWP_RGB = 0x00,
	GSP_RGB_SWP_RBG,
	GSP_RGB_SWP_GRB,
	GSP_RGB_SWP_GBR,
	GSP_RGB_SWP_BGR,
	GSP_RGB_SWP_BRG,
	GSP_RGB_SWP_MAX,
} GSP_RGB_SWAP_MOD_E;

typedef enum _GSP_A_SWAP_MOD_TAG_ {
	GSP_A_SWAP_ARGB, GSP_A_SWAP_RGBA, GSP_A_SWAP_MAX,
} GSP_A_SWAP_MOD_E;

typedef enum _GSP_DATA_FMT_TAG_ {
	GSP_FMT_ARGB888 = 0x00,
	GSP_FMT_RGB888,
	GSP_FMT_CMPESS_RGB888,
	GSP_FMT_ARGB565,
	GSP_FMT_RGB565,
	GSP_FMT_YUV420_2P,
	GSP_FMT_YUV420_3P,
	GSP_FMT_YUV400,
	GSP_FMT_YUV422,
	GSP_FMT_8BPP,
	GSP_FMT_PMARGB,
	GSP_FMT_MAX_NUM,
} GSP_DATA_FMT_E;

typedef enum _GSP_ERR_CODE_TAG_ {
	/*GSP HW defined err code, start*/
	GSP_NO_ERR = 0,
	GSP_DES_SIZE_ERR = 1,
	GSP_SCL_OUT_RNG_ERR = 2,
	GSP_SCAL_NO_SAME_XY_COOR_ERR = 3,
	GSP_DES_FRMT_ERR0 = 4,
	GSP_LYER0_FRMT_ERR = 5,
	GSP_LYER1_FRMT_ERR = 6,
	GSP_DES_R5_SWAP_ERR = 7,
	GSP_LYER0_R5_SWAP_ERR = 8,
	GSP_LYER1_R5_SWAP_ERR = 9,
	GSP_LYER0_CLP_SIZE_ZERO_ERR = 10,
	GSP_LYER1_CLP_SIZE_ZERO_ERR = 11,
	GSP_DES_PITCH_ZERO_ERR = 12,
	GSP_LYER0_PITCH_ZERO_ERR = 13,
	GSP_LYER1_PITCH_ZERO_ERR = 14,
	GSP_LYER0_CLP_SITUATION_ERR = 15,
	GSP_LYER1_CLP_SITUATION_ERR = 16,
	GSP_LYER0_OUT_SITUATION_ERR = 17,
	GSP_LYER1_OUT_SITUATION_ERR = 18,
	GSP_CMD_NUM_ERR = 19,
	GSP_ALL_MODULE_DISABLE_ERR = 20,
	/*GSP HW defined err code, end*/

	/*GSP kernel driver defined err code, start*/
	GSP_KERNEL_FULL = 0x81, //kernel driver only supports GSP_MAX_USER clients
	GSP_KERNEL_OPEN_INTR = 0x82, //wait open semaphore, interrupt by signal
	GSP_KERNEL_CFG_INTR = 0x83, //wait hw semaphore, interrupt by signal
	GSP_KERNEL_COPY_ERR = 0x84, //copy cfg params err
	GSP_KERNEL_CALLER_NOT_OWN_HW = 0x85, // the caller thread don't get the GSP-HW semaphore, have no power to trigger,waite done.
	GSP_KERNEL_WORKAROUND_ALLOC_ERR = 0x86, //alloc CMDQ descriptor memory err
	GSP_KERNEL_WORKAROUND_WAITDONE_TIMEOUT = 0x87,
	GSP_KERNEL_WORKAROUND_WAITDONE_INTR = 0x88,
	GSP_KERNEL_GEN_OUT_RANG = 0x89,
	GSP_KERNEL_GEN_ALLOC_ERR = 0x8A,
	GSP_KERNEL_GEN_COMMON_ERR = 0x8B,
	GSP_KERNEL_WAITDONE_TIMEOUT = 0x8C,
	GSP_KERNEL_WAITDONE_INTR = 0x8D,
	GSP_KERNEL_FORCE_EXIT = 0x8E, //not an err
	GSP_KERNEL_CTL_CMD_ERR = 0x8F, //not an err
	/*GSP kernel driver defined err code, end*/

	/*GSP HAL defined err code, start*/

	GSP_HAL_PARAM_ERR = 0xA0, // common hal interface parameter err
	GSP_HAL_PARAM_CHECK_ERR = 0xA1, // GSP config parameter check err
	GSP_HAL_VITUAL_ADDR_NOT_SUPPORT = 0xA2, // GSP can't process virtual address
	GSP_HAL_ALLOC_ERR = 0xA3,
	GSP_HAL_KERNEL_DRIVER_NOT_EXIST = 0xA4, // gsp driver nod not exist
	/*GSP HAL defined err code, end*/

	GSP_ERR_MAX_NUM,
} GSP_ERR_CODE_E;

typedef enum _GSP_LAYER_SRC_DATA_FMT_TAG_ {
	GSP_SRC_FMT_ARGB888 = 0x00,
	GSP_SRC_FMT_RGB888,
	GSP_SRC_FMT_ARGB565,
	GSP_SRC_FMT_RGB565,
	GSP_SRC_FMT_YUV420_2P,
	GSP_SRC_FMT_YUV420_3P,
	GSP_SRC_FMT_YUV400_1P,
	GSP_SRC_FMT_YUV422_2P,
	GSP_SRC_FMT_8BPP,
	GSP_SRC_FMT_MAX_NUM,
} GSP_LAYER_SRC_DATA_FMT_E;

typedef enum _GSP_LAYER_DST_DATA_FMT_TAG_ {
	GSP_DST_FMT_ARGB888 = 0x00,
	GSP_DST_FMT_RGB888,
	GSP_DST_FMT_ARGB565,
	GSP_DST_FMT_RGB565,
	GSP_DST_FMT_YUV420_2P,
	GSP_DST_FMT_YUV420_3P,
	GSP_DST_FMT_YUV422_2P,
	GSP_DST_FMT_MAX_NUM,
} GSP_LAYER_DST_DATA_FMT_E;

typedef struct _GSP_ENDIAN_INFO_TAG_ {
	GSP_LNG_WRD_ENDN_E y_lng_wrd_endn;
	GSP_WORD_ENDN_E y_word_endn;
	GSP_LNG_WRD_ENDN_E uv_lng_wrd_endn;
	GSP_WORD_ENDN_E uv_word_endn;
	GSP_LNG_WRD_ENDN_E va_lng_wrd_endn;
	GSP_WORD_ENDN_E va_word_endn;
	GSP_RGB_SWAP_MOD_E rgb_swap_mode;
	GSP_A_SWAP_MOD_E a_swap_mode;
} GSP_ENDIAN_INFO_PARAM_T;

typedef struct _GSP_RGB_TAG_ {
	uint8_t b_val;
	uint8_t g_val;
	uint8_t r_val;
	uint8_t a_val; //if necessary
} GSP_RGB_T;

typedef struct _GSP_POS_TAG_ {
	uint16_t pos_pt_x;
	uint16_t pos_pt_y;
} GSP_POS_PT_T;

typedef struct _GSP_RECT_TAG {
	uint16_t st_x;
	uint16_t st_y;
	uint16_t rect_w;
	uint16_t rect_h;
} GSP_RECT_T;

typedef struct _GSP_DATA_ADDR_TAG {
	uint32_t addr_y;
	uint32_t addr_uv;
	uint32_t addr_v;   //for 3 plane
} GSP_DATA_ADDR_T;

typedef struct _GSP_LAYER0_CONFIG_INFO_TAG_ {
	GSP_DATA_ADDR_T src_addr;
	uint32_t pitch;
	GSP_RECT_T clip_rect;
	GSP_RECT_T des_rect;
	GSP_RGB_T grey;
	GSP_RGB_T colorkey;
	GSP_ENDIAN_INFO_PARAM_T endian_mode;
	GSP_LAYER_SRC_DATA_FMT_E img_format;
	GSP_ROT_ANGLE_E rot_angle;
	uint8_t row_tap_mode;
	uint8_t col_tap_mode;
	uint8_t alpha;
	uint8_t colorkey_en;
	uint8_t pallet_en;
	uint8_t scaling_en;
	uint8_t layer_en;
	uint8_t pmargb_en;
	uint8_t pmargb_mod;
} GSP_LAYER0_CONFIG_INFO_T;

typedef struct _GSP_LAYER1_CONFIG_INFO_TAG_ {
	GSP_DATA_ADDR_T src_addr;
	uint32_t pitch;
	GSP_RECT_T clip_rect;
	GSP_POS_PT_T des_pos;
	GSP_RGB_T grey;
	GSP_RGB_T colorkey;
	GSP_ENDIAN_INFO_PARAM_T endian_mode;
	GSP_LAYER_SRC_DATA_FMT_E img_format;
	GSP_ROT_ANGLE_E rot_angle;
	uint8_t row_tap_mode;
	uint8_t col_tap_mode;
	uint8_t alpha;
	uint8_t colorkey_en;
	uint8_t pallet_en;
	uint8_t layer_en;
	uint8_t pmargb_en;
	uint8_t pmargb_mod;
} GSP_LAYER1_CONFIG_INFO_T;

typedef struct _GSP_LAYER_DST_CONFIG_INFO_TAG_ {
	GSP_DATA_ADDR_T src_addr;
	uint32_t pitch;
	GSP_ENDIAN_INFO_PARAM_T endian_mode;
	GSP_LAYER_DST_DATA_FMT_E img_format;
	uint8_t compress_r8_en;
	//uint8_t                      layer_en;
} GSP_LAYER_DES_CONFIG_INFO_T;

typedef struct _GSP_MISC_CONFIG_INFO_TAG_ {
	uint8_t dithering_en;
	uint8_t gsp_gap;   //gsp ddr gap(0~255)
	uint8_t gsp_clock;   //gsp clock(0:96M 1:153.6M 2:192M 3:256M)
	uint8_t ahb_clock;   //ahb clock(0:26M 1:76M 2:128M 3:192M)
	uint8_t split_pages;   //0:not split  1: split
} GSP_MISC_CONFIG_INFO_T;

typedef struct _GSP_CONFIG_INFO_TAG_ {
	GSP_MISC_CONFIG_INFO_T misc_info;
	GSP_LAYER0_CONFIG_INFO_T layer0_info;
	GSP_LAYER1_CONFIG_INFO_T layer1_info;
	GSP_LAYER_DES_CONFIG_INFO_T layer_des_info;
} GSP_CONFIG_INFO_T;

#define GSP_IO_MAGIC                'G'
#define GSP_IO_SET_PARAM            _IOW(GSP_IO_MAGIC, GSP_SET_PARAM,GSP_CONFIG_INFO_T)
#define GSP_IO_TRIGGER_RUN          _IO(GSP_IO_MAGIC, GSP_TRIGGER_RUN)
#define GSP_IO_WAIT_FINISH          _IO(GSP_IO_MAGIC, GSP_WAIT_FINISH)

#ifndef CEIL
#define CEIL(x,y)   ({uint32_t __x = (x),__y = (y);(__x + __y -1)/__y;})
#endif

/**---------------------------------------------------------------------------*
 **                         Dependencies                                      *
 **---------------------------------------------------------------------------*/
#include <soc/sprd/sci_glb_regs.h>
#include <soc/sprd/globalregs.h> //define IRQ_GSP_INT
#include <linux/delay.h>
#include <linux/clk.h>

#ifdef CONFIG_ARCH_SCX15
#ifdef CONFIG_SHARK_DOLPHIN
#define GSP_IOMMU_WORKAROUND1
#define CONFIG_HAS_EARLYSUSPEND_GSP// dolphin use early suspend, shark use suspend
#endif
#else
#define GSP_WORK_AROUND1
#endif

/**---------------------------------------------------------------------------*
 **                         Macro Definition                              *
 **---------------------------------------------------------------------------*/
//GSP job config relative
#define GSP_MOD_EN          (REG_AP_AHB_AHB_EB)
#define GSP_SOFT_RESET      (REG_AP_AHB_AHB_RST)

//GSP DDR access relative
//#define SPRD_AONAPB_PHYS		0X402E0000
#define GSP_EMC_MATRIX_BASE		(REG_AON_APB_APB_EB1) // GSP access DDR through matrix to AXI, must enable gsp-gate on this matrix
#define GSP_EMC_MATRIX_BIT		(BIT_DISP_EMC_EB) // [11] gsp-gate bit on matrix , EMC is DDR controller, should always enabled
//GSP inner work loggy clock ctl
//#define SPRD_APBCKG_PHYS		0X71200000
#define GSP_CLOCK_BASE		(REG_AP_CLK_GSP_CFG)

//force enable GSP inner work loggy clock, used for debug
//#define SPRD_AHB_PHYS			0X20D00000
#define GSP_AUTO_GATE_ENABLE_BASE		(REG_AP_AHB_AP_SYS_AUTO_SLEEP_CFG)
#define GSP_AUTO_GATE_ENABLE_BIT		(BIT_GSP_AUTO_GATE_EN)//[8] is gate switch, 1:GSP work clk enable by busy signal, 0:force enable, control by busy will save power
#define GSP_CKG_FORCE_ENABLE_BIT		(BIT_GSP_CKG_FORCE_EN)

//GSP register set clock , through AHB bus
//#define SPRD_APBCKG_PHYS      0X71200000
#define GSP_AHB_CLOCK_BASE      (REG_AP_CLK_AP_AHB_CFG)
#define GSP_AHB_CLOCK_26M_BIT   (0)// [1:0] is used by GSP, 0:26M
#define GSP_AHB_CLOCK_192M_BIT  (3)// [1:0] is used by GSP, 0:26M 1:76M 2:128M 3:192M
//interrupt relative
#define TB_GSP_INT 			(IRQ_GSP_INT)  //gsp hardware irq number
#define GSP_IRQ_BIT			SCI_INTC_IRQ_BIT(TB_GSP_INT) //gsp hardware irq bit, == (TB_GSP_INT % 32)
#define GSP_SOFT_RST_BIT    (BIT_GSP_SOFT_RST) //gsp chip module soft reset bit
#define GSP_MOD_EN_BIT      (BIT_GSP_EB) //gsp chip module enable bit
#define GSP_REG_BASE        (SPRD_GSP_BASE)
#define GSP_HOR_COEF_BASE   (GSP_REG_BASE + 0x90)
#define GSP_VER_COEF_BASE   (GSP_REG_BASE + 0x110)

#ifndef GSP_ASSERT
#define GSP_ASSERT()        do{}while(1)
#endif

#ifdef CONFIG_ARCH_SCX15// dolphin
#define GSP_CLOCK_PARENT3		("clk_153m6")
#define GSP_CLOCK_PARENT2		("clk_128m")
#define GSP_CLOCK_PARENT1		("clk_96m")
#define GSP_CLOCK_PARENT0		("clk_76m8")
#else //shark
#define GSP_CLOCK_PARENT3		("clk_256m")
#define GSP_CLOCK_PARENT2		("clk_192m")
#define GSP_CLOCK_PARENT1		("clk_153m6")
#define GSP_CLOCK_PARENT0		("clk_96m")
#endif
#define GSP_CLOCK_NAME			("clk_gsp")

#define GSP_EMC_CLOCK_PARENT_NAME		("clk_aon_apb")
#define GSP_EMC_CLOCK_NAME				("clk_gsp_emc")

#include <soc/sprd/sci.h>
#define GSP_REG_READ(reg)  (*(volatile uint32_t*)(reg))
#define GSP_REG_WRITE(reg,value)	(*(volatile uint32_t*)reg = value)

#define GSP_EMC_MATRIX_ENABLE()     sci_glb_set(GSP_EMC_MATRIX_BASE, GSP_EMC_MATRIX_BIT)
#define GSP_CLOCK_SET(sel)          sci_glb_write(GSP_CLOCK_BASE, (sel), 0x3)
#define GSP_AUTO_GATE_ENABLE()      sci_glb_set(GSP_AUTO_GATE_ENABLE_BASE, GSP_AUTO_GATE_ENABLE_BIT)
#define GSP_AUTO_GATE_DISABLE()     sci_glb_clr(GSP_AUTO_GATE_ENABLE_BASE, GSP_AUTO_GATE_ENABLE_BIT)

#define GSP_FORCE_GATE_ENABLE()      sci_glb_set(GSP_AUTO_GATE_ENABLE_BASE, GSP_CKG_FORCE_ENABLE_BIT)
#define GSP_AHB_CLOCK_SET(sel)      sci_glb_write(GSP_AHB_CLOCK_BASE, (sel), 0x3)
#define GSP_AHB_CLOCK_GET()      	sci_glb_read(GSP_AHB_CLOCK_BASE,0x3)

//0x402B001C multi-media force shutdown [25]
//0x402E0000 MM enable
#define GSP_ENABLE_MM(addr)\
		{\
	sci_glb_clr((REG_PMU_APB_PD_MM_TOP_CFG),(BIT_PD_MM_TOP_FORCE_SHUTDOWN));\
	sci_glb_set(REG_AON_APB_APB_EB0,(BIT_PD_MM_TOP_FORCE_SHUTDOWN));\
		}

#if defined(CONFIG_ARCH_SCX15) || defined(CONFIG_ARCH_SCX30G) || defined(CONFIG_ARCH_SCX35L)
//in dolphin,soft reset should not be called for iommu workaround
#ifdef CONFIG_OF
#define GSP_MMU_CTRL_BASE (gsp_mmu_ctrl_addr)
#else
#ifdef CONFIG_ARCH_SCX30G
#define GSP_MMU_CTRL_BASE (SPRD_GSPMMU_BASE+0x8000)
#else
#define GSP_MMU_CTRL_BASE (SPRD_GSPMMU_BASE+0x4000)
#endif
#endif

#define GSP_HWMODULE_SOFTRESET()\
		{\
	sci_glb_set(GSP_SOFT_RESET,GSP_SOFT_RST_BIT);\
	udelay(10);\
	sci_glb_clr(GSP_SOFT_RESET,GSP_SOFT_RST_BIT);\
	GSP_REG_WRITE(GSP_MMU_CTRL_BASE,0x10000001);\
		}
#else
#define GSP_HWMODULE_SOFTRESET()\
		sci_glb_set(GSP_SOFT_RESET,GSP_SOFT_RST_BIT);\
		udelay(10);\
		sci_glb_clr(GSP_SOFT_RESET,GSP_SOFT_RST_BIT)
#endif

#define GSP_HWMODULE_ENABLE()       sci_glb_set(GSP_MOD_EN,GSP_MOD_EN_BIT)
#define GSP_HWMODULE_DISABLE()		sci_glb_clr(GSP_MOD_EN,GSP_MOD_EN_BIT)
#endif /* SPRD_REGS_GSP_H */
