/*
 * Copyright (C) 2012 Samsung Electronics Co.Ltd
 * Authors:
 *	Jinyoung Jeon <jy0.jeon@samsung.com>
 *	Vijayakumar <vijay.bvb@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <linux/math64.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/errno.h>
#include <linux/irq.h>
#include <linux/kthread.h>
#include <linux/io.h>
#include <linux/pid.h>
#include <linux/pm_runtime.h>
#include <soc/sprd/hardware.h>

#include <drm/drmP.h>
#include <drm/sprd_drm.h>

#include "sprd_drm_ipp.h"
#include "drm_fourcc.h"
#include "sprd_drm_gsp.h"

#ifdef GSP_WORK_AROUND1
#include <linux/dma-mapping.h>
#endif

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/device.h>
#endif

#define get_gsp_context(dev)	platform_get_drvdata(to_platform_device(dev))
#define gsp_read(offset)		readl(ctx->regs + (offset))
#define gsp_write(cfg, offset)	writel(cfg, ctx->regs + (offset))

#ifdef CONFIG_OF
#if defined(CONFIG_ARCH_SCX15) || defined(CONFIG_ARCH_SCX30G) || defined(CONFIG_ARCH_SCX35L)
uint32_t gsp_mmu_ctrl_addr = 0;
#endif
#endif

/*
 * A structure of gsp context.
 *
 * @ippdrv: prepare initialization using ippdrv.
 * @lock: locking of operations.
 * @regs: GSP iomapped register.
 * @reg_size: register size.
 * @gsp_clk: gsp clock.
 * @emc_clk: emc clock.
 * @id: gsp id.
 * @irq: irq number.
 */
struct gsp_context {
	struct sprd_drm_ippdrv ippdrv;
	void __iomem *regs;
	size_t reg_size;
	GSP_CONFIG_INFO_T gsp_cfg;
	struct mutex lock;
	struct clk *gsp_clk;
	struct clk *emc_clk;
	int id;
	int irq;
	int cur_buf_id[SPRD_DRM_OPS_MAX];
	bool suspended;
	volatile u32 coef_force_calc;
#ifdef CONFIG_OF
	struct device *gsp_of_dev;
#endif
};

#define GSP_RATIO(x, y)        ((65536 * x) / y)
#define GSP_UP_MAX             GSP_RATIO(1, 4)
#define GSP_DOWN_MIN           GSP_RATIO(4, 1)

#ifdef CACHE_COEF
typedef struct _coef_entry {
	struct _coef_entry* prev;
	struct _coef_entry* next;
	uint16_t in_w;
	uint16_t in_h;
	uint16_t out_w;
	uint16_t out_h;
	uint32_t coef[COEF_MATRIX_ENTRY_SIZE];
} Coef_Entry;

Coef_Entry *Coef_Entry_List_Head = NULL;

static uint32_t s_cache_coef_init_flag = 0;
#endif

static uint8_t _init_pool(void *buffer_ptr, uint32_t buffer_size,
		GSC_MEM_POOL * pool_ptr)
{
	if (NULL == buffer_ptr || 0 == buffer_size || NULL == pool_ptr)
		return FALSE;

	if (buffer_size < MIN_POOL_SIZE)
		return FALSE;

	pool_ptr->begin_addr = (uint32_t) buffer_ptr;
	pool_ptr->total_size = buffer_size;
	pool_ptr->used_size = 0;
	DRM_DEBUG("GSP_init_pool:begin_addr:0x%08x,total_size:%d,used_size:%d\n",
			pool_ptr->begin_addr, pool_ptr->total_size,
			pool_ptr->used_size);
	return TRUE;
}

static void *_allocate(uint32_t size, uint32_t align_shift,
		GSC_MEM_POOL * pool_ptr)
{
	uint32_t begin_addr = 0;
	uint32_t temp_addr = 0;
	if (NULL == pool_ptr) {
		DRM_ERROR("GSP_Allocate:_Allocate error! \n");
		return NULL;
	}
	begin_addr = pool_ptr->begin_addr;
	temp_addr = begin_addr + pool_ptr->used_size;
	temp_addr = (((temp_addr + (1UL << align_shift) - 1) >> align_shift)
			<< align_shift);
	if (temp_addr + size > begin_addr + pool_ptr->total_size) {
		DRM_ERROR("GSP_Allocate err:temp_addr:0x%08x,size:%d,begin_addr:0x%08x,"
				"total_size:%d,used_size:%d\n", temp_addr, size, begin_addr,
				pool_ptr->total_size, pool_ptr->used_size);
		return NULL;
	}
	pool_ptr->used_size = (temp_addr + size) - begin_addr;
	SCI_MEMSET((void *) temp_addr, 0, size);
	DRM_DEBUG("GSP_Allocate:_Allocate success!%08x \n",temp_addr);
	return (void *) temp_addr;
}

static int64_t div64_s64_s64(int64_t dividend, int64_t divisor)
{
	int8_t sign = 1;
	int64_t dividend_tmp = dividend;
	int64_t divisor_tmp = divisor;
	int64_t ret = 0;
	if (0 == divisor)
		return 0;

	if ((dividend >> 63) & 0x1) {
		sign *= -1;
		dividend_tmp = dividend * (-1);
	}
	if ((divisor >> 63) & 0x1) {
		sign *= -1;
		divisor_tmp = divisor * (-1);
	}
	ret = div64_s64(dividend_tmp, divisor_tmp);
	ret *= sign;
	return ret;
}

static void normalize_inter(int64_t * data, int16_t * int_data, uint8_t ilen)
{
	uint8_t it;
	int64_t tmp_d = 0;
	int64_t *tmp_data = NULL;
	int64_t tmp_sum_val = 0;
	tmp_data = data;
	tmp_sum_val = 0;
	for (it = 0; it < ilen; it++)
		tmp_sum_val += tmp_data[it];

	if (0 == tmp_sum_val) {
		uint8_t value = 256 / ilen;
		for (it = 0; it < ilen; it++) {
			tmp_d = value;
			int_data[it] = (int16_t) tmp_d;
		}
	} else {
		for (it = 0; it < ilen; it++) {
			tmp_d = div64_s64_s64(tmp_data[it] * (int64_t) 256, tmp_sum_val);
			int_data[it] = (uint16_t) tmp_d;
		}
	}
}

/* ------------------------------------------  */
static int16_t sum_fun(int16_t *data, int8_t ilen)
{
	int8_t i;
	int16_t tmp_sum;
	tmp_sum = 0;

	for (i = 0; i < ilen; i++)
		tmp_sum += *data++;

	return tmp_sum;
}

static void adjust_filter_inter(int16_t *filter, uint8_t ilen)
{
	int32_t i, midi;
	int32_t tmpi, tmp_S;
	int32_t tmp_val = 0;

	tmpi = sum_fun(filter, ilen) - 256;
	midi = ilen >> 1;
	GSC_SIGN2(tmp_val, tmpi);

	if ((tmpi & 1) == 1)  // tmpi is odd
	{
		filter[midi] = filter[midi] - tmp_val;
		tmpi -= tmp_val;
	}

	tmp_S = GSC_ABS(tmpi / 2);

	if ((ilen & 1) == 1)  // ilen is odd
	{
		for (i = 0; i < tmp_S; i++) {
			filter[midi - (i + 1)] = filter[midi - (i + 1)] - tmp_val;
			filter[midi + (i + 1)] = filter[midi + (i + 1)] - tmp_val;
		}
	} else { /* ilen is even */
		for (i = 0; i < tmp_S; i++) {
			filter[midi - (i + 1)] = filter[midi - (i + 1)] - tmp_val;
			filter[midi + i] = filter[midi + i] - tmp_val;
		}
	}

	if (filter[midi] > 255) {
		tmp_val = filter[midi];
		filter[midi] = 255;
		filter[midi - 1] = filter[midi - 1] + tmp_val - 255;
	}
}

static int16_t cal_y_mode_l_coef(int16_t coef_lenght, int16_t * coef_data_ptr,
		int16_t N, int16_t M, GSC_MEM_POOL * pool_ptr)
{
	int8_t mount;
	int16_t i, mid_i, kk, j, sum_val;
	int64_t *filter = _allocate(GSC_COUNT * sizeof(int64_t), 3, pool_ptr);
	int64_t *tmp_filter = _allocate(GSC_COUNT * sizeof(int64_t), 3, pool_ptr);
	int16_t *normal_filter = _allocate(GSC_COUNT * sizeof(int16_t), 2,
			pool_ptr);

	if (NULL == filter || NULL == tmp_filter || NULL == normal_filter)
		return 1;

	mid_i = coef_lenght >> 1;
	filter[mid_i] = div64_s64_s64((int64_t)((int64_t) N << GSC_FIX),
			(int64_t) MAX(M, N));
	for (i = 0; i < mid_i; i++) {
		int64_t angle_x = div64_s64_s64(
				(int64_t) ARC_32_COEF * (int64_t)(i + 1) * (int64_t) N,
				(int64_t) MAX(M,
						N) * (int64_t) 8);
		int64_t angle_y = div64_s64_s64(
				(int64_t) ARC_32_COEF * (int64_t)(i + 1) * (int64_t) N,
				(int64_t)(M * N) * (int64_t) 8);
		int32_t value_x = sin_32((int32_t) angle_x);
		int32_t value_y = sin_32((int32_t) angle_y);
		filter[mid_i + i + 1] = div64_s64_s64(
				(int64_t)((int64_t) value_x * (int64_t)(1 << GSC_FIX)),
				(int64_t)((int64_t) M * (int64_t) value_y));
		filter[mid_i - (i + 1)] = filter[mid_i + i + 1];
	}
	for (i = -1; i < mid_i; i++) {
		int32_t angle_32 = (int32_t) div64_s64_s64(
				(int64_t)(
						(int64_t) 2 * (int64_t)(mid_i - i - 1) *
						(int64_t) ARC_32_COEF), (int64_t) coef_lenght);
		int64_t a = (int64_t) 9059697;
		int64_t b = (int64_t) 7717519;
		int64_t t = a - ((b * cos_32(angle_32)) >> 30);
		filter[mid_i + i + 1] = (t * filter[mid_i + i + 1]) >> GSC_FIX;
		filter[mid_i - (i + 1)] = filter[mid_i + i + 1];
	}
	for (i = 0; i < 8; i++) {
		mount = 0;
		for (j = i; j < coef_lenght; j += 8) {
			tmp_filter[mount] = filter[j];
			mount++;
		}
		normalize_inter(tmp_filter, normal_filter, (int8_t) mount);
		sum_val = sum_fun(normal_filter, mount);
		if (256 != sum_val)
			adjust_filter_inter(normal_filter, mount);

		mount = 0;
		for (kk = i; kk < coef_lenght; kk += 8) {
			coef_data_ptr[kk] = normal_filter[mount];
			mount++;
		}
	}
	return 0;
}

/* cal Y model */
static int16_t cal_y_scaling_coef(int16_t tap, int16_t D, int16_t I,
		int16_t * y_coef_data_ptr, int16_t dir, GSC_MEM_POOL * pool_ptr)
{
	uint16_t coef_lenght;

	coef_lenght = (uint16_t) (tap * 8);
	SCI_MEMSET(y_coef_data_ptr, 0, coef_lenght * sizeof(int16_t));
	cal_y_mode_l_coef(coef_lenght, y_coef_data_ptr, I, D, pool_ptr);
	return coef_lenght;
}

static int16_t cal_uv_scaling_coef(int16_t tap, int16_t D, int16_t I,
	int16_t * uv_coef_data_ptr, int16_t dir, GSC_MEM_POOL * pool_ptr)
{
	int16_t uv_coef_lenght;

	if ((dir == 1)) {
		uv_coef_lenght = (int16_t) (tap * 8);
		cal_y_mode_l_coef(uv_coef_lenght, uv_coef_data_ptr, I, D, pool_ptr);
	} else {
		if (D > I)
			uv_coef_lenght = (int16_t) (tap * 8);
		else
			uv_coef_lenght = (int16_t) (2 * 8);

		cal_y_mode_l_coef(uv_coef_lenght, uv_coef_data_ptr, I, D, pool_ptr);
	}
	return uv_coef_lenght;
}

static void get_filter(int16_t * coef_data_ptr, int16_t * out_filter,
		int16_t iI_hor, int16_t coef_len, int16_t * filter_len)
{
	int16_t i, pos_start;

	pos_start = coef_len / 2;

	while (pos_start >= iI_hor)
		pos_start -= iI_hor;

	for (i = 0; i < iI_hor; i++) {
		int16_t len = 0;
		int16_t j;
		int16_t pos = pos_start + i;
		while (pos >= iI_hor)
			pos -= iI_hor;

		for (j = 0; j < coef_len; j += iI_hor) {
			*out_filter++ = coef_data_ptr[j + pos];
			len++;
		}
		*filter_len++ = len;
	}
}

static void write_scalar_coef(int16_t * dst_coef_ptr, int16_t * coef_ptr,
		int16_t dst_pitch, int16_t src_pitch)
{
	int i, j;

	for (i = 0; i < 8; i++) {
		for (j = 0; j < src_pitch; j++) {
			*(dst_coef_ptr + j) =
					*(coef_ptr + i * src_pitch + src_pitch - 1 - j);
		}
		dst_coef_ptr += dst_pitch;
	}
}

static void check_coef_range(int16_t * coef_ptr, int16_t rows, int16_t columns,
		int16_t pitch) {
	int16_t i, j;
	int16_t value, diff, sign;
	int16_t *coef_arr[COEF_ARR_ROWS] = { NULL };

	for (i = 0; i < COEF_ARR_ROWS; i++) {
		coef_arr[i] = coef_ptr;
		coef_ptr += pitch;
	}
	for (i = 0; i < rows; i++) {
		for (j = 0; j < columns; j++) {
			value = coef_arr[i][j];
			if (value > 255) {
				diff = value - 255;
				coef_arr[i][j] = 255;
				sign = GSC_ABS(diff);
				if ((sign & 1) == 1) { /* ilen is odd */
					coef_arr[i][j + 1] = coef_arr[i][j + 1] + (diff + 1) / 2;
					coef_arr[i][j - 1] = coef_arr[i][j - 1] + (diff - 1) / 2;
				} else { /* ilen is even */
					coef_arr[i][j + 1] = coef_arr[i][j + 1] + (diff) / 2;
					coef_arr[i][j - 1] = coef_arr[i][j - 1] + (diff) / 2;
				}
			}
		}
	}
}

static void gsp_rearrange_coef(void* src, void*dst, int32_t tap)
{
	uint32_t i, j;
	int16_t *src_ptr, *dst_ptr;

	src_ptr = (int16_t*) src;
	dst_ptr = (int16_t*) dst;
	if (src_ptr == NULL || dst_ptr == NULL)
		return;

	if (0 != dst_ptr)
		memset((void*) dst_ptr, 0x00, 8 * 8 * sizeof(int16_t));

	switch (tap) {
	case 6:
	case 2:
		for (i = 0; i < 8; i++)
			for (j = 0; j < tap; j++)
				*(dst_ptr + i * 8 + 1 + j) = *(src_ptr + i * 8 + j);
	break;
	case 4:
	case 8:
		for (i = 0; i < 8; i++)
			for (j = 0; j < tap; j++)
				*(dst_ptr + i * 8 + j) = *(src_ptr + i * 8 + j);
	break;
	}
}

#ifdef CACHE_COEF
static int32_t cache_coef_init(void)
{
	Coef_Entry *Coef_Entry_Array = NULL;
	uint32_t i = 0;
	DRM_DEBUG("GSP_CACHE_COEF:init\n");

	if (s_cache_coef_init_flag == 0) {
		Coef_Entry_Array = (Coef_Entry *) kmalloc(
				sizeof(Coef_Entry) * CACHED_COEF_CNT_MAX, GFP_KERNEL);

		if (Coef_Entry_Array) {
			memset((void*) Coef_Entry_Array, 0,
					sizeof(Coef_Entry) * CACHED_COEF_CNT_MAX);

			Coef_Entry_List_Head = &Coef_Entry_Array[0];
			Coef_Entry_Array[0].prev = &Coef_Entry_Array[0];
			Coef_Entry_Array[0].next = &Coef_Entry_Array[0];
			i++;

			while (i < CACHED_COEF_CNT_MAX) {
				LIST_ADD_TO_LIST_HEAD(&Coef_Entry_Array[i]);
				i++;
			}
			s_cache_coef_init_flag = 1;
		} else
			return -1;
	}
	return 0;
}

/*
 func:cache_coef_hit_check
 desc:find the entry have the same in_w in_h out_w out_h
 return:if hit,return the entry pointer; else return null;
 */
static Coef_Entry* cache_coef_hit_check(uint16_t in_w, uint16_t in_h,
		uint16_t out_w, uint16_t out_h) {
	static uint32_t total_cnt = 0;
	static uint32_t hit_cnt = 0;

	Coef_Entry* walk = Coef_Entry_List_Head;

	total_cnt++;
	while (walk->in_w != 0) {
		if (walk->in_w == in_w && walk->in_h == in_h &&
			walk->out_w == out_w && walk->out_h == out_h) {
			hit_cnt++;
			DRM_DEBUG("GSP_CACHE_COEF:hit, hit_ratio:%d percent\n",
					hit_cnt * 100 / total_cnt);
			return walk;
		}
		if (walk->next == Coef_Entry_List_Head)
			break;

		walk = walk->next;
	}
	DRM_DEBUG("GSP_CACHE_COEF:miss\n");
	return NULL;
}

static Coef_Entry* cache_coef_move_entry_to_list_head(Coef_Entry* pEntry) {
	LIST_FETCH_FROM_LIST(pEntry);
	LIST_ADD_TO_LIST_HEAD(pEntry);
	return Coef_Entry_List_Head;
}

#endif

/**---------------------------------------------------------------------------*
 **                         Public Functions                                  *
 **---------------------------------------------------------------------------*/
/****************************************************************************/
/* Purpose: generate scale factor                                           */
/* Author:                                                                  */
/* Input:                                                                   */
/*          i_w:    source image width                                      */
/*          i_h:    source image height                                     */
/*          o_w:    target image width                                      */
/*          o_h:    target image height                                     */
/* Output:                                                                  */
/*          coeff_h_ptr: pointer of horizontal coefficient buffer, the size of which must be at  */
/*                     least SCALER_COEF_TAP_NUM_HOR * 4 bytes              */
/*                    the output coefficient will be located in coeff_h_ptr[0], ......,   */
/*                      coeff_h_ptr[SCALER_COEF_TAP_NUM_HOR-1]              */
/*          coeff_v_ptr: pointer of vertical coefficient buffer, the size of which must be at      */
/*                     least (SCALER_COEF_TAP_NUM_VER + 1) * 4 bytes        */
/*                    the output coefficient will be located in coeff_v_ptr[0], ......,   */
/*                    coeff_h_ptr[SCALER_COEF_TAP_NUM_VER-1] and the tap number */
/*                    will be located in coeff_h_ptr[SCALER_COEF_TAP_NUM_VER] */
/*          temp_buf_ptr: temp buffer used while generate the coefficient   */
/*          temp_buf_ptr: temp buffer size, 6k is the suggest size         */
/* Return:                                                                  */
/* Note:                                                                    */
/****************************************************************************/
static uint8_t gsp_gen_block_ccaler_coef(uint32_t i_w, uint32_t i_h, uint32_t o_w,
		uint32_t o_h, uint32_t hor_tap, uint32_t ver_tap,
		uint32_t *coeff_h_ptr, uint32_t *coeff_v_ptr,
		void *temp_buf_ptr, uint32_t temp_buf_size)
{
	int16_t D_hor = i_w;    /* decimition at horizontal */
	int16_t I_hor = o_w;    /* interpolation at horizontal */
	int16_t *cong_com_hor = 0;
	int16_t *cong_com_ver = 0;
	int16_t *coeff_array = 0;

	uint32_t coef_buf_size = 0;
	int16_t *temp_filter_ptr = NULL;
	int16_t *filter_ptr = NULL;
	uint32_t filter_buf_size = GSC_COUNT * sizeof(int16_t);
	int16_t filter_len[COEF_ARR_ROWS] = { 0 };
	int16_t coef_len = 0;
	GSC_MEM_POOL pool = { 0 };
	uint32_t i = 0;

#ifdef CACHE_COEF
	Coef_Entry* pEntry = NULL;

	if (s_cache_coef_init_flag == 0)
		cache_coef_init();

	if (s_cache_coef_init_flag == 1) {
		pEntry = cache_coef_hit_check(i_w, i_h, o_w, o_h);
		if (pEntry) { /* hit */
			memcpy((void*) coeff_h_ptr, (void*) pEntry->coef,
					COEF_MATRIX_ENTRY_SIZE * 4);
			cache_coef_move_entry_to_list_head(pEntry);
			return TRUE;
		}
	}
#endif

	/* init pool and allocate static array */
	if (!_init_pool(temp_buf_ptr, temp_buf_size, &pool)) {
		DRM_ERROR("GSP_Gen_Block_Ccaler_Coef: _init_pool error! \n");
		return FALSE;
	}

	coef_buf_size = COEF_ARR_ROWS * COEF_ARR_COL_MAX * sizeof(int16_t);
	cong_com_hor = (int16_t*) _allocate(coef_buf_size, 2, &pool);
	cong_com_ver = (int16_t*) _allocate(coef_buf_size, 2, &pool);
	coeff_array = (int16_t*) _allocate(8 * 8, 2, &pool);

	if (NULL == cong_com_hor || NULL == cong_com_ver || NULL == coeff_array) {
		DRM_ERROR("GSP_Gen_Block_Ccaler_Coef:_Allocate error!%08x,%08x,%08x\n",
				cong_com_hor, cong_com_ver, coeff_array);
		return FALSE;
	}

	temp_filter_ptr = _allocate(filter_buf_size, 2, &pool);
	filter_ptr = _allocate(filter_buf_size, 2, &pool);
	if (NULL == temp_filter_ptr || NULL == filter_ptr) {
		DRM_ERROR("GSP_Gen_Block_Ccaler_Coef:_Allocate error! \n");
		return FALSE;
	}

	/* calculate coefficients of Y component in horizontal direction */
	coef_len = cal_y_scaling_coef(hor_tap, D_hor, I_hor, temp_filter_ptr, 1,
			&pool);
	get_filter(temp_filter_ptr, filter_ptr, 8, coef_len, filter_len);
	write_scalar_coef(cong_com_hor, filter_ptr, 8, hor_tap);
	check_coef_range(cong_com_hor, 8, hor_tap, 8);
	gsp_rearrange_coef(cong_com_hor, coeff_array, hor_tap);
	{
		uint32_t cnts = 0, reg = 0;
		uint16_t p0, p1;
		for (i = 0; i < 8; i++) {
			p0 = (uint16_t) (*(coeff_array + i * 8 + 0));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 1));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_h_ptr[cnts + 0] = reg;

			p0 = (uint16_t) (*(coeff_array + i * 8 + 2));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 3));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_h_ptr[cnts + 1] = reg;

			p0 = (uint16_t) (*(coeff_array + i * 8 + 4));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 5));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_h_ptr[cnts + 2] = reg;

			p0 = (uint16_t) (*(coeff_array + i * 8 + 6));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 7));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_h_ptr[cnts + 3] = reg;

			cnts += 4;
		}
	}

	/* calculate coefficients of UV component in horizontal direction */
	coef_len = cal_uv_scaling_coef(ver_tap, D_hor, I_hor, temp_filter_ptr, 1,
			&pool);
	get_filter(temp_filter_ptr, filter_ptr, 8, coef_len, filter_len);
	write_scalar_coef(cong_com_ver, filter_ptr, 8, ver_tap);
	check_coef_range(cong_com_ver, 8, ver_tap, 8);
	memset(coeff_array, 0x00, 8 * 8 * sizeof(int16_t));
	gsp_rearrange_coef(cong_com_ver, coeff_array, ver_tap);
	{
		uint32_t cnts = 0, reg = 0;
		uint16_t p0, p1;
		for (i = 0; i < 8; i++) {
			p0 = (uint16_t) (*(coeff_array + i * 8 + 0));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 1));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_v_ptr[cnts + 0] = reg;

			p0 = (uint16_t) (*(coeff_array + i * 8 + 2));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 3));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_v_ptr[cnts + 1] = reg;

			p0 = (uint16_t) (*(coeff_array + i * 8 + 4));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 5));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_v_ptr[cnts + 2] = reg;

			p0 = (uint16_t) (*(coeff_array + i * 8 + 6));
			p1 = (uint16_t) (*(coeff_array + i * 8 + 7));
			reg = (p0 & 0x1ff) | ((p1 & 0x1ff) << 16);
			coeff_v_ptr[cnts + 3] = reg;

			cnts += 4;
		}
	}

#ifdef CACHE_COEF
	if (s_cache_coef_init_flag == 1) {
		pEntry = LIST_GET_THE_TAIL_ENTRY();
		if (pEntry->in_w == 0)
			DRM_DEBUG("GSP_CACHE_COEF:add\n");
		else
			DRM_DEBUG("GSP_CACHE_COEF:swap\n");

		memcpy((void*) pEntry->coef, (void*) coeff_h_ptr,
				COEF_MATRIX_ENTRY_SIZE * 4);
		cache_coef_move_entry_to_list_head(pEntry);
		LIST_SET_ENTRY_KEY(pEntry, i_w, i_h, o_w, o_h);
	}
#endif

	return TRUE;
}

static void gsp_scale_coef_tab_config(uint32_t *p_h_coeff, uint32_t *p_v_coeff)
{
	uint32_t i = 0, j = 0;
	uint32_t *s_scaling_reg_hor_ptr = 0, *s_scaling_reg_ver_ptr = 0;
	uint32_t scale_h_coef_addr = GSP_HOR_COEF_BASE, scale_v_coef_addr =
			GSP_VER_COEF_BASE;

	s_scaling_reg_hor_ptr = p_h_coeff;

	for (i = 0; i < 8; i++) {
		for (j = 0; j < 4; j++) {
			*(volatile uint32_t*) scale_h_coef_addr = *s_scaling_reg_hor_ptr;
			scale_h_coef_addr += 4;
			s_scaling_reg_hor_ptr++;
		}
	}

	s_scaling_reg_ver_ptr = p_v_coeff;
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 4; j++) {
			*(volatile uint32_t*) scale_v_coef_addr = *s_scaling_reg_ver_ptr;
			scale_v_coef_addr += 4;
			s_scaling_reg_ver_ptr++;
		}
	}
}

/*
 * M2M operation : supports crop/scale/rotation/csc so on.
 * Memory ----> GSP H/W ----> Memory.
 * Writeback operation : supports cloned screen with FIMD.
 * FIMD ----> GSP H/W ----> Memory.
 * Output operation : supports direct display using local path.
 * Memory ----> GSP H/W ----> FIMD.
 */

static int gsp_set_planar_addr(struct drm_sprd_ipp_buf_info *buf_info,
		u32 fmt, struct drm_sprd_sz *sz)
{
	dma_addr_t *base[SPRD_DRM_PLANAR_MAX];
	uint64_t size[SPRD_DRM_PLANAR_MAX];
	uint64_t ofs[SPRD_DRM_PLANAR_MAX];
	bool bypass = false;
	uint64_t tsize = 0;
	int i;

	for_each_ipp_planar(i) {
		base[i] = &buf_info->base[i];
		size[i] = buf_info->size[i];
		ofs[i] = 0;
		tsize += size[i];
		if (size[i])
			DRM_DEBUG_KMS("%s:base[%d][0x%x]s[%d][%llu]\n", __func__,
				i, *base[i], i, size[i]);
	}

	if (!tsize) {
		DRM_INFO("%s:failed to get buffer size.\n", __func__);
		goto err_info;
	}

	switch (fmt) {
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV21:
	case DRM_FORMAT_NV16:
	case DRM_FORMAT_NV61:
		ofs[0] = (uint64_t)sz->hsize * sz->vsize;
		ofs[1] = ofs[0] >> 1;
		if (*base[0] && *base[1]) {
			if (size[0] + size[1] < ofs[0] + ofs[1])
				goto err_info;
			bypass = true;
		}
		break;
	case DRM_FORMAT_NV12MT:
		ofs[0] = ALIGN(ALIGN(sz->hsize, 128) *
				ALIGN(sz->vsize, 32), SZ_8K);
		ofs[1] = ALIGN(ALIGN(sz->hsize, 128) *
				ALIGN(sz->vsize >> 1, 32), SZ_8K);
		if (*base[0] && *base[1]) {
			if (size[0] + size[1] < ofs[0] + ofs[1])
				goto err_info;
			bypass = true;
		}
		break;
	case DRM_FORMAT_YUV410:
	case DRM_FORMAT_YVU410:
	case DRM_FORMAT_YUV411:
	case DRM_FORMAT_YVU411:
	case DRM_FORMAT_YUV420:
	case DRM_FORMAT_YVU420:
	case DRM_FORMAT_YUV422:
	case DRM_FORMAT_YVU422:
	case DRM_FORMAT_YUV444:
	case DRM_FORMAT_YVU444:
		ofs[0] = (uint64_t)sz->hsize * sz->vsize;
		ofs[1] = ofs[2] = ofs[0] >> 2;
		if (*base[0] && *base[1] && *base[2]) {
			if (size[0]+size[1]+size[2] < ofs[0]+ofs[1]+ofs[2])
				goto err_info;
			bypass = true;
		}
		break;
	case DRM_FORMAT_XRGB8888:
		ofs[0] = (uint64_t)sz->hsize * sz->vsize << 2;
		if (*base[0]) {
			if (size[0] < ofs[0])
				goto err_info;
		}
		bypass = true;
		break;
	default:
		bypass = true;
		break;
	}

	if (!bypass) {
		*base[1] = *base[0] + ofs[0];
		if (ofs[1] && ofs[2])
			*base[2] = *base[1] + ofs[1];
	}

	DRM_DEBUG_KMS("%s:y[0x%x],cb[0x%x],cr[0x%x]\n", __func__,
		*base[0], *base[1], *base[2]);

	return 0;

err_info:
	DRM_ERROR("invalid size for fmt[0x%x]\n", fmt);

	for_each_ipp_planar(i) {
		base[i] = &buf_info->base[i];
		size[i] = buf_info->size[i];

		DRM_ERROR("base[%d][0x%x]s[%d][%llu]ofs[%d][%llu]\n",
			i, *base[i], i, size[i], i, ofs[i]);
	}

	return -EINVAL;
}

static int gsp_src_set_fmt(struct device *dev, u32 fmt)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	struct sprd_drm_ippdrv *ippdrv = &ctx->ippdrv;
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s:fmt[0x%x]\n", __func__, fmt);

	switch (fmt) {
	case DRM_FORMAT_RGB565:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_RGB565;
		break;
	case DRM_FORMAT_RGB888:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_RGB888;
		break;
	case DRM_FORMAT_YUV422:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_YUV422_2P;
		break;
	case DRM_FORMAT_NV12:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_YUV420_2P;
		break;
	case DRM_FORMAT_NV21:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_YUV420_2P;
		ctx->gsp_cfg.layer0_info.endian_mode.uv_word_endn = GSP_WORD_ENDN_2;
		break;
	case DRM_FORMAT_YUV420:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_YUV420_3P;
		break;
	case DRM_FORMAT_XRGB8888:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_ARGB888;
		break;
	case DRM_FORMAT_ARGB8888:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_ARGB888;
		ctx->gsp_cfg.layer0_info.endian_mode.y_word_endn = GSP_WORD_ENDN_1;
		break;
	default:
		ctx->gsp_cfg.layer0_info.img_format = GSP_SRC_FMT_MAX_NUM;
		dev_err(ippdrv->dev, "invalid target format 0x%x.\n", fmt);
		return -EINVAL;
	}

	cfg = gsp_read(SPRD_LAYER0_CFG);

	cfg &= ~(SPRD_LAYER0_CFG_IMG_FORMAT_L0_MASK);
	cfg |= SPRD_LAYER0_CFG_IMG_FORMAT_L0_SET(
			ctx->gsp_cfg.layer0_info.img_format);

	gsp_write(cfg, SPRD_LAYER0_CFG);

	cfg = gsp_read(SPRD_LAYER0_ENDIAN);
	cfg |= (ctx->gsp_cfg.layer0_info.endian_mode.y_word_endn) |
		(ctx->gsp_cfg.layer0_info.endian_mode.uv_word_endn << 3) |
		(ctx->gsp_cfg.layer0_info.endian_mode.va_word_endn << 6) |
		(ctx->gsp_cfg.layer0_info.endian_mode.rgb_swap_mode << 9) |
		(ctx->gsp_cfg.layer0_info.endian_mode.a_swap_mode << 12);

	gsp_write(cfg, SPRD_LAYER0_ENDIAN);

	return 0;
}

static int gsp_src_set_transf(struct device *dev,
		enum drm_sprd_degree degree,
		enum drm_sprd_flip flip, bool *swap)
{
	DRM_DEBUG_KMS("%s:degree[%d]flip[0x%x]\n", __func__,
		degree, flip);

	/* ToDo: need to implement */

	return 0;
}

static int gsp_src_set_size(struct device *dev, int swap,
		struct drm_sprd_pos *pos, struct drm_sprd_sz *sz)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s:swap[%d]hsize[%d]vsize[%d]\n",
		__func__, swap, sz->hsize, sz->vsize);

	DRM_DEBUG_KMS("%s:x[%d]y[%d]w[%d]h[%d]\n", __func__,
		pos->x, pos->y, pos->w, pos->h);

	ctx->gsp_cfg.layer0_info.clip_rect.st_x = pos->x;
	ctx->gsp_cfg.layer0_info.clip_rect.st_y = pos->y;
	ctx->gsp_cfg.layer0_info.clip_rect.rect_w = pos->w;
	ctx->gsp_cfg.layer0_info.clip_rect.rect_h = pos->h;

	cfg = (ctx->gsp_cfg.layer0_info.clip_rect.st_x
			| (ctx->gsp_cfg.layer0_info.clip_rect.st_y << 16));
	gsp_write(cfg, SPRD_LAYER0_CLIP_START);

	cfg = (ctx->gsp_cfg.layer0_info.clip_rect.rect_w
			| (ctx->gsp_cfg.layer0_info.clip_rect.rect_h << 16));
	gsp_write(cfg, SPRD_LAYER0_CLIP_SIZE);

	ctx->gsp_cfg.layer0_info.pitch = sz->hsize;
	gsp_write(ctx->gsp_cfg.layer0_info.pitch, SPRD_LAYER0_PITCH);

	return 0;
}

static int gsp_src_set_addr(struct device *dev,
		struct drm_sprd_ipp_buf_info *buf_info, u32 buf_id,
		enum drm_sprd_ipp_buf_type buf_type)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	struct sprd_drm_ippdrv *ippdrv = &ctx->ippdrv;
	struct drm_sprd_ipp_cmd_node *c_node = ippdrv->c_node;
	struct drm_sprd_ipp_property *property;
	struct drm_sprd_ipp_config *config;
	int ret;

	if (!c_node) {
		DRM_ERROR("failed to get c_node.\n");
		return -EINVAL;
	}

	property = &c_node->property;

	DRM_DEBUG_KMS("%s:prop_id[%d]buf_id[%d]buf_type[%d]\n", __func__,
			property->prop_id, buf_id, buf_type);

	/* address register set */
	switch (buf_type) {
	case IPP_BUF_ENQUEUE:
		ctx->cur_buf_id[SPRD_DRM_OPS_SRC] = buf_id;
		config = &property->config[SPRD_DRM_OPS_SRC];
		ret = gsp_set_planar_addr(buf_info, config->fmt, &config->sz);
		if (ret) {
			dev_err(dev, "failed to set plane src addr.\n");
			return ret;
		}

		ctx->gsp_cfg.layer0_info.src_addr.addr_y =
				buf_info->base[SPRD_DRM_PLANAR_Y];
		ctx->gsp_cfg.layer0_info.src_addr.addr_uv =
				buf_info->base[SPRD_DRM_PLANAR_CB];
		ctx->gsp_cfg.layer0_info.src_addr.addr_v =
				buf_info->base[SPRD_DRM_PLANAR_CR];

		gsp_write(ctx->gsp_cfg.layer0_info.src_addr.addr_y, SPRD_LAYER0_Y_ADDR);
		gsp_write(ctx->gsp_cfg.layer0_info.src_addr.addr_uv,
				SPRD_LAYER0_UV_ADDR);
		gsp_write(ctx->gsp_cfg.layer0_info.src_addr.addr_v,
				SPRD_LAYER0_VA_ADDR);
		break;
	case IPP_BUF_DEQUEUE:
	default:
		/* bypass */
		break;
	}

	return 0;
}

static struct sprd_drm_ipp_ops gsp_src_ops = {
	.set_fmt = gsp_src_set_fmt,
	.set_transf = gsp_src_set_transf,
	.set_size = gsp_src_set_size,
	.set_addr = gsp_src_set_addr,
};

static int gsp_dst_set_fmt(struct device *dev, u32 fmt)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	struct sprd_drm_ippdrv *ippdrv = &ctx->ippdrv;
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s:fmt[0x%x]\n", __func__, fmt);

	switch (fmt) {
	case DRM_FORMAT_RGB565:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_RGB565;
		break;
	case DRM_FORMAT_RGB888:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_RGB888;
		break;
	case DRM_FORMAT_YUV422:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_YUV422_2P;
		break;
	case DRM_FORMAT_NV12:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_YUV420_2P;
		break;
	case DRM_FORMAT_NV21:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_YUV420_2P;
		ctx->gsp_cfg.layer_des_info.endian_mode.uv_word_endn = GSP_WORD_ENDN_2;
		break;
	case DRM_FORMAT_YUV420:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_YUV420_3P;
		break;
	case DRM_FORMAT_XRGB8888:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_ARGB888;
		break;
	case DRM_FORMAT_ARGB8888:
		ctx->gsp_cfg.layer_des_info.img_format = GSP_DST_FMT_ARGB888;
		ctx->gsp_cfg.layer_des_info.endian_mode.y_word_endn = GSP_WORD_ENDN_1;
		break;
	default:
		dev_err(ippdrv->dev, "invalid target format 0x%x.\n", fmt);
		return -EINVAL;
	}

	cfg = gsp_read(SPRD_DES_DATA_CFG);

	cfg &= ~(SPRD_DEST_DATA_CFG_IMG_FORMAT_MASK);
	cfg |=
			(SPRD_DEST_DATA_CFG_IMG_FORMAT_SET(ctx->gsp_cfg.layer_des_info.img_format));

	gsp_write(cfg, SPRD_DES_DATA_CFG);

	cfg = gsp_read(SPRD_DES_DATA_ENDIAN);
	cfg |= (ctx->gsp_cfg.layer_des_info.endian_mode.y_word_endn) |
		(ctx->gsp_cfg.layer_des_info.endian_mode.uv_word_endn << 3) |
		(ctx->gsp_cfg.layer_des_info.endian_mode.va_word_endn << 6) |
		(ctx->gsp_cfg.layer_des_info.endian_mode.rgb_swap_mode << 9) |
		(ctx->gsp_cfg.layer_des_info.endian_mode.a_swap_mode << 12);

	gsp_write(cfg, SPRD_DES_DATA_ENDIAN);

	return 0;
}

static int gsp_dst_set_transf(struct device *dev,
		enum drm_sprd_degree degree,
		enum drm_sprd_flip flip, bool *swap)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	struct sprd_drm_ippdrv *ippdrv = &ctx->ippdrv;
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s:degree[%d]flip[0x%x]\n", __func__,
		degree, flip);

	switch (degree) {
	case SPRD_DRM_DEGREE_0:
		if (flip & SPRD_DRM_FLIP_VERTICAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_0_M;
		else if (flip & SPRD_DRM_FLIP_HORIZONTAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_180_M;
		else
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_0;
		break;
	case SPRD_DRM_DEGREE_90:
		if (flip & SPRD_DRM_FLIP_VERTICAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_270_M;
		else if (flip & SPRD_DRM_FLIP_HORIZONTAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_90_M;
		else
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_270;
		break;
	case SPRD_DRM_DEGREE_180:
		if (flip & SPRD_DRM_FLIP_VERTICAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_180_M;
		else if (flip & SPRD_DRM_FLIP_HORIZONTAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_0_M;
		else
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_180;
		break;
	case SPRD_DRM_DEGREE_270:
		if (flip & SPRD_DRM_FLIP_VERTICAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_90_M;
		else if (flip & SPRD_DRM_FLIP_HORIZONTAL)
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_270_M;
		else
			ctx->gsp_cfg.layer0_info.rot_angle = GSP_ROT_ANGLE_90;
		break;
	default:
		dev_err(ippdrv->dev, "inavlid degree value %d.\n", degree);
		return -EINVAL;
	}

	cfg = gsp_read(SPRD_LAYER0_CFG);

	cfg &= ~(SPRD_LAYER0_CFG_ROT_ANGLE_MASK);
	cfg |= SPRD_LAYER0_CFG_ROT_ANGLE_SET(ctx->gsp_cfg.layer0_info.rot_angle);

	gsp_write(cfg, SPRD_LAYER0_CFG);

	return 0;
}

static int gsp_dst_set_size(struct device *dev, int swap,
		struct drm_sprd_pos *pos, struct drm_sprd_sz *sz)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s:swap[%d]hsize[%d]vsize[%d]\n",
		__func__, swap, sz->hsize, sz->vsize);

	DRM_DEBUG_KMS("%s:x[%d]y[%d]w[%d]h[%d]\n",
		__func__, pos->x, pos->y, pos->w, pos->h);

	ctx->gsp_cfg.layer0_info.des_rect.st_x = pos->x;
	ctx->gsp_cfg.layer0_info.des_rect.st_y = pos->y;
	ctx->gsp_cfg.layer0_info.des_rect.rect_w = pos->w;
	ctx->gsp_cfg.layer0_info.des_rect.rect_h = pos->h;

	cfg = (ctx->gsp_cfg.layer0_info.des_rect.st_x
			| (ctx->gsp_cfg.layer0_info.des_rect.st_y << 16));
	gsp_write(cfg, SPRD_LAYER0_DES_START);

	cfg = (ctx->gsp_cfg.layer0_info.des_rect.rect_w
			| (ctx->gsp_cfg.layer0_info.des_rect.rect_h << 16));
	gsp_write(cfg, SPRD_LAYER0_DES_SIZE);

	ctx->gsp_cfg.layer_des_info.pitch = sz->hsize;

	gsp_write(ctx->gsp_cfg.layer_des_info.pitch, SPRD_DES_PITCH);

	return 0;
}

static int gsp_dst_set_addr(struct device *dev,
		struct drm_sprd_ipp_buf_info *buf_info, u32 buf_id,
		enum drm_sprd_ipp_buf_type buf_type)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	struct sprd_drm_ippdrv *ippdrv = &ctx->ippdrv;
	struct drm_sprd_ipp_cmd_node *c_node = ippdrv->c_node;
	struct drm_sprd_ipp_property *property;
	struct drm_sprd_ipp_config *config;
	int ret;

	if (!c_node) {
		DRM_ERROR("failed to get c_node.\n");
		return -EINVAL;
	}

	property = &c_node->property;

	DRM_DEBUG_KMS("%s:prop_id[%d]buf_id[%d]buf_type[%d]\n", __func__,
			property->prop_id, buf_id, buf_type);

	/* address register set */
	switch (buf_type) {
	case IPP_BUF_ENQUEUE:
		ctx->cur_buf_id[SPRD_DRM_OPS_DST] = buf_id;
		config = &property->config[SPRD_DRM_OPS_DST];
		ret = gsp_set_planar_addr(buf_info, config->fmt, &config->sz);
		if (ret) {
			dev_err(dev, "failed to set plane dst addr.\n");
			return ret;
		}

		ctx->gsp_cfg.layer_des_info.src_addr.addr_y =
				buf_info->base[SPRD_DRM_PLANAR_Y];
		ctx->gsp_cfg.layer_des_info.src_addr.addr_uv =
				buf_info->base[SPRD_DRM_PLANAR_CB];
		ctx->gsp_cfg.layer_des_info.src_addr.addr_v =
				buf_info->base[SPRD_DRM_PLANAR_CR];

		gsp_write(ctx->gsp_cfg.layer_des_info.src_addr.addr_y, SPRD_DES_Y_ADDR);
		gsp_write(ctx->gsp_cfg.layer_des_info.src_addr.addr_uv,
				SPRD_DES_UV_ADDR);
		gsp_write(ctx->gsp_cfg.layer_des_info.src_addr.addr_v, SPRD_DES_V_ADDR);
		break;
	case IPP_BUF_DEQUEUE:
		break;
	default:
		/* bypass */
		break;
	}

	return 0;
}

static struct sprd_drm_ipp_ops gsp_dst_ops = {
	.set_fmt = gsp_dst_set_fmt,
	.set_transf = gsp_dst_set_transf,
	.set_size = gsp_dst_set_size,
	.set_addr = gsp_dst_set_addr,
};

static int gsp_clk_ctrl(struct gsp_context *ctx, bool enable)
{
	DRM_INFO("%s:enable[%d]\n", __func__, enable);

	if (enable) {
		clk_prepare_enable(ctx->gsp_clk);
		clk_prepare_enable(ctx->emc_clk);
		ctx->coef_force_calc = 1;
		ctx->suspended = false;
	} else {
		clk_disable_unprepare(ctx->emc_clk);
		clk_disable_unprepare(ctx->gsp_clk);
		ctx->suspended = true;
	}

	return 0;
}

static irqreturn_t gsp_irq_handler(int irq, void *dev_id)
{
	struct gsp_context *ctx = dev_id;
	struct sprd_drm_ippdrv *ippdrv = &ctx->ippdrv;
	struct drm_sprd_ipp_cmd_node *c_node = ippdrv->c_node;
	struct drm_sprd_ipp_event_info *event = c_node->event;
	enum drm_sprd_ops_id ops_id = SPRD_DRM_OPS_DST;
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s:buf_id[%d]\n", __func__,
		ctx->cur_buf_id[SPRD_DRM_OPS_DST]);

	cfg = gsp_read(SPRD_GSP_INT_CFG);
	cfg |= (SPRD_GSP_INT_CFG_INT_CLR_SET(1));
	gsp_write(cfg, SPRD_GSP_INT_CFG);

	udelay(10);

	cfg = gsp_read(SPRD_GSP_INT_CFG);
	cfg &= ~(SPRD_GSP_INT_CFG_INT_CLR_MASK);
	gsp_write(cfg, SPRD_GSP_INT_CFG);

	cfg = gsp_read(SPRD_GSP_INT_CFG);
	cfg |= SPRD_GSP_INT_CFG_INT_EN_SET(GSP_IRQ_TYPE_DISABLE);
	gsp_write(cfg, SPRD_GSP_INT_CFG);

	event->ippdrv = ippdrv;
	event->buf_id[ops_id] = ctx->cur_buf_id[SPRD_DRM_OPS_DST];

	ippdrv->sched_event(event);

	return IRQ_HANDLED;
}

static int gsp_init_prop_list(struct sprd_drm_ippdrv *ippdrv)
{
	struct drm_sprd_ipp_prop_list *capability;

	DRM_DEBUG_KMS("%s\n", __func__);

	capability = devm_kzalloc(ippdrv->dev, sizeof(*capability), GFP_KERNEL);
	if (!capability) {
		DRM_ERROR("failed to alloc capability.\n");
		return -ENOMEM;
	}

	capability->writeback = 0;
	capability->degree = (1 << SPRD_DRM_DEGREE_0) | (1 << SPRD_DRM_DEGREE_90)
					| (1 << SPRD_DRM_DEGREE_180) | (1 << SPRD_DRM_DEGREE_270);
	capability->csc = 1;
	capability->crop = 1;
	capability->scale = 1;

	ippdrv->prop_list = capability;

	return 0;
}

static inline bool gsp_check_limit(struct drm_sprd_ipp_property *property)
{
	struct drm_sprd_ipp_config *src_config =
					&property->config[SPRD_DRM_OPS_SRC];
	struct drm_sprd_ipp_config *dst_config =
					&property->config[SPRD_DRM_OPS_DST];
	struct drm_sprd_pos src_pos = src_config->pos;
	struct drm_sprd_pos dst_pos = dst_config->pos;
	unsigned int h_ratio, v_ratio;

	if (src_config->degree == SPRD_DRM_DEGREE_90 ||
		src_config->degree == SPRD_DRM_DEGREE_270)
		swap(src_pos.w, src_pos.h);

	if (dst_config->degree == SPRD_DRM_DEGREE_90 ||
		dst_config->degree == SPRD_DRM_DEGREE_270)
		swap(dst_pos.w, dst_pos.h);

	if ((src_pos.w > dst_pos.w && src_pos.h < dst_pos.h) ||
		(src_pos.w < dst_pos.w && src_pos.h > dst_pos.h)) {
		DRM_ERROR("unsupported scale[%d %d->%d %d]\n",
			src_pos.w, src_pos.h, dst_pos.w, dst_pos.h);
		return false;
	}

	h_ratio = GSP_RATIO(src_pos.w, dst_pos.w);
	v_ratio = GSP_RATIO(src_pos.h, dst_pos.h);

	if ((h_ratio > GSP_DOWN_MIN) ||
			(h_ratio < GSP_UP_MAX)) {
		DRM_ERROR("h_ratio[%d]out of range\n", h_ratio);
		return false;
	}

	if ((v_ratio > GSP_DOWN_MIN) ||
			(v_ratio < GSP_UP_MAX)) {
		DRM_ERROR("v_ratio[%d]out of range\n", v_ratio);
		return false;
	}

	/* ToDo: need to add more check routine */
	return true;
}

static int gsp_ippdrv_check_property(struct device *dev,
		struct drm_sprd_ipp_property *property)
{
	int ret = 0;

	if (!ipp_is_m2m_cmd(property->cmd))
		ret = -EPERM;

	if (!gsp_check_limit(property))
		ret = -EPERM;

	if (ret)
		DRM_ERROR("invalid property\n");

	return ret;
}

static int gsp_ippdrv_reset(struct device *dev)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s\n", __func__);

	memset(&ctx->gsp_cfg, 0x0, sizeof(ctx->gsp_cfg));

	ctx->gsp_cfg.layer0_info.layer_en = 1;

#ifndef GSP_IOMMU_WORKAROUND1
		GSP_HWMODULE_SOFTRESET(); //workaround gsp-iommu bug
#endif
	GSP_AUTO_GATE_ENABLE();

	cfg = gsp_read(SPRD_GSP_INT_CFG);
	cfg |= SPRD_GSP_INT_CFG_INT_MODE_SET(GSP_IRQ_MODE_LEVEL);
	gsp_write(cfg, SPRD_GSP_INT_CFG);

	cfg = gsp_read(SPRD_GSP_CFG);
	cfg &= ~(SPRD_GSP_CFG_L0_EN_MASK);
	cfg |= SPRD_GSP_CFG_L0_EN_SET(ctx->gsp_cfg.layer0_info.layer_en);
	gsp_write(cfg, SPRD_GSP_CFG);

	return 0;
}

static void gsp_coef_tap_convert(GSP_CONFIG_INFO_T* gsp_cfg,
		u8 h_tap, u8 v_tap)
{
	switch (h_tap) {
	case 8:
		gsp_cfg->layer0_info.row_tap_mode = 0;
		break;
	case 6:
		gsp_cfg->layer0_info.row_tap_mode = 1;
		break;
	case 4:
		gsp_cfg->layer0_info.row_tap_mode = 2;
		break;
	case 2:
		gsp_cfg->layer0_info.row_tap_mode = 3;
		break;
	default:
		gsp_cfg->layer0_info.row_tap_mode = 0;
		break;
	}

	switch (v_tap) {
	case 8:
		gsp_cfg->layer0_info.col_tap_mode = 0;
		break;
	case 6:
		gsp_cfg->layer0_info.col_tap_mode = 1;
		break;
	case 4:
		gsp_cfg->layer0_info.col_tap_mode = 2;
		break;
	case 2:
		gsp_cfg->layer0_info.col_tap_mode = 3;
		break;
	default:
		gsp_cfg->layer0_info.col_tap_mode = 0;
		break;
	}

	gsp_cfg->layer0_info.row_tap_mode &= 0x3;
	gsp_cfg->layer0_info.col_tap_mode &= 0x3;
}

static int32_t gsp_scaling_coef_gen_and_config(struct device *dev,
		struct gsp_context *ctx)
{
	GSP_CONFIG_INFO_T* gsp_cfg = &ctx->gsp_cfg;
	u8 h_tap = 8, v_tap = 8;
	u32 *tmp_buf = NULL, *h_coeff = NULL, *v_coeff = NULL;
	u32 coef_factor_w = 0, coef_factor_h = 0;
	u32 after_rotate_w = 0, after_rotate_h = 0;
	u32 coef_in_w = 0, coef_in_h = 0;
	u32 coef_out_w = 0, coef_out_h = 0;
	static volatile u32 coef_in_w_last = 0, coef_in_h_last = 0;
	static volatile u32 coef_out_w_last = 0, coef_out_h_last = 0;
	u32 cfg = 0;

	if (gsp_cfg->layer0_info.scaling_en == 1) {
		if (gsp_cfg->layer0_info.des_rect.rect_w < 4
				|| gsp_cfg->layer0_info.des_rect.rect_h < 4) {
			return GSP_KERNEL_GEN_OUT_RANG;
		}

		if (gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_0
				|| gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_180
				|| gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_0_M
				|| gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_180_M) {
			after_rotate_w = gsp_cfg->layer0_info.clip_rect.rect_w;
			after_rotate_h = gsp_cfg->layer0_info.clip_rect.rect_h;
		} else if (gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_90
				|| gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_270
				|| gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_90_M
				|| gsp_cfg->layer0_info.rot_angle == GSP_ROT_ANGLE_270_M) {
			after_rotate_w = gsp_cfg->layer0_info.clip_rect.rect_h;
			after_rotate_h = gsp_cfg->layer0_info.clip_rect.rect_w;
		}

		coef_factor_w =
				CEIL(after_rotate_w,gsp_cfg->layer0_info.des_rect.rect_w);
		coef_factor_h =
				CEIL(after_rotate_h,gsp_cfg->layer0_info.des_rect.rect_h);

		if (coef_factor_w > 16 || coef_factor_h > 16)
			return GSP_KERNEL_GEN_OUT_RANG;

		if (coef_factor_w > 8)
			coef_factor_w = 4;
		 else if (coef_factor_w > 4)
			coef_factor_w = 2;
		else
			coef_factor_w = 1;

		if (coef_factor_h > 8)
			coef_factor_h = 4;
		 else if (coef_factor_h > 4)
			coef_factor_h = 2;
		 else
			coef_factor_h = 1;

		coef_in_w = CEIL(after_rotate_w,coef_factor_w);
		coef_in_h = CEIL(after_rotate_h,coef_factor_h);
		coef_out_w = gsp_cfg->layer0_info.des_rect.rect_w;
		coef_out_h = gsp_cfg->layer0_info.des_rect.rect_h;
		if (ctx->coef_force_calc ||coef_in_w_last != coef_in_w
			|| coef_in_h_last != coef_in_h || coef_out_w_last != coef_out_w
			|| coef_out_h_last != coef_out_h) {
			tmp_buf = (u32 *) kmalloc(GSP_COEFF_BUF_SIZE, GFP_KERNEL);
			if (NULL == tmp_buf) {
				DRM_ERROR("SCALE DRV: No mem to alloc coeff buffer! \n");
				return GSP_KERNEL_GEN_ALLOC_ERR;
			}

			h_coeff = tmp_buf;
			v_coeff = tmp_buf + (GSP_COEFF_COEF_SIZE / 4);

			if (!(gsp_gen_block_ccaler_coef(coef_in_w, coef_in_h, coef_out_w,
					coef_out_h, h_tap, v_tap, h_coeff, v_coeff,
					tmp_buf + (GSP_COEFF_COEF_SIZE / 2),
					GSP_COEFF_POOL_SIZE))) {
				kfree(tmp_buf);
				DRM_ERROR("GSP DRV: GSP_Gen_Block_Ccaler_Coef error! \n");
				return GSP_KERNEL_GEN_COMMON_ERR;
			}

			gsp_scale_coef_tab_config(h_coeff, v_coeff);
			coef_in_w_last = coef_in_w;
			coef_in_h_last = coef_in_h;
			coef_out_w_last = coef_out_w;
			coef_out_h_last = coef_out_h;
			ctx->coef_force_calc = 0;
		}

		gsp_coef_tap_convert(gsp_cfg, h_tap, v_tap);

		cfg = gsp_read(SPRD_LAYER0_CFG);
		cfg &= ~((SPRD_LAYER0_CFG_ROW_TAP_MODE_MASK)
				| (SPRD_LAYER0_CFG_COL_TAP_MODE_MASK));
		cfg |=
				SPRD_LAYER0_CFG_ROW_TAP_MODE_SET(gsp_cfg->layer0_info.row_tap_mode);
		cfg |=
				SPRD_LAYER0_CFG_COL_TAP_MODE_SET(gsp_cfg->layer0_info.col_tap_mode);
		gsp_write(cfg, SPRD_LAYER0_CFG);

		kfree(tmp_buf);
	}

	return GSP_NO_ERR;
}

static int gsp_ippdrv_start(struct device *dev, enum drm_sprd_ipp_cmd cmd)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	int ret;
	u32 cfg = 0;

	DRM_DEBUG_KMS("%s:cmd[%d]\n", __func__, cmd);

	switch (cmd) {
	case IPP_CMD_M2M:
		/* ToDo: FixMe */
		ctx->gsp_cfg.misc_info.ahb_clock = 2;
		ctx->gsp_cfg.misc_info.gsp_clock = 3;

		if (ctx->gsp_cfg.layer0_info.rot_angle & 0x1) {
			if ((ctx->gsp_cfg.layer0_info.clip_rect.rect_w
					!= ctx->gsp_cfg.layer0_info.des_rect.rect_h)
					|| (ctx->gsp_cfg.layer0_info.clip_rect.rect_h
							!= ctx->gsp_cfg.layer0_info.des_rect.rect_w))
				ctx->gsp_cfg.layer0_info.scaling_en = 1;
		} else {
			if ((ctx->gsp_cfg.layer0_info.clip_rect.rect_w
					!= ctx->gsp_cfg.layer0_info.des_rect.rect_w)
					|| (ctx->gsp_cfg.layer0_info.clip_rect.rect_h
							!= ctx->gsp_cfg.layer0_info.des_rect.rect_h))
				ctx->gsp_cfg.layer0_info.scaling_en = 1;
		}

		if (ctx->gsp_cfg.layer0_info.scaling_en == 1) {
			cfg = gsp_read(SPRD_GSP_CFG);
			cfg |= (SPRD_GSP_CFG_SCALE_STATUS_CLEAR_SET(1));
			gsp_write(cfg, SPRD_GSP_CFG);

			udelay(10);

			cfg = gsp_read(SPRD_GSP_CFG);
			cfg &= ~(SPRD_GSP_CFG_SCALE_STATUS_CLEAR_MASK);
			gsp_write(cfg, SPRD_GSP_CFG);
		}

		cfg = gsp_read(SPRD_GSP_CFG);
		cfg &= ~(SPRD_GSP_CFG_SCALE_EN_MASK);
		cfg |= (SPRD_GSP_CFG_SCALE_EN_SET(ctx->gsp_cfg.layer0_info.scaling_en));
		gsp_write(cfg, SPRD_GSP_CFG);

		/* enable bypass/split bit for iommu issue - 14th bit */
		cfg = gsp_read(SPRD_GSP_CFG);
		cfg &= ~(1<<14);
		gsp_write(cfg, SPRD_GSP_CFG);

		GSP_CLOCK_SET(ctx->gsp_cfg.misc_info.gsp_clock);

		ret = gsp_scaling_coef_gen_and_config(dev, ctx);
		if (ret) {
			DRM_ERROR("%s:gsp config err:%d\n", __func__, ret);
			goto exit;
		}

		cfg = gsp_read(SPRD_GSP_CFG);
		cfg &= SPRD_GSP_CFG_ERR_FLAG_MASK;
		if (SPRD_GSP_CFG_ERR_FLAG_GET(cfg)) {
			cfg = gsp_read(SPRD_GSP_CFG);
			cfg &= SPRD_GSP_CFG_ERR_CODE_MASK;

			DRM_ERROR("%s:GSP configuration error[%u]\n", __func__, cfg);

			return SPRD_GSP_CFG_ERR_CODE_GET(cfg);
		}

		cfg = gsp_read(SPRD_GSP_INT_CFG);
		cfg |= SPRD_GSP_INT_CFG_INT_EN_SET(GSP_IRQ_TYPE_ENABLE);
		gsp_write(cfg, SPRD_GSP_INT_CFG);

		cfg = gsp_read(SPRD_GSP_CFG);
		cfg |= SPRD_GSP_CFG_RUN_SET(1);
		gsp_write(cfg, SPRD_GSP_CFG);
		break;
	default:
		ret = -EINVAL;
		dev_err(dev, "Invalid operations.\n");
		return ret;
	}

exit:
	DRM_DEBUG_KMS("%s:cmd[%d]done\n", __func__, cmd);

	return 0;
}

static void gsp_ippdrv_stop(struct device *dev, enum drm_sprd_ipp_cmd cmd)
{
	struct gsp_context *ctx = get_gsp_context(dev);
	u32 cfg = 0;

	DRM_INFO("%s:cmd[%d]\n", __func__, cmd);

	switch (cmd) {
	case IPP_CMD_M2M:
		cfg = gsp_read(SPRD_GSP_INT_CFG);
		cfg |= (SPRD_GSP_INT_CFG_INT_CLR_SET(1));
		gsp_write(cfg, SPRD_GSP_INT_CFG);

		udelay(10);

		cfg = gsp_read(SPRD_GSP_INT_CFG);
		cfg &= ~(SPRD_GSP_INT_CFG_INT_CLR_MASK);
		gsp_write(cfg, SPRD_GSP_INT_CFG);

		cfg = gsp_read(SPRD_GSP_INT_CFG);
		cfg |= SPRD_GSP_INT_CFG_INT_EN_SET(GSP_IRQ_TYPE_DISABLE);
		gsp_write(cfg, SPRD_GSP_INT_CFG);

		break;
	default:
		dev_err(dev, "Invalid operations.\n");
		break;
	}
}

static int32_t gsp_clock_init(struct gsp_context *ctx)
{
	struct clk *emc_clk_parent = NULL;
	struct clk *gsp_clk_parent = NULL;
	int ret = 0;

	emc_clk_parent = clk_get(NULL, GSP_EMC_CLOCK_PARENT_NAME);
	if (IS_ERR(emc_clk_parent)) {
		DRM_ERROR("gsp: get emc clk_parent failed!\n");
		return -1;
	} else {
		DRM_DEBUG("gsp: get emc clk_parent ok!\n");
	}

	ctx->emc_clk = clk_get(NULL, GSP_EMC_CLOCK_NAME);
	if (IS_ERR(ctx->emc_clk)) {
		DRM_ERROR("gsp: get emc clk failed!\n");
		return -1;
	} else {
		DRM_DEBUG("gsp: get emc clk ok!\n");
	}

	ret = clk_set_parent(ctx->emc_clk, emc_clk_parent);
	if (ret) {
		DRM_ERROR("gsp: gsp set emc clk parent failed!\n");
		return -1;
	} else {
		DRM_DEBUG("gsp: gsp set emc clk parent ok!\n");
	}

	gsp_clk_parent = clk_get(NULL, GSP_CLOCK_PARENT3);
	if (IS_ERR(gsp_clk_parent)) {
		DRM_ERROR("gsp: get clk_parent failed!\n");
		return -1;
	} else {
		DRM_DEBUG("gsp: get clk_parent ok!\n");
	}

	ctx->gsp_clk = clk_get(NULL, GSP_CLOCK_NAME);
	if (IS_ERR(ctx->gsp_clk)) {
		DRM_ERROR("gsp: get clk failed!\n");
		return -1;
	} else {
		DRM_DEBUG("gsp: get clk ok!\n");
	}

	ret = clk_set_parent(ctx->gsp_clk, gsp_clk_parent);
	if (ret) {
		DRM_ERROR("gsp: gsp set clk parent failed!\n");
		return -1;
	} else {
		DRM_DEBUG("gsp: gsp set clk parent ok!\n");
	}

	return ret;
}

static int gsp_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct gsp_context *ctx;
	struct sprd_drm_ippdrv *ippdrv;
#ifdef CONFIG_OF
	struct resource *res;
#endif
	int ret;

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

#define GSP_RATIO(x, y)	((65536 * x) / y)
#define GSP_UP_MAX		GSP_RATIO(1, 4)
#define GSP_DOWN_MIN		GSP_RATIO(4, 1)

#define CACHE_COEF
#ifdef CACHE_COEF
/* we use Least Recently Used(LRU) to implement the coef-matrix cache policy */
#define COEF_MATRIX_ENTRY_SIZE (GSP_COEFF_COEF_SIZE/2)
#define CACHED_COEF_CNT_MAX 32

#define LIST_ADD_TO_LIST_HEAD(pEntry)\
{\
	Coef_Entry_List_Head->prev->next = (pEntry);\
	(pEntry)->prev = Coef_Entry_List_Head->prev;\
	(pEntry)->next = Coef_Entry_List_Head;\
	Coef_Entry_List_Head->prev = (pEntry);\
	Coef_Entry_List_Head = (pEntry);\
}

#define LIST_FETCH_FROM_LIST(pEntry)\
{\
	pEntry->prev->next = pEntry->next;\
	pEntry->next->prev = pEntry->prev;\
}

#define LIST_SET_ENTRY_KEY(pEntry,i_w,i_h,o_w,o_h)\
{\
	pEntry->in_w = i_w;\
	pEntry->in_h = i_h;\
	pEntry->out_w = o_w;\
	pEntry->out_h = o_h;\
}

#define LIST_GET_THE_TAIL_ENTRY()	(Coef_Entry_List_Head->prev)
#endif

#ifdef CONFIG_OF
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "sprdgsp");
	if (!res) {
		DRM_ERROR("failed to get GSP base address\n");
		return -ENOMEM;
	}

	ctx->suspended = true; /* gsp device in off state */
	ctx->reg_size = resource_size(res);
	ctx->regs = devm_ioremap(&pdev->dev, res->start,
					ctx->reg_size);
	if (unlikely(!ctx->regs)) {
		DRM_ERROR("failed to map GSP base\n");
		return -ENOMEM;
	}

	ctx->gsp_of_dev = &(pdev->dev);
	ctx->irq = irq_of_parse_and_map(ctx->gsp_of_dev->of_node, 0);

	ret = of_property_read_u32(ctx->gsp_of_dev->of_node, "gsp_mmu_ctrl_base",
				&gsp_mmu_ctrl_addr);
	if(ret) {
		DRM_ERROR("read gsp_mmu_ctrl_addr failed:ret[%d]\n", ret);
		return -ENOMEM;
	}

	gsp_mmu_ctrl_addr = (uint32_t)ioremap_nocache(gsp_mmu_ctrl_addr, sizeof(gsp_mmu_ctrl_addr));

	if(!gsp_mmu_ctrl_addr)
		return -EFAULT;
#else
	ctx->regs = (void __iomem*) GSP_REG_BASE;
	if (!ctx->regs) {
		dev_err(dev, "failed to map registers.\n");
		return -ENXIO;
	}

	ctx->irq = TB_GSP_INT;
#endif

	GSP_AUTO_GATE_ENABLE();
	GSP_ENABLE_MM();

	ret = gsp_clock_init(ctx);
	if (ret) {
		dev_err(dev, "gsp emc clock init failed. \n");
		return ret;
	}

	ret = request_threaded_irq(ctx->irq, NULL, gsp_irq_handler,
		IRQF_ONESHOT, "drm_gsp", ctx);
	if (ret < 0) {
		dev_err(dev, "failed to request irq.\n");
		return ret;
	}

	ippdrv = &ctx->ippdrv;
	ippdrv->dev = dev;
	ippdrv->ops[SPRD_DRM_OPS_SRC] = &gsp_src_ops;
	ippdrv->ops[SPRD_DRM_OPS_DST] = &gsp_dst_ops;
	ippdrv->check_property = gsp_ippdrv_check_property;
	ippdrv->reset = gsp_ippdrv_reset;
	ippdrv->start = gsp_ippdrv_start;
	ippdrv->stop = gsp_ippdrv_stop;

	ret = gsp_init_prop_list(ippdrv);
	if (ret < 0) {
		dev_err(dev, "failed to init property list.\n");
		goto err_get_irq;
	}

	DRM_INFO("%s:id[%d]ippdrv[0x%x]\n", __func__, ctx->id, (int) ippdrv);

	mutex_init(&ctx->lock);
	platform_set_drvdata(pdev, ctx);

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	ret = sprd_drm_ippdrv_register(ippdrv);
	if (ret < 0) {
		dev_err(dev, "failed to register drm gsp device.\n");
		goto err_ippdrv_register;
	}

	memset(&ctx->gsp_cfg, 0, sizeof(ctx->gsp_cfg));

	dev_info(dev, "drm gsp registered successfully.\n");

	return 0;

err_ippdrv_register:
	devm_kfree(dev, ippdrv->prop_list);
	pm_runtime_disable(dev);

err_get_irq:
	free_irq(ctx->irq, ctx);

	return ret;
}

static int gsp_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct gsp_context *ctx = get_gsp_context(dev);
	struct sprd_drm_ippdrv *ippdrv = &ctx->ippdrv;

	devm_kfree(dev, ippdrv->prop_list);
	sprd_drm_ippdrv_unregister(ippdrv);
	mutex_destroy(&ctx->lock);

	pm_runtime_set_suspended(dev);
	pm_runtime_disable(dev);

	free_irq(ctx->irq, ctx);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int gsp_suspend(struct device *dev)
{
	struct gsp_context *ctx = get_gsp_context(dev);

	DRM_INFO("%s\n", __func__);

	if (pm_runtime_suspended(dev))
		return 0;

	return gsp_clk_ctrl(ctx, false);
}

static int gsp_resume(struct device *dev)
{
	struct gsp_context *ctx = get_gsp_context(dev);

	DRM_INFO("%s\n", __func__);

	if (!pm_runtime_suspended(dev))
		return gsp_clk_ctrl(ctx, true);

	return 0;
}
#endif

#ifdef CONFIG_PM_RUNTIME
static int gsp_runtime_suspend(struct device *dev)
{
	struct gsp_context *ctx = get_gsp_context(dev);

	DRM_DEBUG("%s\n", __func__);

	if (pm_runtime_suspended(dev) || ctx->suspended)
		return 0;

	return gsp_clk_ctrl(ctx, false);
}

static int gsp_runtime_resume(struct device *dev)
{
	struct gsp_context *ctx = get_gsp_context(dev);

	DRM_DEBUG("%s\n", __func__);

	if (!pm_runtime_suspended(dev))
		return gsp_clk_ctrl(ctx, true);

	return 0;
}
#endif

static const struct dev_pm_ops gsp_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(gsp_suspend, gsp_resume)
	SET_RUNTIME_PM_OPS(gsp_runtime_suspend, gsp_runtime_resume, NULL)
};

#ifdef CONFIG_OF
static const struct of_device_id sprd_drm_gsp_dt_match[] = {
	{ .compatible = "sprd,sprd_drm_gsp",},
	{}
};
MODULE_DEVICE_TABLE(of, sprd_drm_gsp_dt_match);
#endif

struct platform_driver gsp_driver = {
	.probe		= gsp_probe,
	.remove		= gsp_remove,
	.driver		= {
		.name	= "sprd-drm-gsp",
		.owner	= THIS_MODULE,
		.pm	= &gsp_pm_ops,
#ifdef CONFIG_OF
		.of_match_table = sprd_drm_gsp_dt_match,
#endif
	},
};

