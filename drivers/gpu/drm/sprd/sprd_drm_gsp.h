/*
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef _SPRD_DRM_GSP_H_
#define _SPRD_DRM_GSP_H_

#include "regs-gsp.h"

#define ARC_32_COEF     0x80000000

#define GSC_FIX     24
#define GSC_COUNT   64
#define TRUE        1
#define FALSE       0

#define GSC_ABS(_a)             ((_a) < 0 ? -(_a) : (_a))
#define GSC_SIGN2(input, p)     {if (p>=0) input = 1; if (p < 0) input = -1;}
#define COEF_ARR_ROWS           9
#define COEF_ARR_COL_MAX        16
#define MIN_POOL_SIZE           (6 * 1024)

#define SCI_MEMSET              memset
#define MAX( _x, _y )           (((_x) > (_y)) ? (_x) : (_y) )

#define GSP_COEFF_BUF_SIZE                              (8 << 10)
#define GSP_COEFF_COEF_SIZE                             (1 << 10)
#define GSP_COEFF_POOL_SIZE                             (6 << 10)

int32_t sin_32(int32_t n);
int32_t cos_32(int32_t n);

typedef struct {
	uint32_t begin_addr;
	uint32_t total_size;
	uint32_t used_size;
} GSC_MEM_POOL;


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
uint8_t GSP_Gen_Block_Ccaler_Coef(uint32_t i_w,
                                  uint32_t i_h,
                                  uint32_t o_w,
                                  uint32_t o_h,
                                  uint32_t hor_tap,
                                  uint32_t ver_tap,
                                  uint32_t *coeff_h_ptr,
                                  uint32_t *coeff_v_ptr,
                                  void *temp_buf_ptr,
                                  uint32_t temp_buf_size);

void GSP_Scale_Coef_Tab_Config(uint32_t *p_h_coeff,uint32_t *p_v_coeff);

#endif /* _SPRD_DRM_GSP_H_ */
