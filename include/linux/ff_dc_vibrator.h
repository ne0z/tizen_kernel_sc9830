/*
* Copyright (C) 2014 Samsung Electronics Co. Ltd. All Rights Reserved.
*
* This software is licensed under the terms of the GNU General Public
* License version 2, as published by the Free Software Foundation, and
* may be copied, distributed, and modified under those terms.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
*/
#ifndef _FF_DC_VIBRATOR_H
#define _FF_DC_VIBRATOR_H
struct ff_dc_vibrator_platform_data {
	char *regulator_name;
	int max_volt;
	int min_volt;
};
#endif
