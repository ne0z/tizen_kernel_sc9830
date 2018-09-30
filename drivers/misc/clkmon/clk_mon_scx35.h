/*
 * drivers/misc/clkmon/clk_mon_scx35.h
 *
 * Register address based on scx30 Chipset
 */

#ifndef _CLK_MON_SCX35_H_
#define _CLK_MON_SCX35_H_

#include <linux/clk_mon.h>
#include <soc/sprd/sci_glb_regs.h>

#define CLK_MON_AHB_EB	 REG_AP_AHB_AHB_EB
#define CLK_MON_AP_SYS_AUTO_SLEEP_CFG REG_AP_AHB_AP_SYS_AUTO_SLEEP_CFG
#define CLK_MON_APB_EB	REG_AP_APB_APB_EB
#define CLK_MON_AON_APB_EB0	REG_AON_APB_APB_EB0
#define CLK_MON_AON_APB_EB1	REG_AON_APB_APB_EB1
#define CLK_MON_PWR_STATUS0_DBG	REG_PMU_APB_PWR_STATUS0_DBG
#define CLK_MON_PWR_STATUS1_DBG	REG_PMU_APB_PWR_STATUS0_DBG
#define CLK_MON_PWR_STATUS2_DBG	REG_PMU_APB_PWR_STATUS0_DBG
#define CLK_MON_PWR_STATUS3_DBG	REG_PMU_APB_PWR_STATUS0_DBG
#define CLK_MON_APB_SLEEP_STATUS	REG_PMU_APB_SLEEP_STATUS

static inline unsigned int vaddr_to_paddr(unsigned long vaddr, int mode)
{
	unsigned int paddr = (unsigned int)vaddr;

	if (mode == PWR_REG) {
		paddr &= 0x0000ffff;
		paddr |= 0x10020000;
	} else if (mode == CLK_REG) {
		unsigned int tmp_high, tmp_low;
		tmp_low = paddr & 0x0000ffff;
		tmp_high = paddr & 0xffff0000;
		tmp_high -= 0xE80D0000;
		paddr = tmp_high | tmp_low;
	}

	return paddr;
}

#endif
