/* Copyright (c) 2018, Bingxing Wang. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <err.h>
#include <debug.h>
#include <reg.h>
#include <malloc.h>
#include <string.h>
#include <msm_panel.h>
#include <platform/timer.h>
#include <platform/clock.h>
#include "mdp5.h"
#include <platform/iomap.h>
#include "mdss_efifb.h"
#include <target/display.h>

static struct msm_fb_panel_data panel;
extern int msm_display_init(struct msm_fb_panel_data *pdata);

static int mdss_uefi_update_panel_info(void)
{
	panel.panel_info.xres = UEFI_FB_HORZ;
	panel.panel_info.yres = UEFI_FB_HORZ;
	panel.panel_info.bpp  = 32;
	panel.panel_info.type = UEFI_PANEL;
	panel.panel_info.clk_rate = 0;

	panel.panel_info.lcdc.h_back_porch  = 0;
	panel.panel_info.lcdc.h_front_porch = 0;
	panel.panel_info.lcdc.h_pulse_width = 0;
	panel.panel_info.lcdc.v_back_porch  = 0;
	panel.panel_info.lcdc.v_front_porch = 0;
	panel.panel_info.lcdc.v_pulse_width = 0;

	panel.panel_info.lcdc.hsync_skew = 0;
	panel.panel_info.lcdc.xres_pad   = 0;
	panel.panel_info.lcdc.yres_pad   = 0;
	panel.panel_info.lcdc.dual_pipe  = 0;

	panel.fb.width   = UEFI_FB_HORZ;
	panel.fb.height  = UEFI_FB_VERT;
	panel.fb.stride  = UEFI_FB_HORZ;
	panel.fb.bpp     = 32;
	panel.fb.format  = FB_FORMAT_BGRA8888;

	return NO_ERROR;
}

static int mdss_uefi_enable_power(uint8_t enable, struct msm_panel_info *pinfo)
{
	return NO_ERROR;
}

static uint32_t mdss_uefi_panel_clock(uint8_t enable, struct msm_panel_info *pinfo)
{
	return NO_ERROR;
}

static uint32_t mdss_uefi_pll_clock(uint8_t enable, struct msm_panel_info *pinfo)
{
	return NO_ERROR;
}

void mdss_uefi_display_init(uint32_t rev)
{
	panel.power_func		= mdss_uefi_enable_power;
	panel.clk_func			= mdss_uefi_panel_clock;
	panel.update_panel_info = mdss_uefi_update_panel_info;
	panel.pll_clk_func		= mdss_uefi_pll_clock;

	panel.fb.base = (void*) UEFI_FB_BASE;
	panel.mdp_rev = rev;

	msm_display_init(&panel);
}
