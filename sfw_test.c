/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw_test.c - API test client */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <sfw/sfw.api_enum.h>
#include <sfw/sfw.api_types.h>

#define __plugin_msg_base sfw_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

typedef struct
{
  u16 msg_id_base;
  vat_main_t *vat_main;
} sfw_test_main_t;

sfw_test_main_t sfw_test_main;

static int
api_sfw_enable_disable (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sfw_enable_disable_t *mp;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "disable"))
	enable_disable = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  M (SFW_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  S (mp);
  W (ret);
  return ret;
}

#include <sfw/sfw.api_test.c>
