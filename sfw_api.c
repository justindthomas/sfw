/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * Binary API handlers for the sfw plugin.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/format_fns.h>
#include <vnet/interface.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <sfw/sfw.h>

/* Generated types + msg IDs (produced at build time from sfw.api) */
#include <sfw/sfw.api_enum.h>
#include <sfw/sfw.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* --- sfw_enable_disable --- */

static void
vl_api_sfw_enable_disable_t_handler (vl_api_sfw_enable_disable_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_enable_disable_reply_t *rmp;
  int rv;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  int enable = mp->enable_disable ? 1 : 0;

  rv = sfw_enable_disable_interface (sm, sw_if_index, enable);

  REPLY_MACRO (VL_API_SFW_ENABLE_DISABLE_REPLY);
}

/* --- sfw_zone_interface_add_del --- */

static void
vl_api_sfw_zone_interface_add_del_t_handler (
  vl_api_sfw_zone_interface_add_del_t *mp)
{
  sfw_main_t *sm = &sfw_main;
  vl_api_sfw_zone_interface_add_del_reply_t *rmp;
  int rv = 0;

  /* Make sure the main data structures exist before we touch them. */
  sfw_feature_init (sm);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  /* zone_name is `string zone_name[32]` in the .api — VPP codegen
   * emits that as a flat u8 zone_name[32] on the wire. Copy into a
   * NUL-terminated local buffer so strcmp/sfw_zone_find_or_create
   * work correctly. */
  char zone_name[33];
  memset (zone_name, 0, sizeof (zone_name));
  memcpy (zone_name, (char *) mp->zone_name, sizeof (mp->zone_name));
  zone_name[sizeof (zone_name) - 1] = 0;

  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto done;
    }

  if (mp->is_add)
    {
      /* 'local' is built-in and cannot be assigned to a physical if. */
      if (strcmp (zone_name, "local") == 0)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto done;
	}

      u32 zone_id = sfw_zone_find_or_create (sm, zone_name);
      if (zone_id == SFW_ZONE_NONE)
	{
	  rv = VNET_API_ERROR_TABLE_TOO_BIG;
	  goto done;
	}

      vec_validate_init_empty (sm->if_config, sw_if_index,
			       (sfw_if_config_t){ 0 });
      sm->if_config[sw_if_index].zone_id = zone_id;

      /* Enable the feature arc on this interface if any policy
       * references its zone (mirror of the CLI path). */
      u32 i;
      for (i = 0; i < SFW_MAX_ZONES * SFW_MAX_ZONES; i++)
	{
	  sfw_policy_t *p = sm->zone_pairs[i].policy;
	  if (p && (p->from_zone_id == zone_id || p->to_zone_id == zone_id))
	    {
	      sfw_enable_disable_interface (sm, sw_if_index, 1);
	      break;
	    }
	}
    }
  else
    {
      /* is_add=false: remove this interface from any zone it was in
       * and turn off the feature arc. */
      if (sw_if_index < vec_len (sm->if_config))
	{
	  sm->if_config[sw_if_index].zone_id = SFW_ZONE_NONE;
	}
      sfw_enable_disable_interface (sm, sw_if_index, 0);
    }

done:
  REPLY_MACRO (VL_API_SFW_ZONE_INTERFACE_ADD_DEL_REPLY);
}

/* Pull in the generated setup_message_id_table + handler array. */
#include <sfw/sfw.api.c>

clib_error_t *
sfw_plugin_api_hookup (vlib_main_t *vm)
{
  sfw_main_t *sm = &sfw_main;
  sm->msg_id_base = setup_message_id_table ();
  return 0;
}
