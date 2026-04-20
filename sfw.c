/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 */

/* sfw.c - stateful firewall plugin init, CLI, feature registration */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <sfw/sfw.h>
#include <vpp/app/version.h>

sfw_main_t sfw_main;

/* --- One-time initialization --- */

void
sfw_feature_init (sfw_main_t *sm)
{
  u32 nworkers = vlib_num_workers ();

  if (sm->initialized)
    return;

  clib_bihash_init_48_8 (&sm->session_hash, "sfw sessions", sm->hash_buckets,
			  sm->hash_memory);

  vec_validate (sm->sessions, nworkers);
  vec_validate_init_empty (sm->lru_head, nworkers, ~0);
  vec_validate_init_empty (sm->lru_tail, nworkers, ~0);
  vec_validate_init_empty (sm->debug_logged, nworkers, 0);
  vec_validate (sm->pending_free, nworkers);
  vec_validate_init_empty (sm->clear_requested, nworkers, 0);

  /* Initialize zone structures.
   * Zone 0 is reserved (SFW_ZONE_NONE).
   * Zone 1 is the built-in "local" zone: the sfw node synthesizes this
   * zone_id as the destination for any packet whose FIB lookup returns
   * DPO_RECEIVE, so operators can write policies like external->local
   * to gate traffic destined for the router itself. */
  clib_memset (sm->zones, 0, sizeof (sm->zones));
  clib_memset (sm->zone_pairs, 0, sizeof (sm->zone_pairs));
  strncpy (sm->zones[SFW_ZONE_LOCAL].name, "local",
	   sizeof (sm->zones[SFW_ZONE_LOCAL].name) - 1);
  sm->zones[SFW_ZONE_LOCAL].zone_id = SFW_ZONE_LOCAL;
  sm->n_zones = 2;

  sm->initialized = 1;
}

/* --- Per-interface feature enable/disable --- */

int
sfw_enable_disable_interface (sfw_main_t *sm, u32 sw_if_index,
			      int enable_disable)
{
  sfw_feature_init (sm);

  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vec_validate_init_empty (sm->if_config, sw_if_index, (sfw_if_config_t){ 0 });

  /* Avoid double-enable/disable */
  if (enable_disable && sm->if_config[sw_if_index].feature_on)
    return 0;
  if (!enable_disable && !sm->if_config[sw_if_index].feature_on)
    return 0;

  vnet_feature_enable_disable ("ip4-unicast", "sfw-ip4", sw_if_index,
			       enable_disable, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast", "sfw-ip6", sw_if_index,
			       enable_disable, 0, 0);

  sm->if_config[sw_if_index].feature_on = enable_disable ? 1 : 0;
  return 0;
}

/* --- Zone management helpers --- */

u32
sfw_zone_find_by_name (sfw_main_t *sm, const char *name)
{
  u32 i;
  for (i = 1; i < sm->n_zones; i++)
    {
      if (strcmp (sm->zones[i].name, name) == 0)
	return i;
    }
  return SFW_ZONE_NONE;
}

static u32
sfw_zone_create (sfw_main_t *sm, const char *name)
{
  if (sm->n_zones >= SFW_MAX_ZONES)
    return SFW_ZONE_NONE;

  u32 id = sm->n_zones++;
  strncpy (sm->zones[id].name, name, sizeof (sm->zones[id].name) - 1);
  sm->zones[id].name[sizeof (sm->zones[id].name) - 1] = 0;
  sm->zones[id].zone_id = id;
  return id;
}

u32
sfw_zone_find_or_create (sfw_main_t *sm, const char *name)
{
  u32 id = sfw_zone_find_by_name (sm, name);
  if (id == SFW_ZONE_NONE)
    id = sfw_zone_create (sm, name);
  return id;
}

/* --- Policy management helpers --- */

sfw_policy_t *
sfw_policy_find (sfw_main_t *sm, const char *name)
{
  u32 i;
  for (i = 0; i < vec_len (sm->policies); i++)
    {
      if (sm->policies[i] && strcmp (sm->policies[i]->name, name) == 0)
	return sm->policies[i];
    }
  return 0;
}

sfw_policy_t *
sfw_policy_create (sfw_main_t *sm, const char *name, u32 from_zone_id,
		   u32 to_zone_id)
{
  sfw_policy_t *p;

  p = clib_mem_alloc (sizeof (*p));
  clib_memset (p, 0, sizeof (*p));
  strncpy (p->name, name, sizeof (p->name) - 1);
  p->name[sizeof (p->name) - 1] = 0;
  p->from_zone_id = from_zone_id;
  p->to_zone_id = to_zone_id;
  p->default_action = SFW_ACTION_DENY;
  p->implicit_icmpv6 = 1; /* enabled by default */

  vec_add1 (sm->policies, p);

  /* Install in zone-pair table */
  u32 zp_index = from_zone_id * SFW_MAX_ZONES + to_zone_id;
  sm->zone_pairs[zp_index].policy = p;

  /* Enable feature on all interfaces in both zones */
  u32 i;
  for (i = 0; i < vec_len (sm->if_config); i++)
    {
      if (sm->if_config[i].zone_id == from_zone_id ||
	  sm->if_config[i].zone_id == to_zone_id)
	sfw_enable_disable_interface (sm, i, 1);
    }

  return p;
}

void
sfw_policy_delete (sfw_main_t *sm, sfw_policy_t *p)
{
  if (!p)
    return;

  /* Detach from zone-pair table */
  u32 zp_index = p->from_zone_id * SFW_MAX_ZONES + p->to_zone_id;
  if (sm->zone_pairs[zp_index].policy == p)
    sm->zone_pairs[zp_index].policy = 0;

  /* Under workers, rule vec reads need to be serialized with a
   * barrier before the backing storage disappears. Only sync if
   * workers are running and VPP is past boot. */
  u8 need_barrier = (vlib_num_workers () > 0 &&
		      vlib_get_main ()->main_loop_count > 0);
  if (need_barrier)
    vlib_worker_thread_barrier_sync (sm->vlib_main);

  vec_free (p->rules);

  /* Remove from policies vector */
  u32 i;
  for (i = 0; i < vec_len (sm->policies); i++)
    {
      if (sm->policies[i] == p)
	{
	  sm->policies[i] = 0;
	  break;
	}
    }

  if (need_barrier)
    vlib_worker_thread_barrier_release (sm->vlib_main);

  clib_mem_free (p);
}

/* --- CLI: sfw zone --- */

static clib_error_t *
sfw_zone_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  char *zone_name = 0;
  u32 sw_if_index = ~0;

  sfw_feature_init (sm);

  if (!unformat (input, "%s", &zone_name))
    return clib_error_return (0, "expected zone name");

  if (!unformat (input, "interface %U", unformat_vnet_sw_interface,
		 sm->vnet_main, &sw_if_index))
    {
      vec_free (zone_name);
      return clib_error_return (0, "expected 'interface <name>'");
    }

  /* 'local' is a built-in zone owned by the plugin; don't let it be
   * assigned to a physical interface. */
  if (strcmp (zone_name, "local") == 0)
    {
      vec_free (zone_name);
      return clib_error_return (
	0, "'local' is a reserved built-in zone and cannot be assigned to "
	   "an interface");
    }

  u32 zone_id = sfw_zone_find_or_create (sm, zone_name);
  vec_free (zone_name);

  if (zone_id == SFW_ZONE_NONE)
    return clib_error_return (0, "too many zones (max %u)", SFW_MAX_ZONES - 2);

  vec_validate_init_empty (sm->if_config, sw_if_index, (sfw_if_config_t){ 0 });
  sm->if_config[sw_if_index].zone_id = zone_id;

  /* Enable feature arc on this interface if any zone-pair policy exists */
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

  return 0;
}

VLIB_CLI_COMMAND (sfw_zone_command, static) = {
  .path = "sfw zone",
  .short_help = "sfw zone <name> interface <iface-name>",
  .function = sfw_zone_command_fn,
};

/* --- CLI: show sfw zones --- */

static clib_error_t *
sfw_show_zones_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  u32 i, j;

  for (i = 1; i < sm->n_zones; i++)
    {
      vlib_cli_output (vm, "Zone %u: %s", i, sm->zones[i].name);

      /* List interfaces in this zone */
      for (j = 0; j < vec_len (sm->if_config); j++)
	{
	  if (sm->if_config[j].zone_id == i)
	    vlib_cli_output (vm, "  interface %U (sw_if_index %u)",
			     format_vnet_sw_if_index_name, sm->vnet_main, j,
			     j);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (sfw_show_zones_command, static) = {
  .path = "show sfw zones",
  .short_help = "show sfw zones",
  .function = sfw_show_zones_command_fn,
};

/* --- CLI: sfw policy --- */

static clib_error_t *
sfw_policy_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  char *policy_name = 0;
  char *from_zone_name = 0, *to_zone_name = 0;
  u8 have_from_zone = 0, have_to_zone = 0;
  u8 have_default_action = 0;
  u8 default_action = SFW_ACTION_DENY;
  u8 have_rule = 0;
  u32 rule_position = ~0;
  u8 rule_action = SFW_ACTION_DENY;
  u8 have_implicit_icmpv6 = 0;
  u8 implicit_icmpv6 = 1;
  u8 delete_rule = 0;

  /* Rule match fields */
  ip46_address_t src_prefix = { 0 }, dst_prefix = { 0 };
  u32 src_plen = 0, dst_plen = 0;
  u32 protocol = 0;
  u32 src_port_lo = 0, src_port_hi = 0;
  u32 dst_port_lo = 0, dst_port_hi = 0;
  u32 icmp_type = 255, icmp_code = 255;
  u8 af = SFW_AF_ANY;

  sfw_feature_init (sm);

  /* Parse policy name */
  if (!unformat (input, "%s", &policy_name))
    return clib_error_return (0, "expected policy name");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "from-zone %s", &from_zone_name))
	have_from_zone = 1;
      else if (unformat (input, "to-zone %s", &to_zone_name))
	have_to_zone = 1;
      else if (unformat (input, "default-action permit-stateful-nat"))
	{
	  default_action = SFW_ACTION_PERMIT_STATEFUL_NAT;
	  have_default_action = 1;
	}
      else if (unformat (input, "default-action permit-stateful"))
	{
	  default_action = SFW_ACTION_PERMIT_STATEFUL;
	  have_default_action = 1;
	}
      else if (unformat (input, "default-action permit"))
	{
	  default_action = SFW_ACTION_PERMIT;
	  have_default_action = 1;
	}
      else if (unformat (input, "default-action deny"))
	{
	  default_action = SFW_ACTION_DENY;
	  have_default_action = 1;
	}
      else if (unformat (input, "implicit-icmpv6 enable"))
	{
	  implicit_icmpv6 = 1;
	  have_implicit_icmpv6 = 1;
	}
      else if (unformat (input, "implicit-icmpv6 disable"))
	{
	  implicit_icmpv6 = 0;
	  have_implicit_icmpv6 = 1;
	}
      else if (unformat (input, "rule %u delete", &rule_position))
	{
	  have_rule = 1;
	  delete_rule = 1;
	}
      else if (unformat (input, "rule %u permit-stateful-nat",
			 &rule_position))
	{
	  have_rule = 1;
	  rule_action = SFW_ACTION_PERMIT_STATEFUL_NAT;
	}
      else if (unformat (input, "rule %u permit-stateful", &rule_position))
	{
	  have_rule = 1;
	  rule_action = SFW_ACTION_PERMIT_STATEFUL;
	}
      else if (unformat (input, "rule %u permit", &rule_position))
	{
	  have_rule = 1;
	  rule_action = SFW_ACTION_PERMIT;
	}
      else if (unformat (input, "rule %u deny", &rule_position))
	{
	  have_rule = 1;
	  rule_action = SFW_ACTION_DENY;
	}
      else if (unformat (input, "src %U/%u", unformat_ip4_address,
			 &src_prefix.ip4, &src_plen))
	af = SFW_AF_IP4;
      else if (unformat (input, "src %U/%u", unformat_ip6_address,
			 &src_prefix.ip6, &src_plen))
	af = SFW_AF_IP6;
      else if (unformat (input, "dst %U/%u", unformat_ip4_address,
			 &dst_prefix.ip4, &dst_plen))
	af = SFW_AF_IP4;
      else if (unformat (input, "dst %U/%u", unformat_ip6_address,
			 &dst_prefix.ip6, &dst_plen))
	af = SFW_AF_IP6;
      else if (unformat (input, "proto %u", &protocol))
	;
      else if (unformat (input, "sport %u-%u", &src_port_lo, &src_port_hi))
	;
      else if (unformat (input, "sport %u", &src_port_lo))
	src_port_hi = src_port_lo;
      else if (unformat (input, "dport %u-%u", &dst_port_lo, &dst_port_hi))
	;
      else if (unformat (input, "dport %u", &dst_port_lo))
	dst_port_hi = dst_port_lo;
      else if (unformat (input, "icmp-type %u", &icmp_type))
	;
      else if (unformat (input, "icmp-code %u", &icmp_code))
	;
      else
	break;
    }

  /* Validate rule field ranges */
  if (have_rule && !delete_rule)
    {
      if ((af == SFW_AF_IP4 && (src_plen > 32 || dst_plen > 32)) ||
	  (af == SFW_AF_IP6 && (src_plen > 128 || dst_plen > 128)))
	{
	  vec_free (policy_name);
	  vec_free (from_zone_name);
	  vec_free (to_zone_name);
	  return clib_error_return (0, "invalid prefix length");
	}
      if (protocol > 255 || src_port_lo > 65535 || src_port_hi > 65535 ||
	  dst_port_lo > 65535 || dst_port_hi > 65535 ||
	  icmp_type > 255 || icmp_code > 255)
	{
	  vec_free (policy_name);
	  vec_free (from_zone_name);
	  vec_free (to_zone_name);
	  return clib_error_return (0, "numeric value out of range");
	}
    }

  sfw_policy_t *p = sfw_policy_find (sm, policy_name);

  /* Create policy if it doesn't exist and we have zone-pair info */
  if (!p && have_from_zone && have_to_zone)
    {
      u32 from_id = sfw_zone_find_or_create (sm, from_zone_name);
      u32 to_id = sfw_zone_find_or_create (sm, to_zone_name);

      if (from_id == SFW_ZONE_NONE || to_id == SFW_ZONE_NONE)
	{
	  vec_free (policy_name);
	  vec_free (from_zone_name);
	  vec_free (to_zone_name);
	  return clib_error_return (0, "too many zones");
	}

      p = sfw_policy_create (sm, policy_name, from_id, to_id);
    }

  vec_free (from_zone_name);
  vec_free (to_zone_name);

  if (!p)
    {
      clib_error_t *err =
	clib_error_return (0, "policy '%s' not found", policy_name);
      vec_free (policy_name);
      return err;
    }

  vec_free (policy_name);

  if (have_default_action)
    p->default_action = default_action;

  if (have_implicit_icmpv6)
    p->implicit_icmpv6 = implicit_icmpv6;

  if (have_rule)
    {
      /* Workers read p->rules during packet processing.  Use a worker
       * barrier to prevent use-after-free from vec reallocation —
       * but only after VPP has fully started.  During unix { exec }
       * at startup, the barrier deadlocks because workers aren't
       * yet responding to barrier requests.  The exec runs single-
       * threaded on the main thread, so no synchronization is needed
       * at that point anyway. */
      u8 need_barrier = (vlib_num_workers () > 0 &&
			  vlib_get_main ()->main_loop_count > 0);
      if (need_barrier)
	vlib_worker_thread_barrier_sync (vm);

      if (delete_rule)
	{
	  if (rule_position < vec_len (p->rules))
	    vec_delete (p->rules, 1, rule_position);
	}
      else
	{
	  sfw_rule_t rule;
	  clib_memset (&rule, 0, sizeof (rule));
	  rule.action = rule_action;
	  rule.af = af;
	  rule.src_prefix = src_prefix;
	  rule.dst_prefix = dst_prefix;
	  rule.src_plen = src_plen;
	  rule.dst_plen = dst_plen;
	  rule.protocol = protocol;
	  rule.src_port_lo = src_port_lo;
	  rule.src_port_hi = src_port_hi;
	  rule.dst_port_lo = dst_port_lo;
	  rule.dst_port_hi = dst_port_hi;
	  rule.icmp_type = icmp_type;
	  rule.icmp_code = icmp_code;

	  /* Insert at position or append if beyond current length */
	  if (rule_position >= vec_len (p->rules))
	    vec_add1 (p->rules, rule);
	  else
	    {
	      vec_insert (p->rules, 1, rule_position);
	      p->rules[rule_position] = rule;
	    }
	}

      if (need_barrier)
	vlib_worker_thread_barrier_release (vm);
    }

  return 0;
}

VLIB_CLI_COMMAND (sfw_policy_command, static) = {
  .path = "sfw policy",
  .short_help = "sfw policy <name> from-zone <zone> to-zone <zone>\n"
		"sfw policy <name> default-action permit|deny|permit-stateful\n"
		"sfw policy <name> implicit-icmpv6 enable|disable\n"
		"sfw policy <name> rule <N> permit-stateful|permit|deny "
		"[src <prefix>] [dst <prefix>] [proto <num>] "
		"[sport <lo>[-<hi>]] [dport <lo>[-<hi>]]",
  .function = sfw_policy_command_fn,
};

/* --- CLI: no sfw policy --- */

static clib_error_t *
sfw_no_policy_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  char *policy_name = 0;

  if (!unformat (input, "%s", &policy_name))
    return clib_error_return (0, "expected policy name");

  sfw_policy_t *p = sfw_policy_find (sm, policy_name);
  vec_free (policy_name);

  if (!p)
    return clib_error_return (0, "policy not found");

  sfw_policy_delete (sm, p);
  return 0;
}

VLIB_CLI_COMMAND (sfw_no_policy_command, static) = {
  .path = "no sfw policy",
  .short_help = "no sfw policy <name>",
  .function = sfw_no_policy_command_fn,
};

/* --- CLI: show sfw policy --- */

static clib_error_t *
sfw_show_policy_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  static char *action_names[] = { "deny", "permit", "permit-stateful",
				   "permit-stateful-nat" };
#define ACTION_NAME(a)                                                        \
  ((a) < ARRAY_LEN (action_names) ? action_names[(a)] : "unknown")
  u32 i, j;

  for (i = 0; i < vec_len (sm->policies); i++)
    {
      sfw_policy_t *p = sm->policies[i];
      if (!p)
	continue;

      const char *from_name =
	(p->from_zone_id < sm->n_zones) ? sm->zones[p->from_zone_id].name :
					   "?";
      const char *to_name =
	(p->to_zone_id < sm->n_zones) ? sm->zones[p->to_zone_id].name : "?";

      vlib_cli_output (vm, "Policy: %s (from-zone %s to-zone %s)", p->name,
		       from_name, to_name);
      vlib_cli_output (vm, "  default-action: %s",
		       ACTION_NAME (p->default_action));
      vlib_cli_output (vm, "  implicit-icmpv6: %s",
		       p->implicit_icmpv6 ? "enabled" : "disabled");
      vlib_cli_output (vm, "  rules: %u", vec_len (p->rules));

      char *af_names[] = { "any", "ip4", "ip6" };
      for (j = 0; j < vec_len (p->rules); j++)
	{
	  sfw_rule_t *r = &p->rules[j];
	  u8 show_v6 = (r->af == SFW_AF_IP6);

	  /* Build optional fields string */
	  u8 *detail = 0;

	  if (r->protocol)
	    detail = format (detail, " proto %u", r->protocol);

	  if (r->src_plen)
	    detail = format (
	      detail, " src %U/%u",
	      show_v6 ? format_ip6_address :
			(format_function_t *) format_ip4_address,
	      show_v6 ? (void *) &r->src_prefix.ip6 :
			(void *) &r->src_prefix.ip4,
	      r->src_plen);

	  if (r->dst_plen)
	    detail = format (
	      detail, " dst %U/%u",
	      show_v6 ? format_ip6_address :
			(format_function_t *) format_ip4_address,
	      show_v6 ? (void *) &r->dst_prefix.ip6 :
			(void *) &r->dst_prefix.ip4,
	      r->dst_plen);

	  if (r->src_port_lo)
	    {
	      if (r->src_port_hi && r->src_port_hi != r->src_port_lo)
		detail = format (detail, " sport %u-%u", r->src_port_lo,
				 r->src_port_hi);
	      else
		detail = format (detail, " sport %u", r->src_port_lo);
	    }

	  if (r->dst_port_lo)
	    {
	      if (r->dst_port_hi && r->dst_port_hi != r->dst_port_lo)
		detail = format (detail, " dport %u-%u", r->dst_port_lo,
				 r->dst_port_hi);
	      else
		detail = format (detail, " dport %u", r->dst_port_lo);
	    }

	  if (r->icmp_type != 255)
	    detail = format (detail, " icmp-type %u", r->icmp_type);
	  if (r->icmp_code != 255)
	    detail = format (detail, " icmp-code %u", r->icmp_code);

	  u8 *line = format (0, "    [%u] %s", j, ACTION_NAME (r->action));
	  if (r->af != SFW_AF_ANY)
	    line = format (line, " %s", af_names[r->af]);
	  if (vec_len (detail))
	    line = format (line, "%v", detail);
	  vlib_cli_output (vm, "%v", line);
	  vec_free (line);
	  vec_free (detail);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (sfw_show_policy_command, static) = {
  .path = "show sfw policy",
  .short_help = "show sfw policy",
  .function = sfw_show_policy_command_fn,
};

/* --- CLI: show sfw sessions --- */

/* Note: this command reads worker-owned session pools without
 * synchronization. Output is best-effort and may show stale or
 * partially updated entries on a live system under load. This is
 * acceptable for diagnostics — strict session auditing would require
 * worker quiescence. */
static clib_error_t *
sfw_show_sessions_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  int verbose = 0;
  u8 show_ip4 = 0, show_ip6 = 0;
  sfw_session_t *s;
  u32 i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "ipv4"))
	show_ip4 = 1;
      else if (unformat (input, "ipv6"))
	show_ip6 = 1;
      else
	break;
    }

  /* If neither specified, show both */
  if (!show_ip4 && !show_ip6)
    {
      show_ip4 = 1;
      show_ip6 = 1;
    }

  if (!sm->initialized)
    {
      vlib_cli_output (vm, "sfw not initialized");
      return 0;
    }

  f64 now = vlib_time_now (vm);

  for (i = 0; i < vec_len (sm->sessions); i++)
    {
      u32 count = 0;
      if (show_ip4 && show_ip6)
	count = pool_elts (sm->sessions[i]);
      else
	{
	  pool_foreach (s, sm->sessions[i])
	    {
	      if ((show_ip4 && !s->is_ip6) || (show_ip6 && s->is_ip6))
		count++;
	    }
	}

      if (i > 0 && verbose)
	vlib_cli_output (vm, "");
      vlib_cli_output (vm, "Thread %u: %u sessions", i, count);

      if (!verbose)
	continue;

      pool_foreach (s, sm->sessions[i])
	{
	  if ((show_ip4 && !s->is_ip6) || (show_ip6 && s->is_ip6))
	    vlib_cli_output (vm, "%U", format_sfw_session, s, now, verbose);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (sfw_show_sessions_command, static) = {
  .path = "show sfw sessions",
  .short_help = "show sfw sessions [ipv4|ipv6] [verbose]",
  .function = sfw_show_sessions_command_fn,
};

/* --- CLI: show sfw lookup (diagnostic) --- */

static clib_error_t *
sfw_show_lookup_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  ip4_address_t src4, dst4;
  u16 sport = 0, dport = 0;
  u8 proto = 6;

  if (!unformat (input, "src %U sport %u dst %U dport %u proto %u",
		 unformat_ip4_address, &src4, &sport, unformat_ip4_address,
		 &dst4, &dport, &proto))
    return clib_error_return (
      0, "usage: show sfw lookup src <ip> sport <N> dst <ip> dport <N> "
	 "proto <N>");

  if (!sm->initialized)
    return clib_error_return (0, "sfw not initialized");

  clib_bihash_kv_48_8_t kv;
  clib_memset (&kv, 0, sizeof (kv));
  sfw_key4_t *key = (sfw_key4_t *) &kv.key;
  key->src = src4;
  key->dst = dst4;
  key->src_port = clib_host_to_net_u16 (sport);
  key->dst_port = clib_host_to_net_u16 (dport);
  key->protocol = proto;

  vlib_cli_output (vm, "Looking up: %U:%u -> %U:%u proto %u",
		   format_ip4_address, &src4, sport, format_ip4_address, &dst4,
		   dport, proto);
  vlib_cli_output (vm, "Key bytes: %U", format_hexdump, &kv.key, 48);

  if (clib_bihash_search_48_8 (&sm->session_hash, &kv, &kv) == 0)
    {
      u32 t = sfw_session_thread (kv.value);
      u32 i = sfw_session_index (kv.value);
      vlib_cli_output (vm, "FOUND: thread %u index %u", t, i);
    }
  else
    vlib_cli_output (vm, "NOT FOUND");

  return 0;
}

VLIB_CLI_COMMAND (sfw_show_lookup_command, static) = {
  .path = "show sfw lookup",
  .short_help =
    "show sfw lookup <src-ip> <sport> <dst-ip> <dport> proto <N>",
  .function = sfw_show_lookup_command_fn,
};

/* --- CLI: clear sfw sessions --- */

static clib_error_t *
sfw_clear_sessions_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  u32 i;

  if (!sm->initialized)
    return 0;

  /* Signal each worker to clear its own sessions.  Workers check
   * this flag in sfw_expire_inline and handle clearing with proper
   * ownership of their pools and pending_free lists. */
  for (i = 0; i < vec_len (sm->clear_requested); i++)
    sm->clear_requested[i] = 1;

  vlib_cli_output (vm, "Session clear requested for all workers");
  return 0;
}

VLIB_CLI_COMMAND (sfw_clear_sessions_command, static) = {
  .path = "clear sfw sessions",
  .short_help = "clear sfw sessions",
  .function = sfw_clear_sessions_command_fn,
};

/* Session expiry is handled inline by each worker thread in the
 * sfw_ip4/sfw_ip6 node functions via sfw_expire_inline(). Each worker
 * only expires its own sessions, avoiding cross-thread pool access. */

/* --- CLI: sfw nat pool --- */

static clib_error_t *
sfw_nat_pool_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  ip4_address_t external_addr, internal_addr;
  u32 external_plen = 0, internal_plen = 0;
  u8 mode = SFW_NAT_MODE_DYNAMIC;

  if (!unformat (input, "%U/%u", unformat_ip4_address, &external_addr,
		 &external_plen))
    return clib_error_return (0, "expected external prefix");

  if (!unformat (input, "internal %U/%u", unformat_ip4_address, &internal_addr,
		 &internal_plen))
    return clib_error_return (0, "expected 'internal <prefix>'");

  if (unformat (input, "mode deterministic"))
    mode = SFW_NAT_MODE_DETERMINISTIC;
  else if (unformat (input, "mode dynamic"))
    mode = SFW_NAT_MODE_DYNAMIC;

  /* Validate prefix lengths */
  if (external_plen > 32)
    return clib_error_return (0, "external prefix length %u > 32",
			      external_plen);
  if (internal_plen > 32)
    return clib_error_return (0, "internal prefix length %u > 32",
			      internal_plen);

  sfw_nat_pool_t pool;
  clib_memset (&pool, 0, sizeof (pool));
  pool.external_addr = external_addr;
  pool.external_plen = external_plen;
  pool.internal_addr = internal_addr;
  pool.internal_plen = internal_plen;
  pool.mode = mode;
  pool.port_range_start = 1024;
  pool.port_range_end = 65535;
  pool.n_external_addrs = (external_plen < 32) ? (1u << (32 - external_plen)) : 1;
  pool.n_internal_addrs = (internal_plen < 32) ? (1u << (32 - internal_plen)) : 1;

  /* Compute ports_per_host for deterministic mode */
  u32 hosts_per_external = pool.n_internal_addrs / pool.n_external_addrs;
  if (hosts_per_external == 0)
    hosts_per_external = 1;
  u32 port_range = pool.port_range_end - pool.port_range_start + 1;
  pool.ports_per_host = (u16) (port_range / hosts_per_external);
  if (pool.ports_per_host == 0)
    pool.ports_per_host = 1;

  /* Allocate per-thread port ranges for dynamic mode.
   * Partition the port range so each thread gets an exclusive slice. */
  if (mode == SFW_NAT_MODE_DYNAMIC)
    {
      sfw_feature_init (sm);
      u32 nworkers = vlib_num_workers ();
      u32 nthreads = nworkers + 1; /* include main thread 0 */
      u32 slice = port_range / nthreads;
      if (slice == 0)
	slice = 1;

      vec_validate (pool.port_bitmaps, nworkers);
      vec_validate (pool.next_port, nworkers);
      vec_validate (pool.thread_port_start, nworkers);
      vec_validate (pool.thread_port_count, nworkers);

      u32 t;
      for (t = 0; t < nthreads; t++)
	{
	  pool.thread_port_start[t] = pool.port_range_start + (t * slice);
	  pool.thread_port_count[t] =
	    (t == nthreads - 1) ? (port_range - t * slice) : slice;

	  vec_validate (pool.port_bitmaps[t], pool.n_external_addrs - 1);
	  vec_validate_init_empty (pool.next_port[t],
				   pool.n_external_addrs - 1, 0);
	  u32 a;
	  for (a = 0; a < pool.n_external_addrs; a++)
	    pool.port_bitmaps[t][a] = 0; /* all clear = all free */
	}
    }

  vec_add1 (sm->nat_pools, pool);

  char *mode_names[] = { "deterministic", "dynamic" };
  vlib_cli_output (vm, "NAT pool added: %U/%u -> %U/%u mode %s",
		   format_ip4_address, &external_addr, external_plen,
		   format_ip4_address, &internal_addr, internal_plen,
		   mode_names[mode]);
  return 0;
}

VLIB_CLI_COMMAND (sfw_nat_pool_command, static) = {
  .path = "sfw nat pool",
  .short_help = "sfw nat pool <ext-prefix> internal <int-prefix> "
		"mode deterministic|dynamic",
  .function = sfw_nat_pool_command_fn,
};

/* --- CLI: sfw nat static --- */

static clib_error_t *
sfw_nat_static_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  ip4_address_t external_addr, internal_addr;
  u32 external_port = 0, internal_port = 0;
  u8 protocol = 0;

  /* Try port-specific format: "tcp|udp addr:port to addr:port" */
  if (unformat (input, "tcp %U:%u to %U:%u", unformat_ip4_address,
		&external_addr, &external_port, unformat_ip4_address,
		&internal_addr, &internal_port))
    protocol = IP_PROTOCOL_TCP;
  else if (unformat (input, "udp %U:%u to %U:%u", unformat_ip4_address,
		     &external_addr, &external_port, unformat_ip4_address,
		     &internal_addr, &internal_port))
    protocol = IP_PROTOCOL_UDP;
  /* Try 1:1 format: "addr to addr" */
  else if (unformat (input, "%U to %U", unformat_ip4_address, &external_addr,
		     unformat_ip4_address, &internal_addr))
    {
      protocol = 0;
      external_port = 0;
      internal_port = 0;
    }
  else
    return clib_error_return (
      0, "expected 'tcp|udp <ext-ip>:<port> to <int-ip>:<port>' or "
	 "'<ext-ip> to <int-ip>'");

  if (external_port > 65535 || internal_port > 65535)
    return clib_error_return (0, "port out of range (0-65535)");

  sfw_nat_static_t mapping;
  clib_memset (&mapping, 0, sizeof (mapping));
  mapping.external_addr = external_addr;
  mapping.external_port = external_port;
  mapping.internal_addr = internal_addr;
  mapping.internal_port = internal_port;
  mapping.protocol = protocol;

  vec_add1 (sm->nat_statics, mapping);

  if (protocol)
    vlib_cli_output (vm, "DNAT static: %s %U:%u -> %U:%u",
		     protocol == IP_PROTOCOL_TCP ? "tcp" : "udp",
		     format_ip4_address, &external_addr, external_port,
		     format_ip4_address, &internal_addr, internal_port);
  else
    vlib_cli_output (vm, "DNAT static: 1:1 %U -> %U", format_ip4_address,
		     &external_addr, format_ip4_address, &internal_addr);
  return 0;
}

VLIB_CLI_COMMAND (sfw_nat_static_command, static) = {
  .path = "sfw nat static",
  .short_help = "sfw nat static tcp|udp <ext-ip>:<port> to <int-ip>:<port>\n"
		"sfw nat static <ext-ip> to <int-ip>  (1:1 NAT)",
  .function = sfw_nat_static_command_fn,
};

/* --- CLI: show sfw nat --- */

static clib_error_t *
sfw_show_nat_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  char *mode_names[] = { "deterministic", "dynamic" };
  u32 i;

  vlib_cli_output (vm, "NAT pools: %u", vec_len (sm->nat_pools));
  for (i = 0; i < vec_len (sm->nat_pools); i++)
    {
      sfw_nat_pool_t *p = &sm->nat_pools[i];
      if (p->mode == SFW_NAT_MODE_DETERMINISTIC)
	vlib_cli_output (
	  vm, "  [%u] %U/%u -> %U/%u mode %s (ports-per-host %u)", i,
	  format_ip4_address, &p->external_addr, p->external_plen,
	  format_ip4_address, &p->internal_addr, p->internal_plen,
	  mode_names[p->mode], p->ports_per_host);
      else
	{
	  vlib_cli_output (vm, "  [%u] %U/%u -> %U/%u mode %s", i,
			   format_ip4_address, &p->external_addr,
			   p->external_plen, format_ip4_address,
			   &p->internal_addr, p->internal_plen,
			   mode_names[p->mode]);
	  if (p->port_bitmaps)
	    {
	      u32 t;
	      for (t = 0; t < vec_len (p->thread_port_count); t++)
		vlib_cli_output (vm,
				 "    thread %u: port_start=%u count=%u "
				 "bitmaps=%s",
				 t, p->thread_port_start[t],
				 p->thread_port_count[t],
				 p->port_bitmaps[t] ? "allocated" : "NULL");
	    }
	  else
	    vlib_cli_output (vm, "    port_bitmaps: NOT ALLOCATED");
	}
    }

  vlib_cli_output (vm, "\nDNAT static mappings: %u",
		   vec_len (sm->nat_statics));
  for (i = 0; i < vec_len (sm->nat_statics); i++)
    {
      sfw_nat_static_t *s = &sm->nat_statics[i];
      if (s->protocol)
	vlib_cli_output (vm, "  [%u] %s %U:%u -> %U:%u", i,
			 s->protocol == IP_PROTOCOL_TCP ? "tcp" : "udp",
			 format_ip4_address, &s->external_addr,
			 s->external_port, format_ip4_address,
			 &s->internal_addr, s->internal_port);
      else
	vlib_cli_output (vm, "  [%u] 1:1 %U -> %U", i, format_ip4_address,
			 &s->external_addr, format_ip4_address,
			 &s->internal_addr);
    }

  return 0;
}

VLIB_CLI_COMMAND (sfw_show_nat_command, static) = {
  .path = "show sfw nat",
  .short_help = "show sfw nat",
  .function = sfw_show_nat_command_fn,
};

/* --- CLI: show sfw nat reverse --- */

static clib_error_t *
sfw_show_nat_reverse_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  sfw_main_t *sm = &sfw_main;
  ip4_address_t addr;
  u32 port = 0;

  if (!unformat (input, "%U:%u", unformat_ip4_address, &addr, &port))
    return clib_error_return (0, "expected <address>:<port>");

  if (port > 65535)
    return clib_error_return (0, "port out of range");

  u32 i;
  for (i = 0; i < vec_len (sm->nat_pools); i++)
    {
      sfw_nat_pool_t *pool = &sm->nat_pools[i];

      if (pool->mode != SFW_NAT_MODE_DETERMINISTIC)
	continue;

      /* Check if the address falls within this pool's external range */
      u32 mask = pool->external_plen ?
		   clib_host_to_net_u32 (~0u << (32 - pool->external_plen)) :
		   0;
      if ((addr.as_u32 & mask) != (pool->external_addr.as_u32 & mask))
	continue;
      u32 ext_idx =
	sfw_ip4_addr_index (&addr, &pool->external_addr, pool->external_plen);
      if (ext_idx >= pool->n_external_addrs)
	continue;

      /* Check if the port falls within the allocatable range */
      if (port < pool->port_range_start || port > pool->port_range_end)
	{
	  vlib_cli_output (vm, "Port %u is outside the allocatable range "
			       "(%u-%u)",
			   port, pool->port_range_start, pool->port_range_end);
	  return 0;
	}

      /* Reverse the deterministic mapping:
       *   host_offset = (port - port_range_start) / ports_per_host
       *   internal_idx = ext_idx * hosts_per_external + host_offset */
      u32 hosts_per_external =
	pool->n_internal_addrs / pool->n_external_addrs;
      if (hosts_per_external == 0)
	hosts_per_external = 1;

      u32 host_offset = (port - pool->port_range_start) / pool->ports_per_host;
      if (host_offset >= hosts_per_external)
	{
	  vlib_cli_output (vm, "Port %u does not map to a valid host", port);
	  return 0;
	}

      u32 internal_idx = ext_idx * hosts_per_external + host_offset;
      ip4_address_t internal_addr;
      sfw_ip4_addr_from_index (&internal_addr, &pool->internal_addr,
			       pool->internal_plen, internal_idx);

      u16 port_base =
	pool->port_range_start + (host_offset * pool->ports_per_host);
      u16 port_end = port_base + pool->ports_per_host - 1;

      vlib_cli_output (vm, "%U:%u -> %U", format_ip4_address, &addr, port,
		       format_ip4_address, &internal_addr);
      vlib_cli_output (vm, "  Pool: %U/%u -> %U/%u (deterministic)",
		       format_ip4_address, &pool->external_addr,
		       pool->external_plen, format_ip4_address,
		       &pool->internal_addr, pool->internal_plen);
      vlib_cli_output (vm, "  Host port range: %u-%u (%u ports)", port_base,
		       port_end, pool->ports_per_host);
      return 0;
    }

  /* Check if it matches a dynamic pool (not reversible) */
  for (i = 0; i < vec_len (sm->nat_pools); i++)
    {
      sfw_nat_pool_t *pool = &sm->nat_pools[i];
      if (pool->mode == SFW_NAT_MODE_DETERMINISTIC)
	continue;
      u32 dmask = pool->external_plen ?
		    clib_host_to_net_u32 (~0u << (32 - pool->external_plen)) :
		    0;
      if ((addr.as_u32 & dmask) == (pool->external_addr.as_u32 & dmask))
	{
	  vlib_cli_output (
	    vm, "%U:%u belongs to a dynamic NAT pool — reverse "
		"lookup is only supported for deterministic mode",
	    format_ip4_address, &addr, port);
	  return 0;
	}
    }

  vlib_cli_output (vm, "No matching NAT pool for %U:%u", format_ip4_address,
		   &addr, port);
  return 0;
}

VLIB_CLI_COMMAND (sfw_show_nat_reverse_command, static) = {
  .path = "show sfw nat reverse",
  .short_help = "show sfw nat reverse <address>:<port>",
  .function = sfw_show_nat_reverse_command_fn,
};

/* --- Plugin init --- */

static clib_error_t *
sfw_init (vlib_main_t *vm)
{
  sfw_main_t *sm = &sfw_main;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Defaults */
  sm->session_timeout = 120.0;
  sm->max_sessions_per_worker = 100000;
  sm->hash_buckets = 64 << 10; /* 64K */
  sm->hash_memory = 256ULL << 20; /* 256 MB */

  /* Wire up the binary API handlers defined in sfw_api.c. */
  clib_error_t *err = sfw_plugin_api_hookup (vm);
  if (err)
    return err;

  return 0;
}

VLIB_INIT_FUNCTION (sfw_init);

/* --- Startup config --- */

static clib_error_t *
sfw_config (vlib_main_t *vm, unformat_input_t *input)
{
  sfw_main_t *sm = &sfw_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "session-timeout %f", &sm->session_timeout))
	;
      else if (unformat (input, "session-hash-buckets %u", &sm->hash_buckets))
	;
      else if (unformat (input, "session-hash-memory %U",
			 unformat_memory_size, &sm->hash_memory))
	;
      else if (unformat (input, "max-sessions-per-worker %u",
			 &sm->max_sessions_per_worker))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (sfw_config, "sfw");

/* --- Feature arc registration --- */

/* sfw replaces NAT plugins — runs after ACL/reassembly, before lookup.
 * No NAT plugins should be loaded when sfw handles NAT. */
VNET_FEATURE_INIT (sfw_ip4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "sfw-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (sfw_ip6, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "sfw-ip6",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa",
			       "ip6-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

/* --- Plugin registration --- */

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Stateful Firewall (dual-stack)",
};
