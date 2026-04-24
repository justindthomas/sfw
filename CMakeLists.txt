# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Justin Thomas

add_vpp_plugin(sfw
  SOURCES
  sfw.c
  sfw_api.c
  sfw_node.c
  sfw_rules.c
  sfw_session.c
  sfw_nat.c
  sfw_nat64.c
  sfw.h

  MULTIARCH_SOURCES
  sfw_node.c

  API_FILES
  sfw.api

  API_TEST_SOURCES
  sfw_test.c
)
