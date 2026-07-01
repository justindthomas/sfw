/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Justin Thomas
 *
 * Standalone, VPP-free wire-format tests for sfw's three IPv6 Router
 * Advertisement option encoders:
 *
 *   sfw_pref64.c  RFC 8781  PREF64 option (type 38)
 *   sfw_rdnss.c   RFC 8106  RDNSS  option (type 25)
 *   sfw_dnr.c     RFC 9463  DNR    option (type 144)  [§6.1 RA option]
 *
 * These encoders emit bytes broadcast onto the LAN in every RA, yet are
 * dark to every other harness: the fuzz tiers stub the whole module out
 * (it needs the patched <vnet/ip6-nd/ip6_ra.h>, absent from vpp-dev), and
 * nothing asserts the produced bytes. A byteswap, wrong option type,
 * wrong length-in-8-octet-units, or bad PREF64 length-code would ship
 * silently and mis-advertise to every host on the segment.
 *
 * The REAL encoder translation units are #included below (behind a
 * minimal test-only shim for the VPP types/helpers they touch), so the
 * bytes asserted here are produced by the exact production code — not a
 * copy. Each expected buffer is hand-constructed straight from the RFC
 * (option type, length in 8-octet units, network-byte-order fields, the
 * prefix/addr/ADN payloads, PREF64's prefix-length -> code mapping, and
 * DNR's ADN DNS-wire encoding + 8-octet padding), independent of how the
 * encoder computes them.
 *
 * Build + run:  ./run.sh   (plain cc, no VPP, no container)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* The real encoders, compiled verbatim into this TU. -Ishim shadows the
 * VPP includes each of them pulls. Their static build/encode helpers thus
 * become directly callable here. */
#include "../../sfw_pref64.c"
#include "../../sfw_rdnss.c"
#include "../../sfw_dnr.c"

/* Link stubs for the runtime externs referenced only by the (compiled but
 * never-called) enable/disable/cb functions. */
sfw_main_t sfw_main;
ip6_main_t ip6_main;
int
vlib_buffer_add_data (vlib_main_t *vm, u32 *buffer_index, void *data,
		      u32 n_data_bytes)
{
  (void) vm; (void) buffer_index; (void) data; (void) n_data_bytes;
  return 0;
}
void
ip6_ra_extra_option_register (ip6_ra_extra_option_fn_t fn) { (void) fn; }
void
ip6_ra_extra_option_unregister (ip6_ra_extra_option_fn_t fn) { (void) fn; }
u32
sfw_nat64_match_pool (sfw_main_t *sm, u32 table_id, const ip6_address_t *v6)
{
  (void) sm; (void) table_id; (void) v6;
  return ~0u;
}

/* ------------------------------------------------------------------ */
/*  Tiny assertion framework                                          */
/* ------------------------------------------------------------------ */
static int g_checks = 0;
static int g_fail = 0;

static void
hexdump (const char *label, const unsigned char *b, int n)
{
  fprintf (stderr, "    %-8s", label);
  for (int i = 0; i < n; i++)
    fprintf (stderr, "%02x%s", b[i], ((i + 1) % 16 == 0 && i + 1 < n) ? "\n            " : " ");
  fprintf (stderr, "\n");
}

static void
expect_bytes (const char *name, const unsigned char *got, int got_len,
	      const unsigned char *exp, int exp_len)
{
  g_checks++;
  if (got_len == exp_len && memcmp (got, exp, exp_len) == 0)
    {
      printf ("  ok   %s (%d bytes)\n", name, exp_len);
      return;
    }
  g_fail++;
  printf ("  FAIL %s\n", name);
  if (got_len != exp_len)
    fprintf (stderr, "    length: got %d, expected %d\n", got_len, exp_len);
  hexdump ("expected", exp, exp_len);
  hexdump ("got", got, got_len < 0 ? 0 : got_len);
}

static void
expect_int (const char *name, long got, long exp)
{
  g_checks++;
  if (got == exp)
    {
      printf ("  ok   %s (= %ld)\n", name, exp);
      return;
    }
  g_fail++;
  printf ("  FAIL %s: got %ld, expected %ld\n", name, got, exp);
}

static ip6_address_t
addr (const char *s)
{
  ip6_address_t a;
  memset (&a, 0, sizeof a);
  if (inet_pton (AF_INET6, s, a.as_u8) != 1)
    {
      fprintf (stderr, "bad test address %s\n", s);
      exit (2);
    }
  return a;
}

/* ================================================================== */
/*  PREF64 — RFC 8781                                                 */
/* ================================================================== */
static void
test_pref64_plc (void)
{
  printf ("[PREF64] prefix-length -> PLC mapping (RFC 8781 Table)\n");
  struct { u8 len; int rc; u8 plc; } ok[] = {
    { 96, 0, 0 }, { 64, 0, 1 }, { 56, 0, 2 },
    { 48, 0, 3 }, { 40, 0, 4 }, { 32, 0, 5 },
  };
  for (unsigned i = 0; i < sizeof ok / sizeof ok[0]; i++)
    {
      u8 plc = 0xff;
      int rc = sfw_pref64_plc_from_len (ok[i].len, &plc);
      char nm[48];
      snprintf (nm, sizeof nm, "plc(/%u)==%u", ok[i].len, ok[i].plc);
      expect_int (nm, (rc == 0 && plc == ok[i].plc) ? 1 : 0, 1);
    }
  u8 bad_lens[] = { 0, 24, 63, 65, 97, 128 };
  for (unsigned i = 0; i < sizeof bad_lens; i++)
    {
      u8 plc;
      char nm[48];
      snprintf (nm, sizeof nm, "plc(/%u)==invalid", bad_lens[i]);
      expect_int (nm, sfw_pref64_plc_from_len (bad_lens[i], &plc), -1);
    }
}

static void
test_pref64_build (void)
{
  printf ("[PREF64] option encoding (RFC 8781 4.1)\n");
  u8 out[16];

  /* A: /96, lifetime 600s. scaled = 600/8 = 75; PLC(/96)=0;
   *    combined = (75<<3)|0 = 600 = 0x0258. Full 12-byte prefix. */
  {
    ip6_address_t p = addr ("64:ff9b::");
    sfw_pref64_build_option (out, &p, 96, 600);
    u8 exp[16] = { 38, 2, 0x02, 0x58,
		   0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 };
    expect_bytes ("pref64 /96 lt=600", out, 16, exp, 16);
  }

  /* B (tricky): /40, lifetime 601s (non-multiple of 8). Ceiling:
   *    scaled = ceil(601/8) = 76; PLC(/40)=4;
   *    combined = (76<<3)|4 = 608|4 = 612 = 0x0264.
   *    Only 5 prefix bytes (40 bits) copied; the 0xEE tail of the
   *    source MUST be zeroed so nothing leaks past the prefix. */
  {
    ip6_address_t p;
    memset (p.as_u8, 0xEE, 16);
    p.as_u8[0] = 0x20; p.as_u8[1] = 0x01; p.as_u8[2] = 0x0d;
    p.as_u8[3] = 0xb8; p.as_u8[4] = 0xaa;
    sfw_pref64_build_option (out, &p, 40, 601);
    u8 exp[16] = { 38, 2, 0x02, 0x64,
		   0x20, 0x01, 0x0d, 0xb8, 0xaa, 0, 0, 0, 0, 0, 0, 0 };
    expect_bytes ("pref64 /40 lt=601 ceil+zerofill", out, 16, exp, 16);
  }

  /* C (tricky): /32, lifetime 65535s. scaled = ceil(65535/8) = 8192 =
   *    0x2000, which exceeds the 13-bit max 0x1FFF -> clamp to 0x1FFF.
   *    PLC(/32)=5; combined = (0x1FFF<<3)|5 = 0xFFF8|5 = 0xFFFD.
   *    4 prefix bytes. Verifies the clamp and that PLC survives in the
   *    low 3 bits at the extreme. */
  {
    ip6_address_t p = addr ("102:304::");
    sfw_pref64_build_option (out, &p, 32, 65535);
    u8 exp[16] = { 38, 2, 0xff, 0xfd,
		   0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0 };
    expect_bytes ("pref64 /32 lt=65535 clamp", out, 16, exp, 16);
  }

  /* D: /64, lifetime 65528s — the exact cap sfw_pref64_enable applies.
   *    scaled = ceil(65528/8) = 8191 = 0x1FFF exactly (no clamp).
   *    PLC(/64)=1; combined = (0x1FFF<<3)|1 = 0xFFF9. 8 prefix bytes. */
  {
    ip6_address_t p = addr ("64:ff9b:1::");
    sfw_pref64_build_option (out, &p, 64, 65528);
    u8 exp[16] = { 38, 2, 0xff, 0xf9,
		   0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0x00, 0x00,
		   0, 0, 0, 0 };
    expect_bytes ("pref64 /64 lt=65528 max-noclamp", out, 16, exp, 16);
  }
}

/* ================================================================== */
/*  RDNSS — RFC 8106                                                  */
/* ================================================================== */
static void
test_rdnss_build (void)
{
  printf ("[RDNSS] option encoding (RFC 8106 5.1)\n");
  u8 out[8 + 16 * 4];

  /* A: 1 server, lifetime 600. Length field = 1 + 2*1 = 3 (8-octet
   *    units) => 24 bytes total. Reserved = 0. */
  {
    ip6_address_t s = addr ("2001:4860:4860::8888");
    sfw_rdnss_build_option (out, &s, 1, 600);
    u8 exp[24] = { 25, 3, 0x00, 0x00, 0x00, 0x00, 0x02, 0x58 };
    memcpy (exp + 8, s.as_u8, 16);
    expect_bytes ("rdnss n=1 lt=600", out, 24, exp, 24);
  }

  /* B: 3 servers, lifetime 0xFFFFFFFF (infinite). Length = 1 + 2*3 = 7
   *    => 56 bytes. Verifies length scales with N and the all-ones
   *    lifetime is emitted byte-for-byte in network order. */
  {
    ip6_address_t s[3] = { addr ("2001:db8::1"),
			   addr ("2001:db8::2"),
			   addr ("fe80::53") };
    sfw_rdnss_build_option (out, s, 3, 0xFFFFFFFFu);
    u8 exp[56] = { 25, 7, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
    for (int i = 0; i < 3; i++)
      memcpy (exp + 8 + 16 * i, s[i].as_u8, 16);
    expect_bytes ("rdnss n=3 lt=inf", out, 56, exp, 56);
  }

  /* C (tricky): lifetime 0x01020304 — distinct bytes catch any
   *    byte-order slip. 2 servers, Length = 1 + 2*2 = 5 => 40 bytes. */
  {
    ip6_address_t s[2] = { addr ("2001:db8:1::1"), addr ("2001:db8:2::2") };
    sfw_rdnss_build_option (out, s, 2, 0x01020304u);
    u8 exp[40] = { 25, 5, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
    for (int i = 0; i < 2; i++)
      memcpy (exp + 8 + 16 * i, s[i].as_u8, 16);
    expect_bytes ("rdnss n=2 lt=0x01020304 byteorder", out, 40, exp, 40);
  }

  /* D: 4 servers (SFW_RDNSS_MAX). Length field must be 1 + 2*4 = 9. */
  {
    ip6_address_t s[4] = { addr ("2001:db8::1"), addr ("2001:db8::2"),
			   addr ("2001:db8::3"), addr ("2001:db8::4") };
    sfw_rdnss_build_option (out, s, 4, 600);
    expect_int ("rdnss n=4 length-field==9", out[1], 9);
    /* And that the 4th server lands at the right offset. */
    expect_bytes ("rdnss n=4 server[3] placement",
		  out + 8 + 16 * 3, 16, s[3].as_u8, 16);
  }
}

/* ================================================================== */
/*  DNR — RFC 9463 6.1 (RA option) + RFC 9461 SvcParams               */
/* ================================================================== */

/* Independently-built RFC 9461 SvcParam blocks, for asserting the
 * encoder's static constants and for building expected DNR options. */
static const u8 EXP_DOT[8] = {
  0x00, 0x01,             /* SvcParamKey = 1 (alpn) */
  0x00, 0x04,             /* value length = 4 */
  0x03, 'd', 'o', 't',    /* alpn-id list: len 3, "dot" */
};
static const u8 EXP_DOH[27] = {
  0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2',        /* alpn = ["h2"] */
  0x00, 0x07, 0x00, 0x10,                         /* dohpath key=7, len 16 */
  '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '{', '?', 'd', 'n', 's', '}',
};

static void
test_dnr_svcparams_constants (void)
{
  printf ("[DNR] fixed SvcParams constants (RFC 9461)\n");
  expect_bytes ("dnr DoT SvcParams", sfw_dnr_svcparams_dot,
		sizeof sfw_dnr_svcparams_dot, EXP_DOT, sizeof EXP_DOT);
  expect_bytes ("dnr DoH SvcParams", sfw_dnr_svcparams_doh,
		sizeof sfw_dnr_svcparams_doh, EXP_DOH, sizeof EXP_DOH);
}

static void
test_dnr_encode_adn (void)
{
  printf ("[DNR] ADN DNS-wire encoding (RFC 1035 3.1)\n");
  u8 w[SFW_DNR_ADN_MAX];
  u16 n;

  n = sfw_dnr_encode_adn ("a.b", w);
  {
    u8 exp[5] = { 1, 'a', 1, 'b', 0 };
    expect_int ("adn(\"a.b\") len", n, 5);
    expect_bytes ("adn(\"a.b\") wire", w, n, exp, 5);
  }

  /* Trailing dot tolerated, must encode identically to no dot. */
  n = sfw_dnr_encode_adn ("example.com.", w);
  {
    u8 exp[13] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    expect_int ("adn(\"example.com.\") len", n, 13);
    expect_bytes ("adn(\"example.com.\") wire", w, n, exp, 13);
  }

  /* Rejections all return 0. */
  expect_int ("adn(\"\")==0", sfw_dnr_encode_adn ("", w), 0);
  expect_int ("adn(\".\")==0", sfw_dnr_encode_adn (".", w), 0);
  expect_int ("adn(\"a..b\")==0", sfw_dnr_encode_adn ("a..b", w), 0);
  {
    char big[80];
    memset (big, 'x', 64); big[64] = 0;   /* 64-octet label > 63 */
    expect_int ("adn(64-char label)==0", sfw_dnr_encode_adn (big, w), 0);
  }
}

static void
test_dnr_build (void)
{
  printf ("[DNR] option encoding (RFC 9463 6.1)\n");
  u8 out[SFW_DNR_OPTION_MAX];
  u16 out_len = 0;

  /* A: DoT, ADN "dns.example.com", 1 addr, priority 1, lifetime 600.
   *    body = 2+2+4+2+17+2+16+2+8 = 55 -> padded 56 (1 pad byte);
   *    Length field = 56/8 = 7. */
  {
    ip6_address_t a = addr ("2001:4860:4860::8888");
    int rc = sfw_dnr_build_option (out, &out_len, "dns.example.com", 1, 600,
				   &a, 1, EXP_DOT, sizeof EXP_DOT);
    u8 exp[56] = {
      144, 7,                          /* type, length (8-octet units) */
      0x00, 0x01,                      /* service priority = 1 */
      0x00, 0x00, 0x02, 0x58,          /* lifetime = 600 */
      0x00, 0x11,                      /* ADN length = 17 */
      3, 'd', 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
      3, 'c', 'o', 'm', 0,             /* ADN wire (17) */
      0x00, 0x10,                      /* Addr length = 16 */
      /* 16 addr bytes at [29..44] */
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0x00, 0x08,                      /* SvcParams length = 8 */
      0x00, 0x01, 0x00, 0x04, 0x03, 'd', 'o', 't',
      0x00,                            /* pad to 56 */
    };
    memcpy (exp + 29, a.as_u8, 16);
    expect_int ("dnr DoT rc", rc, 0);
    expect_bytes ("dnr DoT dns.example.com 1addr", out, out_len, exp, 56);
  }

  /* B: DoH, ADN "resolver.example.net", 2 addrs, priority 0 -> promoted
   *    to 1 (RFC 9460 2.4.1: SvcPriority 0 is AliasMode; DNR is always
   *    ServiceMode), lifetime infinite.
   *    body = 2+2+4+2+22+2+32+2+27 = 95 -> padded 96 (1 pad); Len = 12. */
  {
    ip6_address_t a[2] = { addr ("2001:4860:4860::8888"),
			   addr ("2606:4700:4700::1111") };
    int rc = sfw_dnr_build_option (out, &out_len, "resolver.example.net",
				   0, 0xFFFFFFFFu, a, 2, EXP_DOH,
				   sizeof EXP_DOH);
    u8 exp[96] = {
      144, 12,
      0x00, 0x01,                      /* priority promoted 0 -> 1 */
      0xff, 0xff, 0xff, 0xff,          /* lifetime infinite */
      0x00, 0x16,                      /* ADN length = 22 */
      8, 'r', 'e', 's', 'o', 'l', 'v', 'e', 'r',
      7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
      3, 'n', 'e', 't', 0,             /* ADN wire (22) */
      0x00, 0x20,                      /* Addr length = 32 */
      /* 32 addr bytes at [34..65] */
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0x00, 0x1b,                      /* SvcParams length = 27 */
      0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2',
      0x00, 0x07, 0x00, 0x10,
      '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '{', '?', 'd', 'n', 's', '}',
      0x00,                            /* pad to 96 */
    };
    memcpy (exp + 34, a[0].as_u8, 16);
    memcpy (exp + 50, a[1].as_u8, 16);
    expect_int ("dnr DoH rc", rc, 0);
    expect_bytes ("dnr DoH resolver.example.net 2addr prio0->1",
		  out, out_len, exp, 96);
  }

  /* C (tricky): pad-to-boundary stress. ADN "x" (wire len 3) with DoT +
   *    1 addr gives body = 2+2+4+2+3+2+16+2+8 = 41 -> padded 48, i.e.
   *    the maximum 7 pad bytes; Length field = 6. */
  {
    ip6_address_t a = addr ("2001:db8::53");
    int rc = sfw_dnr_build_option (out, &out_len, "x", 5, 600, &a, 1,
				   EXP_DOT, sizeof EXP_DOT);
    u8 exp[48] = {
      144, 6,
      0x00, 0x05,
      0x00, 0x00, 0x02, 0x58,
      0x00, 0x03,                      /* ADN length = 3 */
      1, 'x', 0,
      0x00, 0x10,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* addr [15..30] */
      0x00, 0x08,
      0x00, 0x01, 0x00, 0x04, 0x03, 'd', 'o', 't',
      0, 0, 0, 0, 0, 0, 0,             /* 7 pad bytes to 48 */
    };
    memcpy (exp + 15, a.as_u8, 16);
    expect_int ("dnr pad-stress rc", rc, 0);
    expect_bytes ("dnr ADN=\"x\" 7-byte pad", out, out_len, exp, 48);
  }

  /* D: argument rejections. */
  {
    ip6_address_t a = addr ("2001:db8::1");
    expect_int ("dnr n_addr=0 -> -1",
		sfw_dnr_build_option (out, &out_len, "a.b", 1, 600, &a, 0,
				      EXP_DOT, sizeof EXP_DOT), -1);
    expect_int ("dnr n_addr>MAX -> -1",
		sfw_dnr_build_option (out, &out_len, "a.b", 1, 600, &a,
				      SFW_DNR_MAX + 1, EXP_DOT,
				      sizeof EXP_DOT), -1);
    expect_int ("dnr bad ADN -> -1",
		sfw_dnr_build_option (out, &out_len, "a..b", 1, 600, &a, 1,
				      EXP_DOT, sizeof EXP_DOT), -1);
  }
}

int
main (void)
{
  printf ("=== sfw RA option encoder wire-format tests ===\n\n");
  test_pref64_plc ();
  test_pref64_build ();
  printf ("\n");
  test_rdnss_build ();
  printf ("\n");
  test_dnr_svcparams_constants ();
  test_dnr_encode_adn ();
  test_dnr_build ();
  printf ("\n=== %d checks, %d failed ===\n", g_checks, g_fail);
  return g_fail ? 1 : 0;
}
