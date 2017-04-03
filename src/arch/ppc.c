/* Copyright (C) 2017 International Business Machines Corp.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include "arch/ppc.h"
#include "arch/probe.h"

/* flags we export */
int ceph_arch_ppc_crc32 = 0;

#include <stdio.h>
#include <sys/auxv.h>

#if __linux__ && __powerpc64__
#include <asm/cputable.h>
#endif /* __linux__ && __powerpc64__ */

#ifndef PPC_FEATURE2_VEC_CRYPTO
#define PPC_FEATURE2_VEC_CRYPTO		0x02000000
#endif

#ifndef AT_HWCAP2
#define AT_HWCAP2	26
#endif

int ceph_arch_ppc_probe(void)
{
  ceph_arch_ppc_crc32 = 0;

#if __linux__ && __powerpc64__
  if (getauxval(AT_HWCAP2) & PPC_FEATURE2_VEC_CRYPTO) ceph_arch_ppc_crc32 = 1;
#endif /* __linux__ && __powerpc64__ */

  return 0;
}

