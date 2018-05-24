#include "acconfig.h"
#include "arch/probe.h"

/* flags we export */
int ceph_arch_neon = 0;
int ceph_arch_aarch64_crc32 = 0;
int ceph_arch_aarch64_pmull = 0;

#include <stdio.h>

#if __linux__

#include <elf.h>
#include <link.h> // ElfW macro
#include <sys/auxv.h>

#if __arm__ || __aarch64__
#include <asm/hwcap.h>
#endif // __arm__

static unsigned long get_auxval(unsigned long type)
{
	unsigned long result = 0;
	FILE *f = fopen("/proc/self/auxv", "r");
	if (f) {
		ElfW(auxv_t) entry;
		while (fread(&entry, sizeof(entry), 1, f) == 1) {
			if (entry.a_type == type) {
				result = entry.a_un.a_val;
				break;
			}
		}
		fclose(f);
	}
	return result;
}

static unsigned long get_hwcap(void)
{
	return getauxval(AT_HWCAP);
}

#endif // __linux__

int ceph_arch_arm_probe(void)
{
	unsigned long hwcap = get_hwcap();
#if __arm__ && __linux__
	ceph_arch_neon = (hwcap & HWCAP_NEON) == HWCAP_NEON;
#elif __aarch64__ && __linux__
	ceph_arch_neon = (hwcap & HWCAP_ASIMD) == HWCAP_ASIMD;
	ceph_arch_aarch64_crc32 = (hwcap & HWCAP_CRC32) == HWCAP_CRC32;
	ceph_arch_aarch64_pmull = (hwcap & HWCAP_PMULL) == HWCAP_PMULL;
#else
	if (0)
		get_hwcap();  // make compiler shut up
#endif
	return 0;
}

