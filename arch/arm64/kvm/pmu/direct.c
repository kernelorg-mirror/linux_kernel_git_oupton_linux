// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>

#include <asm/arm_pmuv3.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_nested.h>
#include <kvm/arm_pmu.h>

#include "pmu.h"

static u64 __effective_pmevtyper(struct kvm_vcpu *vcpu, unsigned int idx)
{
	u64 val = __vcpu_sys_reg(vcpu, counter_index_to_evtreg(idx));

	/* TODO: Enforce event filter */
	return val;
}

static void load_pmu_counter(struct kvm_vcpu *vcpu, unsigned int idx)
{
	__kvm_write_cpu_evtyper(idx, __effective_pmevtyper(vcpu, idx));
	__kvm_write_cpu_evcntr(idx, __vcpu_sys_reg(vcpu, counter_index_to_reg(idx)));
}

static void save_pmu_counter(struct kvm_vcpu *vcpu, unsigned int idx)
{
	__vcpu_sys_reg(vcpu, counter_index_to_reg(idx)) = __kvm_read_cpu_evcntr(idx);
}

#define __cfg_set_reg(pfx, sfx)	pfx ## SET ## _ ## sfx
#define __cfg_clr_reg(pfx, sfx)	pfx ## CLR ## _ ## sfx

#define load_cfg_reg_clr_set(v, pfx, sfx)				\
do {									\
	u64 __set = __vcpu_sys_reg(v, __cfg_set_reg(pfx, sfx));		\
	u64 __mask = kvm_pmu_valid_counter_mask(v);			\
	u64 __clr = ~__set & __mask;					\
									\
	write_sysreg(__set, __cfg_set_reg(pfx, sfx));			\
	write_sysreg(__clr, __cfg_clr_reg(pfx, sfx));			\
} while (0)

#define save_cfg_reg_clr_set(v, pfx, sfx)				\
do {									\
	u64 __mask = kvm_pmu_valid_counter_mask(v);			\
	u64 __set;							\
									\
	/*								\
	 * The bitmask is readable through either the CLR or SET	\
	 * accessor. Deliberatly pick the CLR accessor to preserve	\
	 * ordering w.r.t. the subsequent write.			\
	 */								\
	__set = read_sysreg(__cfg_clr_reg(pfx, sfx)) & __mask;		\
	__vcpu_sys_reg(v, __cfg_set_reg(pfx, sfx)) = __set;		\
	write_sysreg(__set, __cfg_clr_reg(pfx, sfx));			\
} while (0)

void kvm_direct_pmu_load(struct kvm_vcpu *vcpu)
{
	unsigned long mask = kvm_pmu_valid_counter_mask(vcpu);
	int i;

	for_each_set_bit(i, &mask, 32)
		load_pmu_counter(vcpu, i);

	load_cfg_reg_clr_set(vcpu, PMCNTEN, EL0);
	load_cfg_reg_clr_set(vcpu, PMINTEN, EL1);
	load_cfg_reg_clr_set(vcpu, PMOVS, EL0);
}

void kvm_direct_pmu_put(struct kvm_vcpu *vcpu)
{
	unsigned long mask = kvm_pmu_valid_counter_mask(vcpu);
	int i;

	/*
	 * The guest event counters will never count at EL2. So, the exception
	 * entry into EL2 is expected to provide the necessary context
	 * synchronization event for the PMU state to be 'stable'.
	 */
	for_each_set_bit(i, &mask, 32)
		save_pmu_counter(vcpu, i);

	save_cfg_reg_clr_set(vcpu, PMCNTEN, EL0);
	save_cfg_reg_clr_set(vcpu, PMINTEN, EL1);
	save_cfg_reg_clr_set(vcpu, PMOVS, EL0);
}
