// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Arm Limited
 * Author: Andrew Murray <Andrew.Murray@arm.com>
 */
#include <linux/kvm_host.h>
#include <linux/perf_event.h>

#include "pmu.h"

static DEFINE_PER_CPU(struct kvm_pmu_events, kvm_pmu_events);

u32 __kvm_pmu_event_mask(unsigned int pmuver)
{
	switch (pmuver) {
	case ID_AA64DFR0_EL1_PMUVer_IMP:
		return GENMASK(9, 0);
	case ID_AA64DFR0_EL1_PMUVer_V3P1:
	case ID_AA64DFR0_EL1_PMUVer_V3P4:
	case ID_AA64DFR0_EL1_PMUVer_V3P5:
	case ID_AA64DFR0_EL1_PMUVer_V3P7:
		return GENMASK(15, 0);
	default:		/* Shouldn't be here, just for sanity */
		WARN_ONCE(1, "Unknown PMU version %d\n", pmuver);
		return 0;
	}
}

u32 kvm_pmu_event_mask(struct kvm *kvm)
{
	u64 dfr0 = kvm_read_vm_id_reg(kvm, SYS_ID_AA64DFR0_EL1);
	u8 pmuver = SYS_FIELD_GET(ID_AA64DFR0_EL1, PMUVer, dfr0);

	return __kvm_pmu_event_mask(pmuver);
}

/*
 * Given the perf event attributes and system type, determine
 * if we are going to need to switch counters at guest entry/exit.
 */
static bool kvm_pmu_switch_needed(struct perf_event_attr *attr)
{
	/**
	 * With VHE the guest kernel runs at EL1 and the host at EL2,
	 * where user (EL0) is excluded then we have no reason to switch
	 * counters.
	 */
	if (has_vhe() && attr->exclude_user)
		return false;

	/* Only switch if attributes are different */
	return (attr->exclude_host != attr->exclude_guest);
}

struct kvm_pmu_events *kvm_get_pmu_events(void)
{
	return this_cpu_ptr(&kvm_pmu_events);
}

/*
 * Add events to track that we may want to switch at guest entry/exit
 * time.
 */
void kvm_set_pmu_events(u32 set, struct perf_event_attr *attr)
{
	struct kvm_pmu_events *pmu = kvm_get_pmu_events();

	if (!kvm_arm_support_pmu_v3() || !kvm_pmu_switch_needed(attr))
		return;

	if (!attr->exclude_host)
		pmu->events_host |= set;
	if (!attr->exclude_guest)
		pmu->events_guest |= set;
}

/*
 * Stop tracking events
 */
void kvm_clr_pmu_events(u32 clr)
{
	struct kvm_pmu_events *pmu = kvm_get_pmu_events();

	if (!kvm_arm_support_pmu_v3())
		return;

	pmu->events_host &= ~clr;
	pmu->events_guest &= ~clr;
}

/*
 * Read a value direct from PMEVTYPER<idx> where idx is 0-30
 * or PMCCFILTR_EL0 where idx is ARMV8_PMU_CYCLE_IDX (31).
 */
u64 __kvm_read_cpu_evtyper(unsigned int idx)
{
	if (idx == ARMV8_PMU_CYCLE_IDX)
		return read_pmccfiltr();

	return read_pmevtypern(idx);
}

/*
 * Write a value direct to PMEVTYPER<idx> where idx is 0-30
 * or PMCCFILTR_EL0 where idx is ARMV8_PMU_CYCLE_IDX (31).
 */
void __kvm_write_cpu_evtyper(unsigned int idx, u64 val)
{
	if (idx == ARMV8_PMU_CYCLE_IDX)
		write_pmccfiltr(val);
	else
		write_pmevtypern(idx, val);
}

/*
 * Read a value direct from PMEVCNTR<idx> where idx is 0-30
 * or PMCCNTR_EL0 where idx is ARMV8_PMU_CYCLE_IDX (31).
 */
u64 __kvm_read_cpu_evcntr(unsigned int idx)
{
	if (idx == ARMV8_PMU_CYCLE_IDX)
		return read_pmccntr();

	return read_pmevcntrn(idx);
}

/*
 * Write a value direct to PMEVCNTR<idx> where idx is 0-30
 * or PMCCNTR_EL0 where idx is ARMV8_PMU_CYCLE_IDX (31).
 */
void __kvm_write_cpu_evcntr(unsigned int idx, u64 val)
{
	if (idx == ARMV8_PMU_CYCLE_IDX)
		write_pmccntr(val);
	else
		write_pmevcntrn(idx, val);
}

/*
 * Modify ARMv8 PMU events to include EL0 counting
 */
static void kvm_vcpu_pmu_enable_el0(unsigned long events)
{
	u64 typer;
	u32 counter;

	for_each_set_bit(counter, &events, 32) {
		typer = __kvm_read_cpu_evtyper(counter);
		typer &= ~ARMV8_PMU_EXCLUDE_EL0;
		__kvm_write_cpu_evtyper(counter, typer);
	}
}

/*
 * Modify ARMv8 PMU events to exclude EL0 counting
 */
static void kvm_vcpu_pmu_disable_el0(unsigned long events)
{
	u64 typer;
	u32 counter;

	for_each_set_bit(counter, &events, 32) {
		typer = __kvm_read_cpu_evtyper(counter);
		typer |= ARMV8_PMU_EXCLUDE_EL0;
		__kvm_write_cpu_evtyper(counter, typer);
	}
}

/*
 * On VHE ensure that only guest events have EL0 counting enabled.
 * This is called from both vcpu_{load,put} and the sysreg handling.
 * Since the latter is preemptible, special care must be taken to
 * disable preemption.
 */
void kvm_vcpu_pmu_restore_guest(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu_events *pmu;
	u32 events_guest, events_host;

	if (!kvm_arm_support_pmu_v3() || !has_vhe())
		return;

	preempt_disable();
	pmu = kvm_get_pmu_events();
	events_guest = pmu->events_guest;
	events_host = pmu->events_host;

	kvm_vcpu_pmu_enable_el0(events_guest);
	kvm_vcpu_pmu_disable_el0(events_host);
	preempt_enable();
}

/*
 * On VHE ensure that only host events have EL0 counting enabled
 */
void kvm_vcpu_pmu_restore_host(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu_events *pmu;
	u32 events_guest, events_host;

	if (!kvm_arm_support_pmu_v3() || !has_vhe())
		return;

	pmu = kvm_get_pmu_events();
	events_guest = pmu->events_guest;
	events_host = pmu->events_host;

	kvm_vcpu_pmu_enable_el0(events_host);
	kvm_vcpu_pmu_disable_el0(events_guest);
}

/*
 * With VHE, keep track of the PMUSERENR_EL0 value for the host EL0 on the pCPU
 * where PMUSERENR_EL0 for the guest is loaded, since PMUSERENR_EL0 is switched
 * to the value for the guest on vcpu_load().  The value for the host EL0
 * will be restored on vcpu_put(), before returning to userspace.
 * This isn't necessary for nVHE, as the register is context switched for
 * every guest enter/exit.
 *
 * Return true if KVM takes care of the register. Otherwise return false.
 */
bool kvm_set_pmuserenr(u64 val)
{
	struct kvm_cpu_context *hctxt;
	struct kvm_vcpu *vcpu;

	if (!kvm_arm_support_pmu_v3() || !has_vhe())
		return false;

	vcpu = kvm_get_running_vcpu();
	if (!vcpu || !vcpu_get_flag(vcpu, PMUSERENR_ON_CPU))
		return false;

	hctxt = host_data_ptr(host_ctxt);
	ctxt_sys_reg(hctxt, PMUSERENR_EL0) = val;
	return true;
}

/*
 * If we interrupted the guest to update the host PMU context, make
 * sure we re-apply the guest EL0 state.
 */
void kvm_vcpu_pmu_resync_el0(void)
{
	struct kvm_vcpu *vcpu;

	if (!has_vhe() || !in_interrupt())
		return;

	vcpu = kvm_get_running_vcpu();
	if (!vcpu)
		return;

	kvm_make_request(KVM_REQ_RESYNC_PMU_EL0, vcpu);
}

void kvm_pmu_write_evtyper(struct kvm_vcpu *vcpu, u64 val, unsigned int idx)
{
	val &= kvm_pmu_evtyper_mask(vcpu->kvm);

	if (kvm_has_direct_pmu(vcpu->kvm))
		direct_pmu_write_evtyper(vcpu, val, idx);
	else
		emulated_pmu_write_evtyper(vcpu, val, idx);
}

void kvm_pmu_write_evcntr(struct kvm_vcpu *vcpu, unsigned int idx, u64 val)
{
	if (kvm_has_direct_pmu(vcpu->kvm))
		direct_pmu_write_evcntr(vcpu, val, idx);
	else
		emulated_pmu_write_evtyper(vcpu, val, idx);
}

u64 kvm_pmu_read_evcntr(struct kvm_vcpu *vcpu, unsigned int idx)
{
	if (kvm_has_direct_pmu(vcpu->kvm))
		return direct_pmu_read_evcntr(vcpu, idx);

	return emulated_pmu_read_evcntr(vcpu, idx);
}
