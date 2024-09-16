#ifndef __ARM64_KVM_PMU_H__
#define __ARM64_KVM_PMU_H__

#include <linux/kvm_host.h>

static inline u32 counter_index_to_reg(unsigned int idx)
{
	return (idx == ARMV8_PMU_CYCLE_IDX) ? PMCCNTR_EL0 : PMEVCNTR0_EL0 + idx;
}

static inline u32 counter_index_to_evtreg(unsigned int idx)
{
	return (idx == ARMV8_PMU_CYCLE_IDX) ? PMCCFILTR_EL0 : PMEVTYPER0_EL0 + idx;
}

static inline bool kvm_pmu_event_filtered(struct kvm *kvm, unsigned int event)
{
	return kvm->arch.pmu_filter && !test_bit(event, kvm->arch.pmu_filter);
}

u32 __kvm_pmu_event_mask(unsigned int pmuver);
u32 kvm_pmu_event_mask(struct kvm *kvm);

u64 __kvm_read_cpu_evtyper(unsigned int idx);
void __kvm_write_cpu_evtyper(unsigned int idx, u64 val);
u64 __kvm_read_cpu_evcntr(unsigned int idx);
void __kvm_write_cpu_evcntr(unsigned int idx, u64 val);

void direct_pmu_write_evtyper(struct kvm_vcpu *vcpu, u64 val, unsigned int idx);

void emulated_pmu_write_evtyper(struct kvm_vcpu *vcpu, u64 val, unsigned int idx);

#endif /* __ARM64_KVM_PMU_H__ */
