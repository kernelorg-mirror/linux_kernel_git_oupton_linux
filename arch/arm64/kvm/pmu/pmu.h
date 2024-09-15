#ifndef __ARM64_KVM_PMU_H__
#define __ARM64_KVM_PMU_H__

#include <asm/kvm_host.h>

static inline u32 counter_index_to_reg(unsigned int idx)
{
	return (idx == ARMV8_PMU_CYCLE_IDX) ? PMCCNTR_EL0 : PMEVCNTR0_EL0 + idx;
}

static inline u32 counter_index_to_evtreg(unsigned int idx)
{
	return (idx == ARMV8_PMU_CYCLE_IDX) ? PMCCFILTR_EL0 : PMEVTYPER0_EL0 + idx;
}

u64 __kvm_read_cpu_evtyper(unsigned int idx);
void __kvm_write_cpu_evtyper(unsigned int idx, u64 val);

#endif /* __ARM64_KVM_PMU_H__ */
