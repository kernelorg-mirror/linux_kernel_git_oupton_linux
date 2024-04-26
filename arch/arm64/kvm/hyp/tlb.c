// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Google LLC
 */

#include <hyp/tlb.h>

static void __s2_tlb_flush_nosync(struct kvm_s2_gather *tlb)
{
	gpa_t stride = __kvm_s2_tlb_stride(tlb);
	gpa_t range = tlb->end - tlb->start;
	gfn_t pages = range >> PAGE_SHIFT;
	int level = __kvm_s2_tlb_ttl(tlb);
	gpa_t addr;

	if (system_supports_tlb_range() && pages < MAX_TLBI_RANGE_PAGES) {
		__flush_s2_tlb_range_op(ipas2e1is, tlb->start, pages, stride, level);
	} else if (range / stride > MAX_DVM_OPS) {
		__tlbi(vmalls12e1is);
	} else {
		for (addr = tlb->start; addr < tlb->end; addr += stride)
			__tlbi_level(ipas2e1is, addr >> 12, level);
	}
}

#define ____kvm_tlb_sync(shareable)	\
	if (shareable)			\
		dsb(ish);		\
	else				\
		dsb(nsh)

#define ____kvm_s2_tlbi(s2_tlbi_op, mmu, shareable, ...)		\
do {									\
	struct tlb_inv_context __cxt;					\
									\
	/* Switch to the requested VMID */				\
	enter_vmid_context(mmu, &__cxt, !shareable);			\
									\
	s2_tlbi_op(__VA_ARGS__);					\
									\
	/*								\
	 * We have to ensure completion of the invalidation at Stage-2,	\
	 * since a table walk on another CPU could refill a TLB with a	\
	 * complete (S1 + S2) walk based on the old Stage-2 mapping if	\
	 * the Stage-1 invalidation happened first.			\
	 */								\
	____kvm_tlb_sync(shareable);					\
									\
	/*								\
	 * We could do so much better if we had the VA as well.		\
	 * instead, we invalidate the whole of stage-1. Weep...		\
	 */								\
	if (shareable)							\
		__tlbi(vmalle1is);					\
	else								\
		__tlbi(vmalle1);					\
	____kvm_tlb_sync(shareable);					\
	isb();								\
									\
	exit_vmid_context(&__cxt);					\
} while (0)

void __kvm_s2_tlb_flush(struct kvm_s2_gather *tlb)
{
	if (__kvm_s2_tlb_empty(tlb))
		return;

	____kvm_s2_tlbi(__s2_tlb_flush_nosync, tlb->mmu, true, tlb);

	*tlb = (struct kvm_s2_gather)KVM_S2_GATHER(tlb->mmu);
}

void __kvm_tlb_flush_vmid_ipa_nsh(struct kvm_s2_mmu *mmu,
				  phys_addr_t ipa, int level)
{
	____kvm_s2_tlbi(__tlbi_level, mmu, false, ipas2e1, ipa, level);
}

void __kvm_tlb_flush_vmid(struct kvm_s2_mmu *mmu)
{
	struct tlb_inv_context cxt;

	/* Switch to requested VMID */
	enter_vmid_context(mmu, &cxt, false);

	__tlbi(vmalls12e1is);
	dsb(ish);
	isb();

	exit_vmid_context(&cxt);
}

void __kvm_flush_cpu_context(struct kvm_s2_mmu *mmu)
{
	struct tlb_inv_context cxt;

	/* Switch to requested VMID */
	enter_vmid_context(mmu, &cxt, false);

	__tlbi(vmalle1);
	asm volatile("ic iallu");
	dsb(nsh);
	isb();

	exit_vmid_context(&cxt);
}

void __kvm_flush_vm_context(void)
{
	/* Same remark as in enter_vmid_context() */
	dsb(ish);
	__tlbi(alle1is);
	dsb(ish);
}
