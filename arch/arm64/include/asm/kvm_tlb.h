// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Google LLC
 */

#ifndef __ARM64_KVM_TLB_H__
#define __ARM64_KVM_TLB_H__

#include <asm/kvm_pgtable.h>
#include <asm/kvm_types.h>
#include <linux/limits.h>

struct kvm_s2_gather {
	struct kvm_s2_mmu	*mmu;

	gpa_t			start;
	gpa_t			end;

	int			ttl;
	bool			ttl_valid;
};

#define KVM_S2_GATHER(__mmu) {		\
	.mmu	= __mmu,		\
	.start	= U64_MAX,		\
}

static inline bool __kvm_s2_tlb_empty(struct kvm_s2_gather *tlb)
{
	return tlb->start >= tlb->end;
}

static inline int __kvm_s2_tlb_ttl(struct kvm_s2_gather *tlb)
{
	if (WARN_ON_ONCE(!tlb->ttl_valid))
		return TLBI_TTL_UNKNOWN;

	return tlb->ttl;
}

static inline gpa_t __kvm_s2_tlb_stride(struct kvm_s2_gather *tlb)
{
	int ttl = __kvm_s2_tlb_ttl(tlb);

	if (ttl == TLBI_TTL_UNKNOWN)
		return kvm_granule_size(KVM_PGTABLE_LAST_LEVEL);

	return kvm_granule_size(ttl);
}

static inline void kvm_s2_tlb_flush(struct kvm_s2_gather *tlb)
{
	kvm_call_hyp(__kvm_s2_tlb_flush, tlb);
}

static inline bool __kvm_s2_can_defer_table_flush(void)
{
	return is_hyp_code();
}

static inline void kvm_s2_tlb_remove_pte(struct kvm_s2_gather *tlb,
					 const struct kvm_pgtable_visit_ctx *ctx)
{
	if (!tlb->ttl_valid) {
		tlb->ttl_valid = true;
		tlb->ttl = ctx->level;
	}

	if (kvm_pte_table(ctx->old, ctx->level) || tlb->ttl != ctx->level)
		tlb->ttl = TLBI_TTL_UNKNOWN;

	tlb->start = min(tlb->start, ctx->addr);
	tlb->end = max(tlb->end, ctx->addr + kvm_granule_size(ctx->level));

	if (!stage2_has_fwb(tlb->mmu->pgt) ||
	    (!__kvm_s2_can_defer_table_flush() && kvm_pte_table(ctx->old, ctx->level)))
		kvm_s2_tlb_flush(tlb);
}

static inline void __kvm_s2_tlb_flush_range(struct kvm_s2_mmu *mmu, gpa_t addr,
					    gpa_t size, int ttl)
{
	struct kvm_s2_gather tlb = {
		.mmu		= mmu,
		.start		= addr,
		.end		= addr + size,
		.ttl		= ttl,
		.ttl_valid	= true,
	};

	kvm_s2_tlb_flush(&tlb);
}

static inline void kvm_s2_tlb_flush_range(struct kvm_s2_mmu *mmu, gpa_t addr,
					  gpa_t size)
{
	__kvm_s2_tlb_flush_range(mmu, addr, size, TLBI_TTL_UNKNOWN);
}

#endif	/* __ARM64_KVM_TLB_H__ */
