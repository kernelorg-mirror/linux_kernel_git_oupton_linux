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
}

#endif	/* __ARM64_KVM_TLB_H__ */
