// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Google LLC
 */

#ifndef __ARM64_KVM_HYP_TLB_H__
#define __ARM64_KVM_HYP_TLB_H__

#include <asm/kvm_tlb.h>
#include <asm/tlbflush.h>

struct tlb_inv_context {
	struct kvm_s2_mmu	*mmu;
	unsigned long		flags;
	u64			tcr;
	u64			sctlr;
};

void enter_vmid_context(struct kvm_s2_mmu *mmu, struct tlb_inv_context *cxt,
			bool nsh);
void exit_vmid_context(struct tlb_inv_context *cxt);

#endif /* __ARM64_KVM_HYP_TLB_H__ */
