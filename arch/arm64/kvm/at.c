// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 - Linaro Ltd
 * Author: Jintack Lim <jintack.lim@linaro.org>
 */

#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

struct mmu_config {
	u64	ttbr0;
	u64	ttbr1;
	u64	tcr;
	u64	sctlr;
	u64	vttbr;
	u64	vtcr;
	u64	hcr;
};

static void __mmu_config_save(struct mmu_config *config)
{
	config->ttbr0	= read_sysreg_el1(SYS_TTBR0);
	config->ttbr1	= read_sysreg_el1(SYS_TTBR1);
	config->tcr	= read_sysreg_el1(SYS_TCR);
	config->sctlr	= read_sysreg_el1(SYS_SCTLR);
	config->vttbr	= read_sysreg(vttbr_el2);
	config->vtcr	= read_sysreg(vtcr_el2);
	config->hcr	= read_sysreg(hcr_el2);
}

static void __mmu_config_restore(struct mmu_config *config)
{
	write_sysreg_el1(config->ttbr0,	SYS_TTBR0);
	write_sysreg_el1(config->ttbr1,	SYS_TTBR1);
	write_sysreg_el1(config->tcr,	SYS_TCR);
	write_sysreg_el1(config->sctlr,	SYS_SCTLR);
	write_sysreg(config->vttbr,	vttbr_el2);
	write_sysreg(config->vtcr,	vtcr_el2);
	/*
	 * ARM errata 1165522 and 1530923 require the actual execution of the
	 * above before we can switch to the EL1/EL0 translation regime used by
	 * the guest.
	 */
	asm(ALTERNATIVE("nop", "isb", ARM64_WORKAROUND_SPECULATIVE_AT));

	write_sysreg(config->hcr,	hcr_el2);

	isb();
}

void __kvm_at_s1e01(struct kvm_vcpu *vcpu, u32 op, u64 vaddr)
{
	struct mmu_config config;
	struct kvm_s2_mmu *mmu;
	unsigned long flags;
	bool fail;
	u64 par;

	write_lock(&vcpu->kvm->mmu_lock);

	/*
	 * We've trapped, so everything is live on the CPU. As we will
	 * be switching contexts behind everybody's back, disable
	 * interrupts...
	 */
	local_irq_save(flags);
	__mmu_config_save(&config);

	/*
	 * If HCR_EL2.{E2H,TGE} == {1,1}, the MMU context is already
	 * the right one (as we trapped from vEL2). We have done too
	 * much work by saving the full MMU context, but who cares?
	 */
	if (vcpu_el2_e2h_is_set(vcpu) && vcpu_el2_tge_is_set(vcpu))
		goto skip_mmu_switch;

	/*
	 * FIXME: Obtaining the S2 MMU for a L2 is horribly racy, and
	 * we may not find it (recycled by another vcpu, for example).
	 * See the other FIXME comment below about the need for a SW
	 * PTW in this case.
	 */
	mmu = lookup_s2_mmu(vcpu);
	if (WARN_ON(!mmu))
		goto out;

	write_sysreg_el1(vcpu_read_sys_reg(vcpu, TTBR0_EL1),	SYS_TTBR0);
	write_sysreg_el1(vcpu_read_sys_reg(vcpu, TTBR1_EL1),	SYS_TTBR1);
	write_sysreg_el1(vcpu_read_sys_reg(vcpu, TCR_EL1),	SYS_TCR);
	write_sysreg_el1(vcpu_read_sys_reg(vcpu, SCTLR_EL1),	SYS_SCTLR);
	__load_stage2(mmu, mmu->arch);

skip_mmu_switch:
	/* Clear TGE, enable S2 translation, we're rolling */
	write_sysreg((config.hcr & ~HCR_TGE) | HCR_VM,	hcr_el2);
	isb();

	switch (op) {
	case OP_AT_S1E1R:
	case OP_AT_S1E1RP:
		fail = __kvm_at("s1e1r", vaddr);
		break;
	case OP_AT_S1E1W:
	case OP_AT_S1E1WP:
		fail = __kvm_at("s1e1w", vaddr);
		break;
	case OP_AT_S1E0R:
		fail = __kvm_at("s1e0r", vaddr);
		break;
	case OP_AT_S1E0W:
		fail = __kvm_at("s1e0w", vaddr);
		break;
	default:
		WARN_ON_ONCE(1);
		fail = true;
		break;
	}

	if (!fail)
		par = read_sysreg(par_el1);
	else
		par = SYS_PAR_EL1_F;

	vcpu_write_sys_reg(vcpu, par, PAR_EL1);

	/*
	 * Failed? let's leave the building now.
	 *
	 * FIXME: how about a failed translation because the shadow S2
	 * wasn't populated? We may need to perform a SW PTW,
	 * populating our shadow S2 and retry the instruction.
	 */
	if (par & SYS_PAR_EL1_F)
		goto nopan;

	/* No PAN? No problem. */
	if (!(*vcpu_cpsr(vcpu) & PSR_PAN_BIT))
		goto nopan;

	/*
	 * For PAN-involved AT operations, perform the same
	 * translation, using EL0 this time.
	 */
	switch (op) {
	case OP_AT_S1E1RP:
		fail = __kvm_at("s1e0r", vaddr);
		break;
	case OP_AT_S1E1WP:
		fail = __kvm_at("s1e0w", vaddr);
		break;
	default:
		goto nopan;
	}

	/*
	 * If the EL0 translation has succeeded, we need to pretend
	 * the AT operation has failed, as the PAN setting forbids
	 * such a translation.
	 *
	 * FIXME: we hardcode a Level-3 permission fault. We really
	 * should return the real fault level.
	 */
	if (fail || !(read_sysreg(par_el1) & SYS_PAR_EL1_F))
		vcpu_write_sys_reg(vcpu, (0xf << 1) | SYS_PAR_EL1_F, PAR_EL1);

nopan:
	__mmu_config_restore(&config);
out:
	local_irq_restore(flags);

	write_unlock(&vcpu->kvm->mmu_lock);
}

void __kvm_at_s1e2(struct kvm_vcpu *vcpu, u32 op, u64 vaddr)
{
	struct kvm_s2_mmu *mmu;
	unsigned long flags;
	u64 val, hcr;

	write_lock(&vcpu->kvm->mmu_lock);

	mmu = &vcpu->kvm->arch.mmu;

	/*
	 * We've trapped, so everything is live on the CPU. As we will
	 * be switching context behind everybody's back, disable
	 * interrupts...
	 */
	local_irq_save(flags);

	val = hcr = read_sysreg(hcr_el2);
	val &= ~HCR_TGE;
	val |= HCR_VM;

	if (!vcpu_el2_e2h_is_set(vcpu))
		val |= HCR_NV | HCR_NV1;

	write_sysreg(val, hcr_el2);
	isb();

	switch (op) {
	case OP_AT_S1E2R:
		asm volatile("at s1e1r, %0" : : "r" (vaddr));
		break;
	case OP_AT_S1E2W:
		asm volatile("at s1e1w, %0" : : "r" (vaddr));
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	isb();

	/* FIXME: handle failed translation due to lack of S2 mapping */
	vcpu_write_sys_reg(vcpu, read_sysreg(par_el1), PAR_EL1);

	write_sysreg(hcr, hcr_el2);
	isb();

	local_irq_restore(flags);

	write_unlock(&vcpu->kvm->mmu_lock);
}
