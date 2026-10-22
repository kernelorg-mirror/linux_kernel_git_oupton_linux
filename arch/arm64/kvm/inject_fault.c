// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fault injection for both 32 and 64bit guests.
 *
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Based on arch/arm/kvm/emulate.c
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_nested.h>
#include <asm/esr.h>

static unsigned int exception_target_el(struct kvm_vcpu *vcpu)
{
	/* If not nesting, EL1 is the only possible exception target */
	if (likely(!vcpu_has_nv(vcpu)))
		return PSR_MODE_EL1h;

	/*
	 * With NV, we need to pick between EL1 and EL2. Note that we
	 * never deal with a nesting exception here, hence never
	 * changing context, and the exception itself can be delayed
	 * until the next entry.
	 */
	switch(*vcpu_cpsr(vcpu) & PSR_MODE_MASK) {
	case PSR_MODE_EL2h:
	case PSR_MODE_EL2t:
		return PSR_MODE_EL2h;
	case PSR_MODE_EL1h:
	case PSR_MODE_EL1t:
		return PSR_MODE_EL1h;
	case PSR_MODE_EL0t:
		return vcpu_el2_tge_is_set(vcpu) ? PSR_MODE_EL2h : PSR_MODE_EL1h;
	default:
		BUG();
	}
}

static enum vcpu_sysreg exception_esr_elx(struct kvm_vcpu *vcpu)
{
	if (exception_target_el(vcpu) == PSR_MODE_EL2h)
		return ESR_EL2;

	return ESR_EL1;
}

static enum vcpu_sysreg exception_far_elx(struct kvm_vcpu *vcpu)
{
	if (exception_target_el(vcpu) == PSR_MODE_EL2h)
		return FAR_EL2;

	return FAR_EL1;
}

static void pend_sync_exception(struct kvm_vcpu *vcpu)
{
	if (exception_target_el(vcpu) == PSR_MODE_EL1h)
		kvm_pend_exception(vcpu, EXCEPT_AA64_EL1_SYNC);
	else
		kvm_pend_exception(vcpu, EXCEPT_AA64_EL2_SYNC);
}

static void pend_serror_exception(struct kvm_vcpu *vcpu)
{
	if (exception_target_el(vcpu) == PSR_MODE_EL1h)
		kvm_pend_exception(vcpu, EXCEPT_AA64_EL1_SERR);
	else
		kvm_pend_exception(vcpu, EXCEPT_AA64_EL2_SERR);
}

static bool __effective_sctlr2_bit(struct kvm_vcpu *vcpu, unsigned int idx)
{
	u64 sctlr2;

	if (!kvm_has_sctlr2(vcpu->kvm))
		return false;

	if (is_nested_ctxt(vcpu) &&
	    !(__vcpu_sys_reg(vcpu, HCRX_EL2) & HCRX_EL2_SCTLR2En))
		return false;

	if (exception_target_el(vcpu) == PSR_MODE_EL1h)
		sctlr2 = vcpu_read_sys_reg(vcpu, SCTLR2_EL1);
	else
		sctlr2 = vcpu_read_sys_reg(vcpu, SCTLR2_EL2);

	return sctlr2 & BIT(idx);
}

static bool effective_sctlr2_ease(struct kvm_vcpu *vcpu)
{
	return __effective_sctlr2_bit(vcpu, SCTLR2_EL1_EASE_SHIFT);
}

static bool effective_sctlr2_nmea(struct kvm_vcpu *vcpu)
{
	return __effective_sctlr2_bit(vcpu, SCTLR2_EL1_NMEA_SHIFT);
}

static void __inject_abt64(struct kvm_vcpu *vcpu, bool iabt, u32 iss, unsigned long addr)
{
	u64 esr;
	u8 ec;

	if (vcpu_mode_priv(vcpu))
		ec = iabt ? ESR_ELx_EC_IABT_CUR : ESR_ELx_EC_DABT_CUR;
	else
		ec = iabt ? ESR_ELx_EC_IABT_LOW : ESR_ELx_EC_DABT_LOW;

	esr = FIELD_PREP(ESR_ELx_EC_MASK, ec) | FIELD_PREP(ESR_ELx_ISS_MASK, iss) |
	      ESR_ELx_IL;

	vcpu_write_sys_reg(vcpu, addr, exception_far_elx(vcpu));
	vcpu_write_sys_reg(vcpu, esr, exception_esr_elx(vcpu));
}

static void inject_abt64(struct kvm_vcpu *vcpu, bool iabt, u8 fsc, u64 addr)
{
	pend_sync_exception(vcpu);
	__inject_abt64(vcpu, iabt, fsc, addr);
}

static void inject_sea64(struct kvm_vcpu *vcpu, bool iabt, u64 addr)
{
	u8 fsc;

	/*
	 * If injecting an abort from a failed S1PTW, rewalk the S1 PTs to
	 * find the failing level. If we can't find it, assume the error was
	 * transient and restart without changing the state.
	 */
	if (kvm_vcpu_abt_iss1tw(vcpu)) {
		u64 hpfar = kvm_vcpu_get_fault_ipa(vcpu);
		int ret, level;

		if (hpfar == INVALID_GPA)
			return;

		ret = __kvm_find_s1_desc_level(vcpu, addr, hpfar, &level);
		if (ret)
			return;

		WARN_ON_ONCE(level < -1 || level > 3);
		fsc = ESR_ELx_FSC_SEA_TTW(level);
	} else {
		fsc = ESR_ELx_FSC_EXTABT;
	}

	/* This delight is brought to you by FEAT_DoubleFault2. */
	if (effective_sctlr2_ease(vcpu))
		pend_serror_exception(vcpu);
	else
		pend_sync_exception(vcpu);

	__inject_abt64(vcpu, iabt, fsc, addr);
}

void kvm_inject_sync(struct kvm_vcpu *vcpu, u64 esr)
{
	pend_sync_exception(vcpu);
	vcpu_write_sys_reg(vcpu, esr, exception_esr_elx(vcpu));
}

static void inject_undef64(struct kvm_vcpu *vcpu)
{
	u64 esr = (ESR_ELx_EC_UNKNOWN << ESR_ELx_EC_SHIFT) | ESR_ELx_IL;

	kvm_inject_sync(vcpu, esr);
}

#define DFSR_FS_4			BIT(10)
#define DFSR_FS_3_0			GENMASK(3, 0)
#define DFSR_FS_EXTABT_nLPAE		0x08
#define DFSR_FS_EXCL_ATOMIC_nLPAE	0x15
#define DFSR_FSC			GENMASK(5, 0)
#define DFSR_FSC_EXTABT_LPAE		0x10
#define DFSR_LPAE			BIT(9)
#define TTBCR_EAE			BIT(31)

static void inject_undef32(struct kvm_vcpu *vcpu)
{
	kvm_pend_exception(vcpu, EXCEPT_AA32_UND);
}

static bool vcpu_trans_32bit_non_lpae(struct kvm_vcpu *vcpu)
{
	return vcpu_el1_is_32bit(vcpu) && !(vcpu_read_sys_reg(vcpu, TCR_EL1) & TTBCR_EAE);
}

/*
 * Modelled after TakeDataAbortException() and TakePrefetchAbortException
 * pseudocode.
 */
static void inject_abt32(struct kvm_vcpu *vcpu, bool is_pabt, u8 status, u32 addr)
{
	u64 far;
	u32 fsr;

	if (vcpu_trans_32bit_non_lpae(vcpu)) {
		/* Ensure status actually fits in DFSR.FS */
		KVM_BUG_ON(status > 0x1F, vcpu->kvm);
		fsr = FIELD_PREP(DFSR_FS_4, FIELD_GET(BIT(4), status)) |
		      FIELD_PREP(DFSR_FS_3_0, FIELD_GET(GENMASK(3, 0), status));
	} else {
		fsr = FIELD_PREP(DFSR_FSC, status) | DFSR_LPAE;
	}

	far = vcpu_read_sys_reg(vcpu, FAR_EL1);

	if (is_pabt) {
		kvm_pend_exception(vcpu, EXCEPT_AA32_IABT);
		far &= GENMASK(31, 0);
		far |= (u64)addr << 32;
		vcpu_write_sys_reg(vcpu, fsr, IFSR32_EL2);
	} else { /* !iabt */
		kvm_pend_exception(vcpu, EXCEPT_AA32_DABT);
		far &= GENMASK(63, 32);
		far |= addr;
		vcpu_write_sys_reg(vcpu, fsr, ESR_EL1);
	}

	vcpu_write_sys_reg(vcpu, far, FAR_EL1);
}

static void inject_sea32(struct kvm_vcpu *vcpu, bool is_pabt, u32 addr)
{
	if (vcpu_trans_32bit_non_lpae(vcpu))
		inject_abt32(vcpu, is_pabt, DFSR_FS_EXTABT_nLPAE, addr);
	else
		inject_abt32(vcpu, is_pabt, DFSR_FSC_EXTABT_LPAE, addr);
}

static void __kvm_inject_sea(struct kvm_vcpu *vcpu, bool iabt, u64 addr)
{
	if (vcpu_el1_is_32bit(vcpu))
		inject_sea32(vcpu, iabt, addr);
	else
		inject_sea64(vcpu, iabt, addr);
}

static void __kvm_inject_abort(struct kvm_vcpu *vcpu, bool iabt, u8 fsc, u64 addr)
{
	if (vcpu_el1_is_32bit(vcpu))
		inject_abt32(vcpu, iabt, fsc, addr);
	else
		inject_abt64(vcpu, iabt, fsc, addr);
}

static bool kvm_sea_target_is_el2(struct kvm_vcpu *vcpu)
{
	if (__vcpu_sys_reg(vcpu, HCR_EL2) & (HCR_EL2_TGE | HCR_EL2_TEA))
		return true;

	if (!vcpu_mode_priv(vcpu))
		return false;

	return (*vcpu_cpsr(vcpu) & PSR_A_BIT) &&
	       (__vcpu_sys_reg(vcpu, HCRX_EL2) & HCRX_EL2_TMEA);
}

int kvm_inject_sea(struct kvm_vcpu *vcpu, bool iabt, u64 addr)
{
	lockdep_assert_held(&vcpu->mutex);

	if (is_nested_ctxt(vcpu) && kvm_sea_target_is_el2(vcpu))
		return kvm_inject_nested_sea(vcpu, iabt, ESR_ELx_FSC_EXTABT, addr);

	__kvm_inject_sea(vcpu, iabt, addr);
	return 1;
}

static int kvm_inject_nested_excl_atomic(struct kvm_vcpu *vcpu, u64 addr)
{
	u64 esr = FIELD_PREP(ESR_ELx_EC_MASK, ESR_ELx_EC_DABT_LOW) |
		  FIELD_PREP(ESR_ELx_FSC, ESR_ELx_FSC_EXCL_ATOMIC) |
		  ESR_ELx_IL;

	vcpu_write_sys_reg(vcpu, addr, FAR_EL2);
	return kvm_inject_nested_sync(vcpu, esr);
}

/**
 * kvm_inject_dabt_excl_atomic - inject a data abort for unsupported exclusive
 *				 or atomic access
 * @vcpu: The VCPU to receive the data abort
 * @addr: The address to report in the DFAR
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
int kvm_inject_dabt_excl_atomic(struct kvm_vcpu *vcpu, u64 addr)
{
	if (is_nested_ctxt(vcpu) && (vcpu_read_sys_reg(vcpu, HCR_EL2) & HCR_EL2_VM))
		return kvm_inject_nested_excl_atomic(vcpu, addr);

	if (vcpu_trans_32bit_non_lpae(vcpu))
		__kvm_inject_abort(vcpu, false, DFSR_FS_EXCL_ATOMIC_nLPAE, addr);
	else
		__kvm_inject_abort(vcpu, false, ESR_ELx_FSC_EXCL_ATOMIC, addr);

	return 1;
}

static bool esr_fsc_is_sea(u64 esr)
{
	return esr_fsc_is_sea_ttw(esr) || esr_fsc_is_secc_ttw(esr) ||
	       FIELD_GET(ESR_ELx_FSC, esr) == ESR_ELx_FSC_EXTABT;
}

void kvm_inject_s1_cmo_dabt(struct kvm_vcpu *vcpu, u8 fsc, u64 addr)
{
	u64 iss = FIELD_PREP(ESR_ELx_FSC, fsc) | ESR_ELx_CM | ESR_ELx_WNR;

	/*
	 * CMO traps are only ever taken from an NV guest, which is guaranteed
	 * to be AArch64.
	 */
	KVM_BUG_ON(vcpu_el1_is_32bit(vcpu), vcpu->kvm);

	if (is_nested_ctxt(vcpu) && esr_fsc_is_sea(fsc) && kvm_sea_target_is_el2(vcpu)) {
		if (esr_fsc_is_sea_ttw(fsc) || esr_fsc_is_secc_ttw(fsc))
			iss |= ESR_ELx_S1PTW;

		kvm_inject_nested_sea(vcpu, false, iss | ESR_ELx_S1PTW, addr);
		return;
	}

	inject_abt64(vcpu, false, iss, addr);
}

void kvm_inject_size_fault(struct kvm_vcpu *vcpu)
{
	bool iabt = kvm_vcpu_trap_is_iabt(vcpu);
	unsigned long addr;

	addr  = kvm_vcpu_get_fault_ipa(vcpu);
	addr |= FAR_TO_FIPA_OFFSET(kvm_vcpu_get_hfar(vcpu));

	/*
	 * If AArch64 or LPAE, set FSC to 0 to indicate an Address
	 * Size Fault at level 0, as if exceeding PARange.
	 *
	 * Non-LPAE guests will only get the external abort, as there
	 * is no way to describe the ASF.
	 */
	if (vcpu_trans_32bit_non_lpae(vcpu))
		__kvm_inject_sea(vcpu, iabt, addr);
	else
		__kvm_inject_abort(vcpu, iabt, ESR_ELx_FSC_ADDRSZ, addr);
}

/**
 * kvm_inject_undefined - inject an undefined instruction into the guest
 * @vcpu: The vCPU in which to inject the exception
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_undefined(struct kvm_vcpu *vcpu)
{
	if (vcpu_el1_is_32bit(vcpu))
		inject_undef32(vcpu);
	else
		inject_undef64(vcpu);
}

static bool serror_is_masked(struct kvm_vcpu *vcpu)
{
	return (*vcpu_cpsr(vcpu) & PSR_A_BIT) && !effective_sctlr2_nmea(vcpu);
}

static bool kvm_serror_target_is_el2(struct kvm_vcpu *vcpu)
{
	if (is_hyp_ctxt(vcpu) || vcpu_el2_amo_is_set(vcpu))
		return true;

	if (!(__vcpu_sys_reg(vcpu, HCRX_EL2) & HCRX_EL2_TMEA))
		return false;

	/*
	 * In another example where FEAT_DoubleFault2 is entirely backwards,
	 * "masked" as it relates to the routing effects of HCRX_EL2.TMEA
	 * doesn't consider SCTLR2_EL1.NMEA. That is to say, even if EL1 asked
	 * for non-maskable SErrors, the EL2 bit takes priority if A is set.
	 */
	if (vcpu_mode_priv(vcpu))
		return *vcpu_cpsr(vcpu) & PSR_A_BIT;

	/*
	 * Otherwise SErrors are considered unmasked when taken from EL0 and
	 * NMEA is set.
	 */
	return serror_is_masked(vcpu);
}

static bool kvm_serror_undeliverable_at_el2(struct kvm_vcpu *vcpu)
{
	return !(vcpu_el2_tge_is_set(vcpu) || vcpu_el2_amo_is_set(vcpu));
}

int kvm_inject_serror_esr(struct kvm_vcpu *vcpu, u64 esr)
{
	lockdep_assert_held(&vcpu->mutex);

	if (is_nested_ctxt(vcpu) && kvm_serror_target_is_el2(vcpu))
		return kvm_inject_nested_serror(vcpu, esr);

	if (vcpu_is_el2(vcpu) && kvm_serror_undeliverable_at_el2(vcpu)) {
		vcpu_set_vsesr(vcpu, esr);
		vcpu_set_flag(vcpu, NESTED_SERROR_PENDING);
		return 1;
	}

	/*
	 * With NV, emulate the exception entry if SErrors are unmasked: in a
	 * nested context with vSErrors enabled, the hardware vSError context
	 * (i.e. HCR_EL2.VSE, VSESR_EL2, VDISR_EL2) is delegated to the guest
	 * hypervisor. Otherwise, HCR_EL2.VSE delivers it once it is unmasked.
	 *
	 * As we're emulating the SError injection we need to explicitly populate
	 * ESR_ELx.EC because hardware will not do it on our behalf.
	 */
	if (vcpu_has_nv(vcpu) && !serror_is_masked(vcpu)) {
		pend_serror_exception(vcpu);
		esr |= FIELD_PREP(ESR_ELx_EC_MASK, ESR_ELx_EC_SERROR) | ESR_ELx_IL;
		vcpu_write_sys_reg(vcpu, esr, exception_esr_elx(vcpu));
		return 1;
	}

	vcpu_set_vsesr(vcpu, esr & ESR_ELx_ISS_MASK);
	*vcpu_hcr(vcpu) |= HCR_EL2_VSE;
	return 1;
}
