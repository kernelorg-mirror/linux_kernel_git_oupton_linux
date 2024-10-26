// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#ifndef __ARM64_KVM_HYP_FAULT_H__
#define __ARM64_KVM_HYP_FAULT_H__

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

static inline bool __translate_far_to_hpfar(u64 far, u64 *hpfar)
{
	int ret;
	u64 par, tmp;

	/*
	 * Resolve the IPA the hard way using the guest VA.
	 *
	 * Stage-1 translation already validated the memory access
	 * rights. As such, we can use the EL1 translation regime, and
	 * don't have to distinguish between EL0 and EL1 access.
	 *
	 * We do need to save/restore PAR_EL1 though, as we haven't
	 * saved the guest context yet, and we may return early...
	 */
	par = read_sysreg_par();
	ret = system_supports_poe() ? __kvm_at(OP_AT_S1E1A, far) :
	                              __kvm_at(OP_AT_S1E1R, far);
	if (!ret)
		tmp = read_sysreg_par();
	else
		tmp = SYS_PAR_EL1_F; /* back to the guest */
	write_sysreg(par, par_el1);

	if (unlikely(tmp & SYS_PAR_EL1_F))
		return false; /* Translation failed, back to guest */

	/* Convert PAR to HPFAR format */
	*hpfar = PAR_TO_HPFAR(tmp);
	return true;
}

static inline bool __hpfar_valid(u64 esr)
{
	/*
	 * HPFAR_EL2 is written for Translation, Access Flag, and Permission
	 * faults at stage-2 that occur during a stage-1 table walk.
	 */
	if (esr & ESR_ELx_S1PTW)
		return esr_fsc_is_translation_fault(esr) ||
		       esr_fsc_is_access_flag_fault(esr) ||
		       esr_fsc_is_permission_fault(esr);

	/*
	* Processors affected by Arm erratum #834220 may have misreported a
	* stage-2 fault when the stage-1 translation should've faulted. Rewalk
	* the stage-1 to ensure the stage-1 mapping is valid.
	*/
	if (cpus_have_final_cap(ARM64_WORKAROUND_834220))
		return false;

	/*
	 * Otherwise, HPFAR_EL2 is written for Translation, Access Flag, and
	 * Address size faults at stage-2.
	 */
	return esr_fsc_is_translation_fault(esr) ||
	       esr_fsc_is_access_flag_fault(esr) ||
	       esr_fsc_is_address_size_fault(esr);
}

static inline bool __is_sea_s1ptw(u64 esr)
{
	return esr_fsc_is_sea(esr) && (esr & ESR_ELx_S1PTW);
}

static inline bool __get_fault_info(u64 esr, struct kvm_vcpu_fault_info *fault)
{
	fault->far_el2 = read_sysreg_el2(SYS_FAR);
	fault->hpfar_el2 = 0;

	/* Don't waste a useful walk result */
	if (__hpfar_valid(esr))
		fault->hpfar_el2 = read_sysreg(hpfar_el2);
	/*
	 * Try to resolve the IPA, but avoid rewalking the stage-1 if hardware
	 * encountered an SEA the first time around.
	 */
	else if (!__is_sea_s1ptw(esr) &&
		 !__translate_far_to_hpfar(fault->far_el2, &fault->hpfar_el2))
			return false;
	/*
	 * Hmm... Looks like the keg is empty this time.
	 *
	 * Continue with forwarding the fault back to the kernel context w/ an
	 * invalid HPFAR_EL2 value.
	 */
	else
		return true;

	/*
	 * Hijack the NS bit to indicate we got a valid HPFAR_EL2 value. The bit
	 * is RES0 in non-secure and we obviously took an abort from the
	 * non-secure IPA space.
	 */
	fault->hpfar_el2 |= HPFAR_EL2_NS;
	return true;
}

#endif
