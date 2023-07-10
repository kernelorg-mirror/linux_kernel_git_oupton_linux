// SPDX-License-Identifier: GPL-2.0-only
/*
 * set_id_regs - Test for setting ID register from usersapce.
 *
 * Copyright (c) 2023 Google LLC.
 *
 *
 * Test that KVM supports setting ID registers from userspace and handles the
 * feature set correctly.
 */

#include <stdint.h>
#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include <linux/bitfield.h>

#define field_get(_mask, _reg) (((_reg) & (_mask)) >> (ffs(_mask) - 1))
#define field_prep(_mask, _val) (((_val) << (ffs(_mask) - 1)) & (_mask))

struct reg_feature {
	uint64_t reg;
	uint64_t ftr_mask;
};

static void guest_code(void)
{
	for (;;)
		GUEST_SYNC(0);
}

static struct reg_feature lower_safe_reg_ftrs[] = {
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64DFR0_EL1), ARM64_FEATURE_MASK(ID_AA64DFR0_BRPS) },
	{ KVM_ARM64_SYS_REG(SYS_ID_DFR0_EL1), ARM64_FEATURE_MASK(ID_DFR0_COPDBG) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64PFR0_EL1), ARM64_FEATURE_MASK(ID_AA64PFR0_EL3) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64MMFR0_EL1), ARM64_FEATURE_MASK(ID_AA64MMFR0_TGRAN4) },
};

static void test_user_set_lower_safe(struct kvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lower_safe_reg_ftrs); i++) {
		struct reg_feature *reg_ftr = lower_safe_reg_ftrs + i;
		uint64_t val, new_val, ftr;

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ftr = field_get(reg_ftr->ftr_mask, val);

		/* Set a safe value for the feature */
		if (ftr > 0)
			ftr--;

		val &= ~reg_ftr->ftr_mask;
		val |= field_prep(reg_ftr->ftr_mask, ftr);

		vcpu_set_reg(vcpu, reg_ftr->reg, val);
		vcpu_get_reg(vcpu, reg_ftr->reg, &new_val);
		ASSERT_EQ(new_val, val);
	}
}

static struct reg_feature exact_reg_ftrs[] = {
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64DFR0_EL1), ARM64_FEATURE_MASK(ID_AA64DFR0_DEBUGVER) },
};

static void test_user_set_exact(struct kvm_vcpu *vcpu)
{
	int i, r;

	for (i = 0; i < ARRAY_SIZE(exact_reg_ftrs); i++) {
		struct reg_feature *reg_ftr = exact_reg_ftrs + i;
		uint64_t val, old_val, ftr;

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ftr = field_get(reg_ftr->ftr_mask, val);
		old_val = val;

		/* Exact match */
		vcpu_set_reg(vcpu, reg_ftr->reg, val);
		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ASSERT_EQ(val, old_val);

		/* Smaller value */
		if (ftr > 0)
			ftr--;
		val &= ~reg_ftr->ftr_mask;
		val |= field_prep(reg_ftr->ftr_mask, ftr);
		r = __vcpu_set_reg(vcpu, reg_ftr->reg, val);
		TEST_ASSERT(r < 0 && errno == EINVAL,
			    "Unexpected KVM_SET_ONE_REG error: r=%d, errno=%d", r, errno);
		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ASSERT_EQ(val, old_val);

		/* Bigger value */
		ftr += 2;
		val &= ~reg_ftr->ftr_mask;
		val |= field_prep(reg_ftr->ftr_mask, ftr);
		r = __vcpu_set_reg(vcpu, reg_ftr->reg, val);
		TEST_ASSERT(r < 0 && errno == EINVAL,
			    "Unexpected KVM_SET_ONE_REG error: r=%d, errno=%d", r, errno);
		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ASSERT_EQ(val, old_val);
	}
}

static struct reg_feature fail_reg_ftrs[] = {
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64DFR0_EL1), ARM64_FEATURE_MASK(ID_AA64DFR0_WRPS) },
	{ KVM_ARM64_SYS_REG(SYS_ID_DFR0_EL1), ARM64_FEATURE_MASK(ID_DFR0_MPROFDBG) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64PFR0_EL1), ARM64_FEATURE_MASK(ID_AA64PFR0_EL2) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64MMFR0_EL1), ARM64_FEATURE_MASK(ID_AA64MMFR0_TGRAN64) },
};

static void test_user_set_fail(struct kvm_vcpu *vcpu)
{
	int i, r;

	for (i = 0; i < ARRAY_SIZE(fail_reg_ftrs); i++) {
		struct reg_feature *reg_ftr = fail_reg_ftrs + i;
		uint64_t val, old_val, ftr;

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ftr = field_get(reg_ftr->ftr_mask, val);

		/* Set a invalid value (too big) for the feature */
		ftr++;

		old_val = val;
		val &= ~reg_ftr->ftr_mask;
		val |= field_prep(reg_ftr->ftr_mask, ftr);

		r = __vcpu_set_reg(vcpu, reg_ftr->reg, val);
		TEST_ASSERT(r < 0 && errno == EINVAL,
			    "Unexpected KVM_SET_ONE_REG error: r=%d, errno=%d", r, errno);

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ASSERT_EQ(val, old_val);
	}
}

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	ksft_print_header();
	ksft_set_plan(3);

	test_user_set_lower_safe(vcpu);
	ksft_test_result_pass("test_user_set_lower_safe\n");

	test_user_set_exact(vcpu);
	ksft_test_result_pass("test_user_set_exact\n");

	test_user_set_fail(vcpu);
	ksft_test_result_pass("test_user_set_fail\n");

	kvm_vm_free(vm);

	ksft_finished();
}
