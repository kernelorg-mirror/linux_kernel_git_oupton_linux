// SPDX-License-Identifier: GPL-2.0-only
/*
 * argh_workarounds - Test that guest's view of CPU workarounds aligns w/ that of
 * the host.
 *
 * Copyright (c) 2024 Google LLC.
 */
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/arm-smccc.h>
#include <linux/kernel.h>
#include <asm/sysreg.h>
#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"

#define CPU_VULNERABILITY_FILE(name)	("/sys/devices/system/cpu/vulnerabilities/" #name)

#define SPECTRE_V2_FILE CPU_VULNERABILITY_FILE(spectre_v2)
#define SPECTRE_V4_FILE CPU_VULNERABILITY_FILE(spec_store_bypass)

enum mitigation_state {
	UNAFFECTED,
	MITIGATED,
	VULNERABLE,
};

static const char *mitigation_to_str(enum mitigation_state state)
{
	switch (state) {
	case UNAFFECTED:
		return "Unaffected";
	case MITIGATED:
		return "Mitigated";
	case VULNERABLE:
		return "Vulnerable";
	default:
		return "Unknown";
	}
}

static char *__read_file(const char *fname)
{
	struct stat st;
	char *buf;
	int fd;

	fd = open(fname, O_RDONLY);
	TEST_ASSERT(fd >= 0, "Failed to open %s, errno=%d", fname, errno);
	TEST_ASSERT(!fstat(fd, &st),
		    "Failed to fstat() on %s, errno=%d", fname, errno);

	buf = malloc(st.st_size);
	TEST_ASSERT(buf, "Failed to allocate buffer");
	TEST_ASSERT(read(fd, buf, st.st_size) > 0,
		    "Failed to read() on %s, errno=%d", fname, errno);
	TEST_ASSERT(!close(fd),
		    "Failed to close() on %s, errno=%d", fname, errno);

	return buf;
}

static u64 __check_fw_mitigation(u32 func_id)
{
	struct arm_smccc_res res;

	smccc_hvc(ARM_SMCCC_ARCH_FEATURES_FUNC_ID, func_id, 0, 0, 0, 0, 0, 0, &res);
	return res.a0;
}

static enum mitigation_state host_spectre_v2_state(void)
{
	char *str = __read_file(SPECTRE_V2_FILE);
	enum mitigation_state r = VULNERABLE;

	if (strstr(str, "Not affected"))
		r = UNAFFECTED;
	else if (strstr(str, "CSV2"))
		r = UNAFFECTED;
	else if (strstr(str, "Branch predictor hardening"))
		r = MITIGATED;

	free(str);
	return r;
}

static enum mitigation_state guest_spectre_v2_state(void)
{
	u64 pfr0 = read_sysreg(ID_AA64PFR0_EL1);

	if (SYS_FIELD_GET(ID_AA64PFR0_EL1, CSV2, pfr0))
		return UNAFFECTED;

	switch (__check_fw_mitigation(ARM_SMCCC_ARCH_WORKAROUND_1)) {
	case SMCCC_RET_SUCCESS:
		return MITIGATED;
	case SMCCC_ARCH_WORKAROUND_RET_UNAFFECTED:
		return UNAFFECTED;
	default:
		return VULNERABLE;
	}
}

static enum mitigation_state spectre_v2_register_state(struct kvm_vcpu *vcpu)
{
	u64 reg;

	vcpu_get_reg(vcpu, KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1, &reg);
	switch (reg) {
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1_AVAIL:
		return MITIGATED;
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1_NOT_REQUIRED:
		return UNAFFECTED;
	default:
		TEST_ASSERT(0, "Unknown value: %ld", reg);
		fallthrough;
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1_NOT_AVAIL:
		return VULNERABLE;
	}
}

static enum mitigation_state host_spectre_v4_state(void)
{
	char *str = __read_file(SPECTRE_V4_FILE);
	enum mitigation_state r = VULNERABLE;

	if (strstr(str, "Not affected"))
		r = UNAFFECTED;
	else if (strstr(str, "Mitigation"))
		r = MITIGATED;

	free(str);
	return r;
}

static enum mitigation_state guest_spectre_v4_state(void)
{
	u64 pfr1 = read_sysreg(ID_AA64PFR1_EL1);

	switch (__check_fw_mitigation(ARM_SMCCC_ARCH_WORKAROUND_2)) {
	case SMCCC_RET_SUCCESS:
		return MITIGATED;
	case SMCCC_ARCH_WORKAROUND_RET_UNAFFECTED:
	case SMCCC_RET_NOT_REQUIRED:
		return UNAFFECTED;
	default:
		break;
	}

	if (SYS_FIELD_GET(ID_AA64PFR1_EL1, SSBS, pfr1))
		return MITIGATED;

	return VULNERABLE;
}

static enum mitigation_state spectre_v4_register_state(struct kvm_vcpu *vcpu)
{
	u64 reg;

	vcpu_get_reg(vcpu, KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2, &reg);
	switch (reg) {
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_NOT_REQUIRED:
		return UNAFFECTED;
	default:
		TEST_ASSERT(0, "Unknown value %ld", reg);
		fallthrough;
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_NOT_AVAIL:
		vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_ID_AA64PFR1_EL1), &reg);
		return SYS_FIELD_GET(ID_AA64PFR1_EL1, SSBS, reg) ? MITIGATED : VULNERABLE;
	}
}

static enum mitigation_state host_spectre_bhb_state(void)
{
	char *str = __read_file(SPECTRE_V2_FILE);
	enum mitigation_state r = UNAFFECTED;

	if (strstr(str, "Vulnerable"))
		r = VULNERABLE;
	else if (strstr(str, "but not BHB"))
		r = UNAFFECTED;
	else if (strstr(str, "BHB"))
		r = MITIGATED;

	free(str);
	return r;
}

static enum mitigation_state guest_spectre_bhb_state(void)
{
	u64 mmfr1 = read_sysreg(ID_AA64MMFR1_EL1);
	u64 pfr0 = read_sysreg(ID_AA64PFR0_EL1);

	/*
	 * FEAT_CSV2p3 is the strongest hardware implementation.
	 */
	if (SYS_FIELD_GET(ID_AA64PFR0_EL1, CSV2, pfr0) >= 3)
		return UNAFFECTED;

	/*
	 * FEAT_ECBHB is a tad weaker, only requiring branch history protection
	 * between exception levels. Good enough for us though.
	 */
	if (SYS_FIELD_GET(ID_AA64MMFR1_EL1, ECBHB, mmfr1))
		return UNAFFECTED;

	switch (__check_fw_mitigation(ARM_SMCCC_ARCH_WORKAROUND_3)) {
	case SMCCC_RET_SUCCESS:
		return MITIGATED;
	case SMCCC_ARCH_WORKAROUND_RET_UNAFFECTED:
		return UNAFFECTED;
	default:
		return VULNERABLE;
	}
}

static enum mitigation_state spectre_bhb_register_state(struct kvm_vcpu *vcpu)
{
	u64 reg;

	vcpu_get_reg(vcpu, KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3, &reg);
	switch (reg) {
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3_AVAIL:
		return MITIGATED;
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3_NOT_REQUIRED:
		return UNAFFECTED;
	default:
		TEST_ASSERT(0, "Unknown value %ld", reg);
		fallthrough;
	case KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3_NOT_AVAIL:
		return VULNERABLE;
	}
}

struct test_case {
	const char 		*name;
	enum mitigation_state 	(*host_state)(void);
	enum mitigation_state	(*guest_state)(void);
	enum mitigation_state	(*reg_state)(struct kvm_vcpu *vcpu);
};

struct test_case test_cases[] = {
	{
		.name 		= "Spectre-v2",
		.host_state 	= host_spectre_v2_state,
		.guest_state	= guest_spectre_v2_state,
		.reg_state	= spectre_v2_register_state,
	},
	{
		.name		= "Spectre-v4",
		.host_state	= host_spectre_v4_state,
		.guest_state	= guest_spectre_v4_state,
		.reg_state	= spectre_v4_register_state,
	},
	{
		.name		= "Spectre-BHB",
		.host_state	= host_spectre_bhb_state,
		.guest_state	= guest_spectre_bhb_state,
		.reg_state	= spectre_bhb_register_state,
	},
};

#define REPORT_MITIGATION_STATE(i) GUEST_SYNC_ARGS(i, test_cases[(i)].guest_state(), 0, 0, 0)

static void guest_code(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++)
		REPORT_MITIGATION_STATE(i);

	GUEST_DONE();
}

static void assert_mitigation_state_eq(struct kvm_vcpu *vcpu, struct ucall *uc)
{
	struct test_case *test = &test_cases[uc->args[1]];
	enum mitigation_state reg_state = test->reg_state(vcpu);
	enum mitigation_state host_state = test->host_state();
	enum mitigation_state guest_state = uc->args[2];

	TEST_ASSERT(guest_state == host_state,
		    "%s: Mismatched mitigation state, guest: %s, host: %s",
		    test->name, mitigation_to_str(guest_state),
		    mitigation_to_str(host_state));

	TEST_ASSERT(guest_state == reg_state,
		    "%s: Mismatched mitigation state, guest: %s, fw reg: %s",
		    test->name, mitigation_to_str(guest_state),
		    mitigation_to_str(reg_state));

	ksft_test_result_pass("%s\n", test->name);
}

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	bool done = false;
	struct ucall uc;

	ksft_print_header();
	ksft_set_plan(ARRAY_SIZE(test_cases));

	while (!done) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			assert_mitigation_state_eq(vcpu, &uc);
			break;
		case UCALL_DONE:
			done = true;
			break;
		default:
			TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
		}
	}

	ksft_finished();
	kvm_vm_free(vm);
	return 0;
}
