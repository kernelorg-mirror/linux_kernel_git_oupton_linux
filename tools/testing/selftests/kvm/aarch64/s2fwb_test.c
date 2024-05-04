#include <stdint.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

#define TEST_ITERATIONS		1000000

static void populate_data(void *alias, size_t len, unsigned long start_val)
{
	for (size_t i = 0; i < len / sizeof(unsigned long); i++) {
		long *p = ((long *)alias) + i;

		WRITE_ONCE(*p, start_val + i);
	}
}

static void check_data(void *alias, size_t len, unsigned long start_val)
{
	for (size_t i = 0; i < len / sizeof(unsigned long); i++) {
		long *p = ((long *)alias) + i;
		long val = READ_ONCE(*p);

		GUEST_ASSERT_EQ(start_val + i, val);
	}
}

extern char __test_fn_start, __test_fn_end;

static noinline void __test_fn(void)
{
	asm volatile("__test_fn_start:\n"
		     "mov x0, #0\n"
		     "ret\n"
		     "__test_fn_end:\n");
}

static void init_text(void *alias)
{
	memcpy(alias, &__test_fn_start, &__test_fn_end - &__test_fn_start);
	dsb(ish);

	asm volatile("dc civac, %0" : : "r" (alias)
		     : "memory");

	dsb(ish);
	isb();
}

#define MOV_X0(imm)	\
	(0b11010010100 << 21 | \
	((imm) & 255) << 5)

static void test_text(unsigned long i, void *normal_wb, void *normal_nc)
{
	uint64_t (*fn)(void) = normal_nc;
	uint32_t *insn = normal_wb;
	uint32_t imm = i % 256;

	WRITE_ONCE(*insn, MOV_X0(imm));
	asm volatile("dsb ish\n"
		     "ic ivau, %0\n"
		     "dsb ish\n"
		     "isb\n"
		     : : "r" (fn)
		     : "memory");

	TEST_ASSERT_EQ(imm, fn());
}

static void guest_code(void *normal_wb, void *normal_nc, size_t len)
{
	unsigned long i;

	for (i = 0; i < TEST_ITERATIONS; i++) {
		populate_data(normal_wb, len, i);
		dsb(ish);
		check_data(normal_nc, len, i);
	}

	init_text(normal_wb);

	for (i = 0; i < TEST_ITERATIONS; i++)
		test_text(i, normal_wb, normal_nc);

	GUEST_DONE();

	/* unreachable */
	__test_fn();
}

static void enter_guest(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unknown ucall %lu", uc.cmd);
	}
}

int main(void)
{
	vm_vaddr_t normal_wb, normal_nc;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	vm_paddr_t gpa;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	normal_wb = vm_vaddr_alloc_page(vm);

	normal_nc = 0xc0000000;
	gpa = addr_gva2gpa(vm, normal_wb);
	__virt_pg_map(vm, normal_nc, gpa, MT_NORMAL_NC);

	pr_info("Test Setup:\n"
		"  Normal-WB:\t[%lx, %lx)\n"
		"  Normal-NC:\t[%lx, %lx)\n"
		"  Iterations:\t%d\n",
		normal_wb, normal_wb + vm->page_size,
		normal_nc, normal_nc + vm->page_size,
		TEST_ITERATIONS);

	vcpu_args_set(vcpu, 3, normal_wb, normal_nc, vm->page_size);
	enter_guest(vcpu);
}
