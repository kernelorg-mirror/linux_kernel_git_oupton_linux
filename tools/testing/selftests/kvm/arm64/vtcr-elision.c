// SPDX-License-Identifier: GPL-2.0-only
/*
 * Run a VM on a pCPU, hotplug the pCPU, then run another VM on it.
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

static int pcpu = 1;

static void guest_code(void)
{
	GUEST_DONE();
}

static void *vcpu_thread(void *arg)
{
	enum vm_guest_mode mode = (enum vm_guest_mode)(unsigned long)arg;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;

	pin_self_to_cpu(pcpu);

	vm = __vm_create_shape_with_one_vcpu(VM_SHAPE(mode), &vcpu, 0, guest_code);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);
	kvm_vm_free(vm);
	return NULL;
}

static void run_vm(enum vm_guest_mode mode)
{
	pthread_t thread;

	pthread_create(&thread, NULL, vcpu_thread, (void *)(unsigned long)mode);
	pthread_join(thread, NULL);
}

static void set_online(const char *val)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", pcpu);
	fd = open(path, O_WRONLY);
	TEST_ASSERT(fd >= 0, "open(%s) failed", path);
	TEST_ASSERT(write(fd, val, 1) == 1, "write(%s) failed", path);
	close(fd);
}

int main(int argc, char *argv[])
{
	bool reset = false;
	int opt;

	while ((opt = getopt(argc, argv, "c:r")) != -1) {
		switch (opt) {
		case 'c':
			pcpu = atoi(optarg);
			break;
		case 'r':
			reset = true;
			break;
		default:
			pr_info("usage: %s [-c pcpu] [-r]\n", argv[0]);
			exit(KSFT_SKIP);
		}
	}

	if (reset) {
		pr_info("Running reset vCPU on pCPU %d\n", pcpu);
		run_vm(VM_MODE_P40V48_4K);
		pr_info("Done\n");
		return 0;
	}

	pr_info("Running primer vCPU on pCPU %d\n", pcpu);
	run_vm(VM_MODE_P48V48_4K);

	pr_info("Offlining pCPU %d\n", pcpu);
	set_online("0");
	pr_info("Onlining pCPU %d\n", pcpu);
	set_online("1");
	sleep(5);

	pr_info("Running victim vCPU on pCPU %d\n", pcpu);
	run_vm(VM_MODE_P48V48_4K);
	pr_info("Done\n");
	return 0;
}
