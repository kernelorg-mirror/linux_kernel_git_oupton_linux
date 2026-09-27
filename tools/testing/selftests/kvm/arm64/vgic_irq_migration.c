// SPDX-License-Identifier: GPL-2.0
/*
 * vgic_irq_migration.c - Test migration of pending SPIs and LPIs between vCPUs
 *
 * Validates that an IRQ (SPI or LPI) that is pending on vCPU0 preserves its
 * pending state when migrated to vCPU1 (via writing GICD_IROUTER for an SPI,
 * or submitting an ITS MOVI command for an LPI), and can then be acknowledged
 * and taken on vCPU1.
 */

#include <linux/sizes.h>
#include <pthread.h>
#include <stdatomic.h>

#include "kvm_util.h"
#include "gic.h"
#include "gic_v3.h"
#include "gic_v3_its.h"
#include "processor.h"
#include "test_util.h"
#include "vgic.h"

#define SPI_INTID		32
#define GIC_LPI_OFFSET		8192
#define LPI_INTID		8192
#define TEST_MEMSLOT_INDEX	1

#define LPI_PROP_DEFAULT_PRIO	0xa0
#define UCALL_CMD_SIGNAL_MSI	0x1000

static struct spi_shared_data {
	atomic_int ready_cpus;
	atomic_int stage;
	atomic_int irq_count[2];
	atomic_int last_irq[2];
	u64 mpidr[2];
	size_t nr_iterations;
} spi_shared;

static void guest_irq_handler_spi(struct ex_regs *regs)
{
	u32 cpu = guest_get_vcpuid();
	u32 intid = gic_get_and_ack_irq();

	if (intid == IAR_SPURIOUS)
		return;

	atomic_fetch_add(&spi_shared.irq_count[cpu], 1);
	atomic_store(&spi_shared.last_irq[cpu], intid);

	gic_set_eoi(intid);
}

static void guest_code_spi(void)
{
	u32 cpu = guest_get_vcpuid();

	gic_init(GIC_V3, 2);
	spi_shared.mpidr[cpu] = read_sysreg_s(SYS_MPIDR_EL1) & GENMASK(23, 0);

	atomic_fetch_add(&spi_shared.ready_cpus, 1);
	while (atomic_load(&spi_shared.ready_cpus) < 2)
		cpu_relax();

	if (cpu == 0) {
		gic_irq_set_config(SPI_INTID, true);
		gic_set_priority(SPI_INTID, 0xa0);
		gic_set_irouter(SPI_INTID, spi_shared.mpidr[0]);
		gic_irq_enable(SPI_INTID);

		/*
		 * Test 1: vCPU 0 self-migration of pending SPI.
		 * vCPU 0 has IRQs disabled, gets SPI pending, then writes
		 * GICD_IROUTER to migrate it to vCPU 1.
		 */
		local_irq_disable();
		atomic_store(&spi_shared.irq_count[0], 0);
		atomic_store(&spi_shared.irq_count[1], 0);
		atomic_store(&spi_shared.last_irq[0], 0);
		atomic_store(&spi_shared.last_irq[1], 0);

		atomic_store(&spi_shared.stage, 1);
		while (atomic_load(&spi_shared.stage) != 2)
			cpu_relax();

		gic_irq_set_pending(SPI_INTID);
		GUEST_ASSERT(gic_irq_get_pending(SPI_INTID));

		/* Migrate to vCPU 1 */
		gic_set_irouter(SPI_INTID, spi_shared.mpidr[1]);

		/* Wait for vCPU 1 to acknowledge taking the interrupt */
		while (atomic_load(&spi_shared.stage) != 3)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[0]), 0);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[1]), 1);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.last_irq[1]), SPI_INTID);

		/* Briefly enable IRQs on vCPU 0 to ensure it wasn't delivered here */
		local_irq_enable();
		for (int i = 0; i < 1000; i++)
			cpu_relax();
		local_irq_disable();
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[0]), 0);

		/*
		 * Test 2: Cross-vCPU migration: vCPU 0 spins in guest mode with
		 * the pending SPI in its LR, and vCPU 1 writes GICD_IROUTER.
		 */
		gic_set_irouter(SPI_INTID, spi_shared.mpidr[0]);
		atomic_store(&spi_shared.irq_count[0], 0);
		atomic_store(&spi_shared.irq_count[1], 0);
		atomic_store(&spi_shared.last_irq[0], 0);
		atomic_store(&spi_shared.last_irq[1], 0);

		/* Make pending: this flushes it into vCPU 0's LR */
		gic_irq_set_pending(SPI_INTID);

		/* Tell vCPU 1 that SPI is pending, then spin in guest mode */
		atomic_store(&spi_shared.stage, 4);
		while (atomic_load(&spi_shared.stage) != 5)
			cpu_relax();

		local_irq_enable();
		for (int i = 0; i < 1000; i++)
			cpu_relax();
		local_irq_disable();
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[0]), 0);

		/*
		 * Test 3: Reverse cross-vCPU migration: vCPU 1 in guest mode with
		 * pending SPI in LR, vCPU 0 writes GICD_IROUTER.
		 */
		atomic_store(&spi_shared.stage, 6);
		local_irq_enable();

		while (atomic_load(&spi_shared.stage) != 7)
			cpu_relax();

		/* Migrate to vCPU 0 */
		gic_set_irouter(SPI_INTID, spi_shared.mpidr[0]);

		while (atomic_load(&spi_shared.irq_count[0]) < 1)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[0]), 1);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.last_irq[0]), SPI_INTID);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[1]), 0);

		atomic_store(&spi_shared.stage, 8);
		local_irq_disable();

		/*
		 * Test 4: Repeated ping-pong migrations.
		 */
		for (size_t iter = 0; iter < spi_shared.nr_iterations; iter++) {
			atomic_store(&spi_shared.irq_count[0], 0);
			atomic_store(&spi_shared.irq_count[1], 0);

			/* Phase A: pending on vCPU 0, migrated to vCPU 1 */
			gic_set_irouter(SPI_INTID, spi_shared.mpidr[0]);
			gic_irq_set_pending(SPI_INTID);

			atomic_store(&spi_shared.stage, 10);
			while (atomic_load(&spi_shared.stage) != 11)
				cpu_relax();

			/* Phase B: pending on vCPU 1, migrated to vCPU 0 */
			local_irq_enable();
			atomic_store(&spi_shared.stage, 12);
			while (atomic_load(&spi_shared.stage) != 13)
				cpu_relax();

			gic_set_irouter(SPI_INTID, spi_shared.mpidr[0]);
			while (atomic_load(&spi_shared.irq_count[0]) < 1)
				cpu_relax();

			GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[0]), 1);
			local_irq_disable();

			atomic_store(&spi_shared.stage, 14);
			while (atomic_load(&spi_shared.stage) != 15)
				cpu_relax();
		}

		atomic_store(&spi_shared.stage, 99);
		GUEST_DONE();
	} else {
		/* vCPU 1 */
		local_irq_enable();

		/* Test 1 */
		while (atomic_load(&spi_shared.stage) != 1)
			cpu_relax();
		atomic_store(&spi_shared.stage, 2);

		while (atomic_load(&spi_shared.irq_count[1]) < 1)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[1]), 1);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.last_irq[1]), SPI_INTID);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[0]), 0);

		atomic_store(&spi_shared.stage, 3);

		/* Test 2 */
		while (atomic_load(&spi_shared.stage) != 4)
			cpu_relax();

		/* Migrate to vCPU 1 */
		gic_set_irouter(SPI_INTID, spi_shared.mpidr[1]);

		while (atomic_load(&spi_shared.irq_count[1]) < 1)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[1]), 1);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.last_irq[1]), SPI_INTID);
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[0]), 0);

		atomic_store(&spi_shared.stage, 5);

		/* Test 3: Reverse */
		while (atomic_load(&spi_shared.stage) != 6)
			cpu_relax();

		local_irq_disable();
		atomic_store(&spi_shared.irq_count[0], 0);
		atomic_store(&spi_shared.irq_count[1], 0);

		gic_set_irouter(SPI_INTID, spi_shared.mpidr[1]);
		gic_irq_set_pending(SPI_INTID);

		atomic_store(&spi_shared.stage, 7);
		while (atomic_load(&spi_shared.stage) != 8)
			cpu_relax();

		local_irq_enable();
		for (int i = 0; i < 1000; i++)
			cpu_relax();
		GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[1]), 0);

		/* Test 4: Loop */
		for (size_t iter = 0; iter < spi_shared.nr_iterations; iter++) {
			while (atomic_load(&spi_shared.stage) != 10)
				cpu_relax();

			gic_set_irouter(SPI_INTID, spi_shared.mpidr[1]);
			while (atomic_load(&spi_shared.irq_count[1]) < 1)
				cpu_relax();

			GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[1]), 1);
			atomic_store(&spi_shared.stage, 11);

			while (atomic_load(&spi_shared.stage) != 12)
				cpu_relax();

			local_irq_disable();
			atomic_store(&spi_shared.irq_count[0], 0);
			atomic_store(&spi_shared.irq_count[1], 0);

			gic_set_irouter(SPI_INTID, spi_shared.mpidr[1]);
			gic_irq_set_pending(SPI_INTID);

			atomic_store(&spi_shared.stage, 13);
			while (atomic_load(&spi_shared.stage) != 14)
				cpu_relax();

			local_irq_enable();
			for (int i = 0; i < 1000; i++)
				cpu_relax();
			GUEST_ASSERT_EQ(atomic_load(&spi_shared.irq_count[1]), 0);

			atomic_store(&spi_shared.stage, 15);
		}

		while (atomic_load(&spi_shared.stage) != 99)
			cpu_relax();
		GUEST_DONE();
	}
}

static struct lpi_shared_data {
	atomic_int ready_cpus;
	atomic_int stage;
	atomic_int irq_count[2];
	atomic_int last_irq[2];
	size_t nr_iterations;

	gpa_t device_table;
	gpa_t collection_table;
	gpa_t cmdq_base;
	void *cmdq_base_va;
	gpa_t itt_tables;
	gpa_t lpi_prop_table;
	gpa_t lpi_pend_tables;
} lpi_shared;

static void guest_irq_handler_lpi(struct ex_regs *regs)
{
	u32 cpu = guest_get_vcpuid();
	u32 intid = gic_get_and_ack_irq();

	if (intid == IAR_SPURIOUS)
		return;

	atomic_fetch_add(&lpi_shared.irq_count[cpu], 1);
	atomic_store(&lpi_shared.last_irq[cpu], intid);

	gic_set_eoi(intid);
}

static void guest_code_lpi(void)
{
	u32 cpu = guest_get_vcpuid();

	gic_init(GIC_V3, 2);
	gic_rdist_enable_lpis(lpi_shared.lpi_prop_table, SZ_64K,
			      lpi_shared.lpi_pend_tables + (cpu * SZ_64K));

	atomic_fetch_add(&lpi_shared.ready_cpus, 1);
	while (atomic_load(&lpi_shared.ready_cpus) < 2)
		cpu_relax();

	if (cpu == 0) {
		its_init(lpi_shared.collection_table, SZ_64K,
			 lpi_shared.device_table, SZ_64K,
			 lpi_shared.cmdq_base, SZ_64K);

		its_send_mapc_cmd(lpi_shared.cmdq_base_va, 0, 0, true);
		its_send_mapc_cmd(lpi_shared.cmdq_base_va, 1, 1, true);
		its_send_mapd_cmd(lpi_shared.cmdq_base_va, 0, lpi_shared.itt_tables, SZ_64K, true);
		its_send_mapti_cmd(lpi_shared.cmdq_base_va, 0, 0, 0, LPI_INTID);
		its_send_invall_cmd(lpi_shared.cmdq_base_va, 0);
		its_send_invall_cmd(lpi_shared.cmdq_base_va, 1);
		its_send_sync_cmd(lpi_shared.cmdq_base_va, 0);
		its_send_sync_cmd(lpi_shared.cmdq_base_va, 1);

		/*
		 * Test 1: vCPU 0 self-migration of pending LPI.
		 * vCPU 0 has IRQs disabled, gets LPI pending, then submits
		 * ITS MOVI command to migrate it to Collection 1 (vCPU 1).
		 */
		local_irq_disable();
		atomic_store(&lpi_shared.irq_count[0], 0);
		atomic_store(&lpi_shared.irq_count[1], 0);
		atomic_store(&lpi_shared.last_irq[0], 0);
		atomic_store(&lpi_shared.last_irq[1], 0);

		atomic_store(&lpi_shared.stage, 1);
		while (atomic_load(&lpi_shared.stage) != 2)
			cpu_relax();

		/* Signal LPI targeting Collection 0 (vCPU 0) */
		its_send_int_cmd(lpi_shared.cmdq_base_va, 0, 0);

		/* Move event 0 to Collection 1 (vCPU 1) */
		its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 1);
		its_send_sync_cmd(lpi_shared.cmdq_base_va, 1);

		while (atomic_load(&lpi_shared.stage) != 3)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 0);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 1);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.last_irq[1]), LPI_INTID);

		local_irq_enable();
		for (int i = 0; i < 1000; i++)
			cpu_relax();
		local_irq_disable();
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 0);

		/*
		 * Test 2: Cross-vCPU migration: vCPU 0 spins in guest mode with
		 * the pending LPI in its LR, and vCPU 1 submits ITS MOVI.
		 */
		its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 0);
		its_send_sync_cmd(lpi_shared.cmdq_base_va, 0);
		atomic_store(&lpi_shared.irq_count[0], 0);
		atomic_store(&lpi_shared.irq_count[1], 0);
		atomic_store(&lpi_shared.last_irq[0], 0);
		atomic_store(&lpi_shared.last_irq[1], 0);

		/* Signal LPI: flushes into vCPU 0's LR */
		its_send_int_cmd(lpi_shared.cmdq_base_va, 0, 0);

		atomic_store(&lpi_shared.stage, 4);
		while (atomic_load(&lpi_shared.stage) != 5)
			cpu_relax();

		local_irq_enable();
		for (int i = 0; i < 1000; i++)
			cpu_relax();
		local_irq_disable();
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 0);

		/*
		 * Test 3: Reverse cross-vCPU migration: vCPU 1 in guest mode with
		 * pending LPI in LR, vCPU 0 submits MOVI.
		 */
		atomic_store(&lpi_shared.stage, 6);
		local_irq_enable();

		while (atomic_load(&lpi_shared.stage) != 7)
			cpu_relax();

		its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 0);
		its_send_sync_cmd(lpi_shared.cmdq_base_va, 0);

		while (atomic_load(&lpi_shared.irq_count[0]) < 1)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 1);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.last_irq[0]), LPI_INTID);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 0);

		atomic_store(&lpi_shared.stage, 8);
		local_irq_disable();

		while (atomic_load(&lpi_shared.stage) != 9)
			cpu_relax();

		/*
		 * Test 4: Host-triggered MSI migration via KVM_SIGNAL_MSI.
		 */
		atomic_store(&lpi_shared.irq_count[0], 0);
		atomic_store(&lpi_shared.irq_count[1], 0);

		/* Event 0 is at Collection 0; ask host to signal MSI */
		GUEST_SYNC(UCALL_CMD_SIGNAL_MSI);

		atomic_store(&lpi_shared.stage, 10);
		while (atomic_load(&lpi_shared.stage) != 11)
			cpu_relax();

		local_irq_enable();
		for (int i = 0; i < 1000; i++)
			cpu_relax();
		local_irq_disable();
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 0);

		atomic_store(&lpi_shared.stage, 12);

		/*
		 * Test 5: Repeated ping-pong migrations.
		 */
		for (size_t iter = 0; iter < lpi_shared.nr_iterations; iter++) {
			atomic_store(&lpi_shared.irq_count[0], 0);
			atomic_store(&lpi_shared.irq_count[1], 0);

			/* Phase A: move to coll 0, signal LPI, vCPU 1 moves to coll 1 */
			its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 0);
			its_send_sync_cmd(lpi_shared.cmdq_base_va, 0);
			its_send_int_cmd(lpi_shared.cmdq_base_va, 0, 0);

			atomic_store(&lpi_shared.stage, 20);
			while (atomic_load(&lpi_shared.stage) != 21)
				cpu_relax();

			/* Phase B: vCPU 1 signals LPI on coll 1, vCPU 0 moves to coll 0 */
			local_irq_enable();
			atomic_store(&lpi_shared.stage, 22);
			while (atomic_load(&lpi_shared.stage) != 23)
				cpu_relax();

			its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 0);
			its_send_sync_cmd(lpi_shared.cmdq_base_va, 0);

			while (atomic_load(&lpi_shared.irq_count[0]) < 1)
				cpu_relax();

			GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 1);
			local_irq_disable();

			atomic_store(&lpi_shared.stage, 24);
			while (atomic_load(&lpi_shared.stage) != 25)
				cpu_relax();
		}

		atomic_store(&lpi_shared.stage, 99);
		GUEST_DONE();
	} else {
		/* vCPU 1 */
		local_irq_enable();

		/* Test 1 */
		while (atomic_load(&lpi_shared.stage) != 1)
			cpu_relax();
		atomic_store(&lpi_shared.stage, 2);

		while (atomic_load(&lpi_shared.irq_count[1]) < 1)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 1);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.last_irq[1]), LPI_INTID);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 0);

		atomic_store(&lpi_shared.stage, 3);

		/* Test 2 */
		while (atomic_load(&lpi_shared.stage) != 4)
			cpu_relax();

		/* Move event 0 to Collection 1 (vCPU 1) */
		its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 1);
		its_send_sync_cmd(lpi_shared.cmdq_base_va, 1);

		while (atomic_load(&lpi_shared.irq_count[1]) < 1)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 1);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.last_irq[1]), LPI_INTID);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 0);

		atomic_store(&lpi_shared.stage, 5);

		/* Test 3: Reverse */
		while (atomic_load(&lpi_shared.stage) != 6)
			cpu_relax();

		local_irq_disable();
		atomic_store(&lpi_shared.irq_count[0], 0);
		atomic_store(&lpi_shared.irq_count[1], 0);

		/* vCPU 1 signals LPI */
		its_send_int_cmd(lpi_shared.cmdq_base_va, 0, 0);

		atomic_store(&lpi_shared.stage, 7);
		while (atomic_load(&lpi_shared.stage) != 8)
			cpu_relax();

		local_irq_enable();
		for (int i = 0; i < 1000; i++)
			cpu_relax();
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 0);

		/* Signal vCPU 0 that vCPU 1 is ready for Test 4 */
		atomic_store(&lpi_shared.stage, 9);

		/* Test 4: Host-triggered MSI */
		while (atomic_load(&lpi_shared.stage) != 10)
			cpu_relax();

		its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 1);
		its_send_sync_cmd(lpi_shared.cmdq_base_va, 1);

		while (atomic_load(&lpi_shared.irq_count[1]) < 1)
			cpu_relax();

		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 1);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.last_irq[1]), LPI_INTID);
		GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[0]), 0);

		atomic_store(&lpi_shared.stage, 11);
		while (atomic_load(&lpi_shared.stage) != 12)
			cpu_relax();

		/* Test 5: Loop */
		for (size_t iter = 0; iter < lpi_shared.nr_iterations; iter++) {
			while (atomic_load(&lpi_shared.stage) != 20)
				cpu_relax();

			its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 1);
			its_send_sync_cmd(lpi_shared.cmdq_base_va, 1);

			while (atomic_load(&lpi_shared.irq_count[1]) < 1)
				cpu_relax();

			GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 1);
			atomic_store(&lpi_shared.stage, 21);

			while (atomic_load(&lpi_shared.stage) != 22)
				cpu_relax();

			local_irq_disable();
			atomic_store(&lpi_shared.irq_count[0], 0);
			atomic_store(&lpi_shared.irq_count[1], 0);

			its_send_movi_cmd(lpi_shared.cmdq_base_va, 0, 0, 1);
			its_send_sync_cmd(lpi_shared.cmdq_base_va, 1);
			its_send_int_cmd(lpi_shared.cmdq_base_va, 0, 0);

			atomic_store(&lpi_shared.stage, 23);
			while (atomic_load(&lpi_shared.stage) != 24)
				cpu_relax();

			local_irq_enable();
			for (int i = 0; i < 1000; i++)
				cpu_relax();
			GUEST_ASSERT_EQ(atomic_load(&lpi_shared.irq_count[1]), 0);

			atomic_store(&lpi_shared.stage, 25);
		}

		while (atomic_load(&lpi_shared.stage) != 99)
			cpu_relax();
		GUEST_DONE();
	}
}

static void signal_lpi(struct kvm_vm *vm, u32 device_id, u32 event_id)
{
	gpa_t db_addr = GITS_BASE_GPA + GITS_TRANSLATER;
	struct kvm_msi msi = {
		.address_lo	= db_addr,
		.address_hi	= db_addr >> 32,
		.data		= event_id,
		.devid		= device_id,
		.flags		= KVM_MSI_VALID_DEVID,
	};

	TEST_ASSERT(__vm_ioctl(vm, KVM_SIGNAL_MSI, &msi) == 1,
		    "KVM_SIGNAL_MSI ioctl failed");
}

static void *test_vcpu_run(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	struct ucall uc;

	while (1) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_PRINTF:
			REPORT_GUEST_PRINTF(uc);
			break;
		case UCALL_SYNC:
			if (uc.args[1] == UCALL_CMD_SIGNAL_MSI)
				signal_lpi(vcpu->vm, 0, 0);
			break;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		case UCALL_DONE:
			return NULL;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}
	}

	return NULL;
}

static void test_spi_migration(size_t nr_iterations)
{
	pthread_t thr[2];
	struct kvm_vcpu *vcpus[2];
	struct kvm_vm *vm;

	vm = vm_create_with_vcpus(2, guest_code_spi, vcpus);

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpus[0]);
	vcpu_init_descriptor_tables(vcpus[1]);
	vm_install_exception_handler(vm, VECTOR_IRQ_CURRENT, guest_irq_handler_spi);

	memset(&spi_shared, 0, sizeof(spi_shared));
	spi_shared.nr_iterations = nr_iterations;
	sync_global_to_guest(vm, spi_shared);

	kvm_pthread_create(&thr[0], NULL, test_vcpu_run, vcpus[0]);
	kvm_pthread_create(&thr[1], NULL, test_vcpu_run, vcpus[1]);

	kvm_pthread_join(thr[0], NULL);
	kvm_pthread_join(thr[1], NULL);

	kvm_vm_free(vm);
}

static void setup_its_tables(struct kvm_vm *vm, struct lpi_shared_data *shared_data)
{
	size_t pages_per_64k = vm_calc_num_guest_pages(vm->mode, SZ_64K);
	size_t sz = 7 * SZ_64K;
	size_t pages = sz / vm->page_size;
	gpa_t gpa_base = ((vm_compute_max_gfn(vm) + 1) * vm->page_size) - sz;
	gpa_t cmdq_base;
	u8 *tbl;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, gpa_base,
				    TEST_MEMSLOT_INDEX, pages, 0);

	shared_data->device_table = vm_phy_pages_alloc(vm, pages_per_64k,
						       gpa_base, TEST_MEMSLOT_INDEX);
	shared_data->collection_table = vm_phy_pages_alloc(vm, pages_per_64k,
							   gpa_base, TEST_MEMSLOT_INDEX);

	cmdq_base = vm_phy_pages_alloc(vm, pages_per_64k, gpa_base, TEST_MEMSLOT_INDEX);
	virt_map(vm, cmdq_base, cmdq_base, pages_per_64k);
	shared_data->cmdq_base = cmdq_base;
	shared_data->cmdq_base_va = (void *)cmdq_base;

	shared_data->itt_tables = vm_phy_pages_alloc(vm, pages_per_64k,
						     gpa_base, TEST_MEMSLOT_INDEX);
	shared_data->lpi_prop_table = vm_phy_pages_alloc(vm, pages_per_64k,
							 gpa_base, TEST_MEMSLOT_INDEX);

	tbl = addr_gpa2hva(vm, shared_data->lpi_prop_table);
	memset(tbl, 0, SZ_64K);
	for (int i = 0; i < 256; i++)
		tbl[i] = LPI_PROP_DEFAULT_PRIO | LPI_PROP_GROUP1 | LPI_PROP_ENABLED;

	shared_data->lpi_pend_tables = vm_phy_pages_alloc(vm, pages_per_64k * 2,
							  gpa_base, TEST_MEMSLOT_INDEX);
}

static bool kvm_supports_its(void)
{
	struct kvm_vm *vm;
	int r;

	if (!kvm_supports_vgic_v3())
		return false;

	vm = vm_create_barebones();
	kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3);
	r = __kvm_test_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_ITS);
	kvm_vm_free(vm);

	return !r;
}

static void test_lpi_migration(size_t nr_iterations)
{
	pthread_t thr[2];
	struct kvm_vcpu *vcpus[2];
	struct kvm_vm *vm;
	int its_fd;

	vm = vm_create_with_vcpus(2, guest_code_lpi, vcpus);

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpus[0]);
	vcpu_init_descriptor_tables(vcpus[1]);
	vm_install_exception_handler(vm, VECTOR_IRQ_CURRENT, guest_irq_handler_lpi);

	its_fd = vgic_its_setup(vm);

	memset(&lpi_shared, 0, sizeof(lpi_shared));
	lpi_shared.nr_iterations = nr_iterations;
	setup_its_tables(vm, &lpi_shared);
	sync_global_to_guest(vm, lpi_shared);

	kvm_pthread_create(&thr[0], NULL, test_vcpu_run, vcpus[0]);
	kvm_pthread_create(&thr[1], NULL, test_vcpu_run, vcpus[1]);

	kvm_pthread_join(thr[0], NULL);
	kvm_pthread_join(thr[1], NULL);

	close(its_fd);
	kvm_vm_free(vm);
}

static void help(const char *name)
{
	printf("\n"
	       "usage: %s [-s] [-l] [-i iterations]\n"
	       " -s: run only SPI migration tests\n"
	       " -l: run only LPI migration tests\n"
	       " -i: number of iterations for loop tests (default: 50)\n\n",
	       name);
}

int main(int argc, char **argv)
{
	bool run_spi = true;
	bool run_lpi = true;
	size_t nr_iterations = 50;
	int opt;

	TEST_REQUIRE(kvm_supports_vgic_v3());

	while ((opt = getopt(argc, argv, "sli:h")) != -1) {
		switch (opt) {
		case 's':
			run_lpi = false;
			break;
		case 'l':
			run_spi = false;
			break;
		case 'i':
			nr_iterations = atoi_positive("iterations", optarg);
			break;
		case 'h':
		default:
			help(argv[0]);
			exit(1);
		}
	}

	if (run_spi) {
		pr_info("Testing SPI migration while in pending state...\n");
		test_spi_migration(nr_iterations);
		pr_info("SPI migration tests passed!\n");
	}

	if (run_lpi) {
		if (!kvm_supports_its()) {
			print_skip("ITS not supported, skipping LPI migration tests");
		} else {
			pr_info("Testing LPI migration while in pending state...\n");
			test_lpi_migration(nr_iterations);
			pr_info("LPI migration tests passed!\n");
		}
	}

	return 0;
}
