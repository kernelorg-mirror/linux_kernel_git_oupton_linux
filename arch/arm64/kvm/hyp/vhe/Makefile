# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module, HYP/VHE part
#

asflags-y := -D__KVM_VHE_HYPERVISOR__
ccflags-y := -D__KVM_VHE_HYPERVISOR__

obj-y := timer-sr.o sysreg-sr.o debug-sr.o switch.o tlb.o
obj-y += ../aarch32.o \
	 ../entry.o \
	 ../exception.o \
	 ../fpsimd.o \
	 ../hyp-entry.o \
	 ../tlb.o \
	 ../vgic-v2-cpuif-proxy.o \
	 ../vgic-v3-sr.o
