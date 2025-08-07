#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/miscdevice.h>

#include <asm/cputype.h>
#include <asm/hypervisor.h>

#include <uapi/linux/apple-virt-tso.h>

#define SYS_IMP_APL_AIDR_EL1_TSO	BIT(9)

#define SYS_IMP_APL_ACTLR_EL12		sys_reg(3, 6, 15, 14, 6)
#define SYS_IMP_APL_ACTLR_EL1_TSOEN	BIT(1)

static DEFINE_STATIC_KEY_FALSE(has_impdef_actlr_accessor);

static void enable_virt_tso_on_cpu(void)
{
	/*
	 * Rely on exception return into the guest for a context synchronization
	 * event.
	 */
	if (static_branch_unlikely(&has_impdef_actlr_accessor))
		sysreg_clear_set_s(SYS_IMP_APL_ACTLR_EL12, 0,
				   SYS_IMP_APL_ACTLR_EL1_TSOEN);
	else
		sysreg_clear_set_s(SYS_ACTLR_EL12, 0,
				   SYS_IMP_APL_ACTLR_EL1_TSOEN);
}

static void disable_virt_tso_on_cpu(void)
{
	if (static_branch_unlikely(&has_impdef_actlr_accessor))
		sysreg_clear_set_s(SYS_IMP_APL_ACTLR_EL12,
				   SYS_IMP_APL_ACTLR_EL1_TSOEN, 0);
	else
		sysreg_clear_set_s(SYS_ACTLR_EL12,
				   SYS_IMP_APL_ACTLR_EL1_TSOEN, 0);
}

static void handle_vcpu_load(struct kvm_vcpu_notifier *n, int vcpu_id)
{
	enable_virt_tso_on_cpu();
}

static void handle_vcpu_put(struct kvm_vcpu_notifier *n, int vcpu_id)
{
	disable_virt_tso_on_cpu();
}

static void handle_notifier_release(struct kvm_vcpu_notifier *n)
{
	kfree(n);
}

static const struct kvm_vcpu_notifier_ops vcpu_ops = {
	.vcpu_load	= handle_vcpu_load,
	.vcpu_put	= handle_vcpu_put,
	.release	= handle_notifier_release,
};

static int register_vcpu_notifier(int kvm_fd)
{
	struct kvm_vcpu_notifier *n;
	int r;

	n = kzalloc(sizeof(*n), GFP_KERNEL_ACCOUNT);
	if (!n)
		return -ENOMEM;

	kvm_init_vcpu_notifier(n, &vcpu_ops);
	r = kvm_register_vcpu_notifier(n, kvm_fd);
	if (r)
		kfree(n);

	return r;
}

static bool system_supports_apple_virt_tso(void)
{
	if (read_cpuid_implementor() != ARM_CPU_IMP_APPLE)
		return false;

	if (!is_kernel_in_hyp_mode())
		return false;

	if (kvm_hypervisor_detected())
		return false;

	return read_sysreg(aidr_el1) & SYS_IMP_APL_AIDR_EL1_TSO;
}

static bool system_has_impdef_actlr_accessor(void)
{
	static const struct midr_range cpus[] = {
		MIDR_ALL_VERSIONS(MIDR_APPLE_M1_ICESTORM),
		MIDR_ALL_VERSIONS(MIDR_APPLE_M1_FIRESTORM),
		MIDR_ALL_VERSIONS(MIDR_APPLE_M1_ICESTORM_PRO),
		MIDR_ALL_VERSIONS(MIDR_APPLE_M1_FIRESTORM_PRO),
		MIDR_ALL_VERSIONS(MIDR_APPLE_M1_ICESTORM_MAX),
		MIDR_ALL_VERSIONS(MIDR_APPLE_M1_FIRESTORM_MAX),
	};

	return is_midr_in_range_list(cpus);
}

static long virt_tso_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int __user *uaddr = (int __user *)arg;
	int kvm_fd;

	if (cmd != APPLE_VIRT_TSO_ENABLE)
		return -ENXIO;

	if (get_user(kvm_fd, uaddr))
		return -EFAULT;

	return register_vcpu_notifier(kvm_fd);
}

static const struct file_operations virt_tso_dev_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= virt_tso_ioctl,
};

static struct miscdevice virt_tso_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "apple_virt_tso",
	.fops	= &virt_tso_dev_fops,
	.mode	= 0660,
};

static __init int apple_virt_tso_init(void)
{
	if (!system_supports_apple_virt_tso())
		return -ENODEV;

	if (system_has_impdef_actlr_accessor())
		static_branch_enable(&has_impdef_actlr_accessor);

	return misc_register(&virt_tso_dev);
}

static void apple_virt_tso_exit(void)
{
	misc_deregister(&virt_tso_dev);
}

module_init(apple_virt_tso_init);
module_exit(apple_virt_tso_exit);
MODULE_LICENSE("GPL");
