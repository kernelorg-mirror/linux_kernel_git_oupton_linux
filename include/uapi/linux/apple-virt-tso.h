#ifndef __LINUX_APPLE_VIRT_TSO_H
#define __LINUX_APPLE_VIRT_TSO_H

#include <linux/ioctl.h>

#define APPLE_VIRT_TSO_IO	0x61

#define APPLE_VIRT_TSO_ENABLE	_IOW(APPLE_VIRT_TSO_IO,  0x00, int *)

#endif
