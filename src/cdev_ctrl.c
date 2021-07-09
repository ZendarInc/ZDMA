/*
 * This file is part of the Xilinx DMA IP Core driver for Linux
 *
 * Copyright (c) 2016-present,  Xilinx, Inc.
 * All rights reserved.
 *
 * This source code is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */

#define pr_fmt(fmt)     KBUILD_MODNAME ":%s: " fmt, __func__

#include "version.h"
#include "cdev_ctrl.h"
#include "zdma_cdev.h"

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>


/*
 * character device file operations for control bus (through control bridge)
 */
static ssize_t char_ctrl_read(struct file *fp, char __user *buf, size_t count,
		loff_t *pos)
{
	struct zdma_cdev *zcdev = (struct zdma_cdev *)fp->private_data;
	struct zdma_dev *zdev;
	void __iomem *reg;
	u32 w;
	int rv;

	rv = zcdev_check(__func__, zcdev, 0);
	if (rv < 0)
		return rv;
	zdev = zcdev->zdev;

	/* only 32-bit aligned and 32-bit multiples */
	if (*pos & 3)
		return -EPROTO;
	/* first address is BAR base plus file position offset */
	reg = zdev->bar[zcdev->bar] + *pos;
	//w = read_register(reg);
	w = ioread32(reg);
	dbg_sg("%s(@%p, count=%ld, pos=%d) value = 0x%08x\n",
			__func__, reg, (long)count, (int)*pos, w);
	rv = copy_to_user(buf, &w, 4);
	if (rv)
		dbg_sg("Copy to userspace failed but continuing\n");

	*pos += 4;
	return 4;
}

static ssize_t char_ctrl_write(struct file *file, const char __user *buf,
			size_t count, loff_t *pos)
{
	struct zdma_cdev *zcdev = (struct zdma_cdev *)file->private_data;
	struct zdma_dev *zdev;
	void __iomem *reg;
	u32 w;
	int rv;

	rv = zcdev_check(__func__, zcdev, 0);
	if (rv < 0)
		return rv;
	zdev = zcdev->zdev;

	/* only 32-bit aligned and 32-bit multiples */
	if (*pos & 3)
		return -EPROTO;

	/* first address is BAR base plus file position offset */
	reg = zdev->bar[zcdev->bar] + *pos;
	rv = copy_from_user(&w, buf, 4);
	if (rv)
		pr_info("copy from user failed %d/4, but continuing.\n", rv);

	dbg_sg("%s(0x%08x @%p, count=%ld, pos=%d)\n",
			__func__, w, reg, (long)count, (int)*pos);
	//write_register(w, reg);
	iowrite32(w, reg);
	*pos += 4;
	return 4;
}

static long version_ioctl(struct zdma_cdev *zcdev, void __user *arg)
{
	struct zdma_ioc_info obj;
	struct zdma_dev *zdev = zcdev->zdev;
	int rv;

	rv = copy_from_user((void *)&obj, arg, sizeof(struct zdma_ioc_info));
	if (rv) {
		pr_info("copy from user failed %d/%ld.\n",
			rv, sizeof(struct zdma_ioc_info));
		return -EFAULT;
	}
	memset(&obj, 0, sizeof(obj));
	obj.vendor = zdev->pdev->vendor;
	obj.device = zdev->pdev->device;
	obj.subsystem_vendor = zdev->pdev->subsystem_vendor;
	obj.subsystem_device = zdev->pdev->subsystem_device;
	obj.driver_version = DRV_MOD_VERSION_NUMBER;
	obj.domain = 0;
	obj.bus = PCI_BUS_NUM(zdev->pdev->devfn);
	obj.dev = PCI_SLOT(zdev->pdev->devfn);
	obj.func = PCI_FUNC(zdev->pdev->devfn);
	if (copy_to_user(arg, &obj, sizeof(struct zdma_ioc_info)))
		return -EFAULT;
	return 0;
}

long char_ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct zdma_cdev *zcdev = (struct zdma_cdev *)filp->private_data;
	struct zdma_dev *zdev;
	struct zdma_ioc_base ioctl_obj;
	long result = 0;
	int rv;

	rv = zcdev_check(__func__, zcdev, 0);
	if (rv < 0)
		return rv;

	zdev = zcdev->zdev;
	if (!zdev) {
		pr_info("cmd %u, zdev NULL.\n", cmd);
		return -EINVAL;
	}
	pr_info("cmd 0x%x, zdev 0x%p, pdev 0x%p.\n", cmd, zdev, zdev->pdev);

	if (_IOC_TYPE(cmd) != ZDMA_IOC_MAGIC) {
		pr_err("cmd %u, bad magic 0x%x/0x%x.\n",
			 cmd, _IOC_TYPE(cmd), ZDMA_IOC_MAGIC);
		return -ENOTTY;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
	if (_IOC_DIR(cmd) & _IOC_READ)
		result = !access_ok(VERIFY_WRITE, (void __user *)arg,
				_IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		result =  !access_ok(VERIFY_READ, (void __user *)arg,
				_IOC_SIZE(cmd));
#else
	if (_IOC_DIR(cmd) & _IOC_READ)
		result = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		result =  !access_ok((void __user *)arg, _IOC_SIZE(cmd));
#endif

	if (result) {
		pr_err("bad access %ld.\n", result);
		return -EFAULT;
	}

	switch (cmd) {
	case ZDMA_IOCINFO:
		if (copy_from_user((void *)&ioctl_obj, (void __user *) arg,
			 sizeof(struct zdma_ioc_base))) {
			pr_err("copy_from_user failed.\n");
			return -EFAULT;
		}

		if (ioctl_obj.magic != ZDMA_XCL_MAGIC) {
			pr_err("magic 0x%x !=  ZDMA_XCL_MAGIC (0x%x).\n",
				ioctl_obj.magic, ZDMA_XCL_MAGIC);
			return -ENOTTY;
		}
		return version_ioctl(zcdev, (void __user *)arg);
	case ZDMA_IOCOFFLINE:
		zdma_device_offline(zdev->pdev, zdev);
		break;
	case ZDMA_IOCONLINE:
		zdma_device_online(zdev->pdev, zdev);
		break;
	default:
		pr_err("UNKNOWN ioctl cmd 0x%x.\n", cmd);
		return -ENOTTY;
	}
	return 0;
}

/* maps the PCIe BAR into user space for memory-like access using mmap() */
int bridge_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zdma_dev *zdev;
	struct zdma_cdev *zcdev = (struct zdma_cdev *)file->private_data;
	unsigned long off;
	unsigned long phys;
	unsigned long vsize;
	unsigned long psize;
	int rv;

	rv = zcdev_check(__func__, zcdev, 0);
	if (rv < 0)
		return rv;
	zdev = zcdev->zdev;

	off = vma->vm_pgoff << PAGE_SHIFT;
	/* BAR physical address */
	phys = pci_resource_start(zdev->pdev, zcdev->bar) + off;
	vsize = vma->vm_end - vma->vm_start;
	/* complete resource */
	psize = pci_resource_end(zdev->pdev, zcdev->bar) -
		pci_resource_start(zdev->pdev, zcdev->bar) + 1 - off;

	dbg_sg("mmap(): zcdev = 0x%08lx\n", (unsigned long)zcdev);
	dbg_sg("mmap(): cdev->bar = %d\n", zcdev->bar);
	dbg_sg("mmap(): zdev = 0x%p\n", zdev);
	dbg_sg("mmap(): pci_dev = 0x%08lx\n", (unsigned long)zdev->pdev);

	dbg_sg("off = 0x%lx\n", off);
	dbg_sg("start = 0x%llx\n",
		(unsigned long long)pci_resource_start(zdev->pdev,
		zcdev->bar));
	dbg_sg("phys = 0x%lx\n", phys);

	if (vsize > psize)
		return -EINVAL;
	/*
	 * pages must not be cached as this would result in cache line sized
	 * accesses to the end point
	 */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	/*
	 * prevent touching the pages (byte access) for swap-in,
	 * and prevent the pages from being swapped out
	 */
	vma->vm_flags |= VMEM_FLAGS;
	/* make MMIO accessible to user space */
	rv = io_remap_pfn_range(vma, vma->vm_start, phys >> PAGE_SHIFT,
			vsize, vma->vm_page_prot);
	dbg_sg("vma=0x%p, vma->vm_start=0x%lx, phys=0x%lx, size=%lu = %d\n",
		vma, vma->vm_start, phys >> PAGE_SHIFT, vsize, rv);

	if (rv)
		return -EAGAIN;
	return 0;
}

/*
 * character device file operations for control bus (through control bridge)
 */
static const struct file_operations ctrl_fops = {
	.owner = THIS_MODULE,
	.open = char_open,
	.release = char_close,
	.read = char_ctrl_read,
	.write = char_ctrl_write,
	.mmap = bridge_mmap,
	.unlocked_ioctl = char_ctrl_ioctl,
};

void cdev_ctrl_init(struct zdma_cdev *zcdev)
{
	cdev_init(&zcdev->cdev, &ctrl_fops);
}
