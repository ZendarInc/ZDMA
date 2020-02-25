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

#ifndef __ZDMA_MODULE_H__
#define __ZDMA_MODULE_H__

#include <linux/types.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/poll.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/aio.h>
#include <linux/splice.h>
#include <linux/version.h>
#include <linux/uio.h>
#include <linux/spinlock_types.h>

#include "libzdma.h"

#define MAGIC_ENGINE	0xEEEEEEEEUL
#define MAGIC_DEVICE	0xDDDDDDDDUL
#define MAGIC_CHAR	0xCCCCCCCCUL
#define MAGIC_BITSTREAM 0xBBBBBBBBUL

extern unsigned int desc_blen_max;
extern unsigned int sgdma_timeout;

struct zdma_cdev {
	unsigned long magic;		/* structure ID for sanity checks */
	struct zdma_pci_dev *zpdev;
	struct zdma_dev *zdev;
	dev_t cdevno;			/* character device major:minor */
	struct cdev cdev;		/* character device embedded struct */
	int bar;			/* PCIe BAR for HW access, if needed */
	unsigned long base;		/* bar access offset */
	struct zdma_engine *engine;	/* engine instance, if needed */
	struct zdma_user_irq *user_irq;	/* IRQ value, if needed */
	struct device *sys_device;	/* sysfs device */
	spinlock_t lock;
};

/* ZDMA PCIe device specific book-keeping */
struct zdma_pci_dev {
	unsigned long magic;		/* structure ID for sanity checks */
	struct pci_dev *pdev;	/* pci device struct from probe() */
	struct zdma_dev *zdev;
	int major;		/* major number */
	int instance;		/* instance number */
	int user_max;
	int c2h_channel_max;
	int h2c_channel_max;

	unsigned int flags;
	/* character device structures */
	struct zdma_cdev ctrl_cdev;
	struct zdma_cdev sgdma_c2h_cdev[ZDMA_CHANNEL_NUM_MAX];
	struct zdma_cdev sgdma_h2c_cdev[ZDMA_CHANNEL_NUM_MAX];
	struct zdma_cdev events_cdev[16];

	struct zdma_cdev user_cdev;
	struct zdma_cdev xvc_cdev;

	void *data;
};

struct cdev_async_io {
	struct kiocb *iocb;
	struct zdma_io_cb* cb;
	bool write;
	bool cancel;
	int cmpl_cnt;
	int req_cnt;
	spinlock_t lock;
	struct work_struct wrk_itm;
	struct cdev_async_io *next;
	ssize_t res;
	ssize_t res2;
	int err_cnt;
};

#endif /* ifndef __ZDMA_MODULE_H__ */
