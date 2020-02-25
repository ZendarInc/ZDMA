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

#ifndef __ZDMA_CHRDEV_H__
#define __ZDMA_CHRDEV_H__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include "zdma_mod.h"

#define ZDMA_NODE_NAME	"zdma"
#define ZDMA_MINOR_BASE (0)
#define ZDMA_MINOR_COUNT (255)

void zdma_cdev_cleanup(void);
int zdma_cdev_init(void);

int char_open(struct inode *inode, struct file *file);
int char_close(struct inode *inode, struct file *file);
int zcdev_check(const char *fname, struct zdma_cdev *zcdev, bool check_engine);
void cdev_ctrl_init(struct zdma_cdev *zcdev);
void cdev_event_init(struct zdma_cdev *zcdev);
void cdev_sgdma_init(struct zdma_cdev *zcdev);
long char_ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

void zpdev_destroy_interfaces(struct zdma_pci_dev *zpdev);
int zpdev_create_interfaces(struct zdma_pci_dev *zpdev);

int bridge_mmap(struct file *file, struct vm_area_struct *vma);

#endif /* __ZDMA_CHRDEV_H__ */
