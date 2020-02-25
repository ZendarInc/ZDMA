/*
 * This file is part of the Xilinx DMA IP Core driver for Linux
 *
 * Copyright (c) 2016-present,	Xilinx, Inc.
 * All rights reserved.
 *
 * This source code is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.	See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */

#define pr_fmt(fmt)		 KBUILD_MODNAME ":%s: " fmt, __func__

#include "zdma_cdev.h"

static struct class *g_zdma_class;

struct kmem_cache *cdev_cache;

enum cdev_type {
	CHAR_USER,
	CHAR_CTRL,
	CHAR_EVENTS,
	CHAR_ZDMA_H2C,
	CHAR_ZDMA_C2H
};

static const char * const devnode_names[] = {
	ZDMA_NODE_NAME "%d_user",
	ZDMA_NODE_NAME "%d_control",
	ZDMA_NODE_NAME "%d_xvc",
	ZDMA_NODE_NAME "%d_events_%d",
	ZDMA_NODE_NAME "%d_h2c_%d",
	ZDMA_NODE_NAME "%d_c2h_%d"
};

enum zpdev_flags_bits {
	XDF_CDEV_USER,
	XDF_CDEV_CTRL,
	XDF_CDEV_EVENT,
	XDF_CDEV_SG,
};

static inline void zpdev_flag_set(struct zdma_pci_dev *zpdev,
				enum zpdev_flags_bits fbit)
{
	zpdev->flags |= 1 << fbit;
}

static inline void zcdev_flag_clear(struct zdma_pci_dev *zpdev,
				enum zpdev_flags_bits fbit)
{
	zpdev->flags &= ~(1 << fbit);
}

static inline int zpdev_flag_test(struct zdma_pci_dev *zpdev,
				enum zpdev_flags_bits fbit)
{
	return zpdev->flags & (1 << fbit);
}

#ifdef __ZDMA_SYSFS__
ssize_t zdma_dev_instance_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct zdma_pci_dev *zpdev =
		(struct zdma_pci_dev *)dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\t%d\n",
			zpdev->major, zpdev->zdev->idx);
}

static DEVICE_ATTR_RO(zdma_dev_instance);
#endif

static int config_kobject(struct zdma_cdev *zcdev, enum cdev_type type)
{
	int rv = -EINVAL;
	struct zdma_dev *zdev = zcdev->zdev;
	struct zdma_engine *engine = zcdev->engine;

	switch (type) {
	case CHAR_ZDMA_H2C:
	case CHAR_ZDMA_C2H:
		if (!engine) {
			pr_err("Invalid DMA engine\n");
			return rv;
		}
		rv = kobject_set_name(&zcdev->cdev.kobj, devnode_names[type],
			zdev->idx, engine->channel);
		break;
	case CHAR_USER:
	case CHAR_CTRL:
	case CHAR_EVENTS:
		rv = kobject_set_name(&zcdev->cdev.kobj, devnode_names[type],
			zdev->idx, zcdev->bar);
		break;
	default:
		pr_warn("%s: UNKNOWN type 0x%x.\n", __func__, type);
		break;
	}

	if (rv)
		pr_err("%s: type 0x%x, failed %d.\n", __func__, type, rv);
	return rv;
}

int zcdev_check(const char *fname, struct zdma_cdev *zcdev, bool check_engine)
{
	struct zdma_dev *zdev;

	if (!zcdev || zcdev->magic != MAGIC_CHAR) {
		pr_info("%s, zcdev 0x%p, magic 0x%lx.\n",
			fname, zcdev, zcdev ? zcdev->magic : 0xFFFFFFFF);
		return -EINVAL;
	}

	zdev = zcdev->zdev;
	if (!zdev || zdev->magic != MAGIC_DEVICE) {
		pr_info("%s, zdev 0x%p, magic 0x%lx.\n",
			fname, zdev, zdev ? zdev->magic : 0xFFFFFFFF);
		return -EINVAL;
	}

	if (check_engine) {
		struct zdma_engine *engine = zcdev->engine;

		if (!engine || engine->magic != MAGIC_ENGINE) {
			pr_info("%s, engine 0x%p, magic 0x%lx.\n", fname,
				engine, engine ? engine->magic : 0xFFFFFFFF);
			return -EINVAL;
		}
	}

	return 0;
}

int char_open(struct inode *inode, struct file *file)
{
	struct zdma_cdev *zcdev;

	/* pointer to containing structure of the character device inode */
	zcdev = container_of(inode->i_cdev, struct zdma_cdev, cdev);
	if (zcdev->magic != MAGIC_CHAR) {
		pr_err("zcdev 0x%p inode 0x%lx magic mismatch 0x%lx\n",
			zcdev, inode->i_ino, zcdev->magic);
		return -EINVAL;
	}
	/* create a reference to our char device in the opened file */
	file->private_data = zcdev;

	return 0;
}

/*
 * Called when the device goes from used to unused.
 */
int char_close(struct inode *inode, struct file *file)
{
	struct zdma_dev *zdev;
	struct zdma_cdev *zcdev = (struct zdma_cdev *)file->private_data;

	if (!zcdev) {
		pr_err("char device with inode 0x%lx zcdev NULL\n",
			inode->i_ino);
		return -EINVAL;
	}

	if (zcdev->magic != MAGIC_CHAR) {
		pr_err("zcdev 0x%p magic mismatch 0x%lx\n",
				zcdev, zcdev->magic);
		return -EINVAL;
	}

	/* fetch device specific data stored earlier during open */
	zdev = zcdev->zdev;
	if (!zdev) {
		pr_err("char device with inode 0x%lx zdev NULL\n",
			inode->i_ino);
		return -EINVAL;
	}

	if (zdev->magic != MAGIC_DEVICE) {
		pr_err("zdev 0x%p magic mismatch 0x%lx\n", zdev, zdev->magic);
		return -EINVAL;
	}

	return 0;
}

/* create_zcdev() -- create a character device interface to data or control bus
 *
 * If at least one SG DMA engine is specified, the character device interface
 * is coupled to the SG DMA file operations which operate on the data bus. If
 * no engines are specified, the interface is coupled with the control bus.
 */

static int create_sys_device(struct zdma_cdev *zcdev, enum cdev_type type)
{
	struct zdma_dev *zdev = zcdev->zdev;
	struct zdma_engine *engine = zcdev->engine;
	int last_param;

	if (type == CHAR_EVENTS)
		last_param = zcdev->bar;
	else
		last_param = engine ? engine->channel : 0;

	zcdev->sys_device = device_create(g_zdma_class, &zdev->pdev->dev,
		zcdev->cdevno, NULL, devnode_names[type], zdev->idx,
		last_param);

	if (!zcdev->sys_device) {
		pr_err("device_create(%s) failed\n", devnode_names[type]);
		return -1;
	}

	return 0;
}

static int destroy_zcdev(struct zdma_cdev *cdev)
{
	if (!cdev) {
		pr_warn("cdev NULL.\n");
		return -EINVAL;
	}
	if (cdev->magic != MAGIC_CHAR) {
		pr_warn("cdev 0x%p magic mismatch 0x%lx\n", cdev, cdev->magic);
		return -EINVAL;
	}

	if (!cdev->zdev) {
		pr_err("zdev NULL\n");
		return -EINVAL;
	}

	if (!g_zdma_class) {
		pr_err("g_zdma_class NULL\n");
		return -EINVAL;
	}

	if (!cdev->sys_device) {
		pr_err("cdev sys_device NULL\n");
		return -EINVAL;
	}

	if (cdev->sys_device)
		device_destroy(g_zdma_class, cdev->cdevno);

	cdev_del(&cdev->cdev);

	return 0;
}

static int create_zcdev(struct zdma_pci_dev *zpdev, struct zdma_cdev *zcdev,
			int bar, struct zdma_engine *engine,
			enum cdev_type type)
{
	int rv;
	int minor;
	struct zdma_dev *zdev = zpdev->zdev;
	dev_t dev;

	spin_lock_init(&zcdev->lock);
	/* new instance? */
	if (!zpdev->major) {
		/* allocate a dynamically allocated char device node */
		int rv = alloc_chrdev_region(&dev, ZDMA_MINOR_BASE,
					ZDMA_MINOR_COUNT, ZDMA_NODE_NAME);

		if (rv) {
			pr_err("unable to allocate cdev region %d.\n", rv);
			return rv;
		}
		zpdev->major = MAJOR(dev);
	}

	/*
	 * do not register yet, create kobjects and name them,
	 */
	zcdev->magic = MAGIC_CHAR;
	zcdev->cdev.owner = THIS_MODULE;
	zcdev->zpdev = zpdev;
	zcdev->zdev = zdev;
	zcdev->engine = engine;
	zcdev->bar = bar;

	rv = config_kobject(zcdev, type);
	if (rv < 0)
		return rv;

	switch (type) {
	case CHAR_USER:
	case CHAR_CTRL:
		/* minor number is type index for non-SGDMA interfaces */
		minor = type;
		cdev_ctrl_init(zcdev);
		break;
	case CHAR_ZDMA_H2C:
		minor = 32 + engine->channel;
		cdev_sgdma_init(zcdev);
		break;
	case CHAR_ZDMA_C2H:
		minor = 36 + engine->channel;
		cdev_sgdma_init(zcdev);
		break;
	case CHAR_EVENTS:
		minor = 10 + bar;
		cdev_event_init(zcdev);
		break;
	default:
		pr_info("type 0x%x NOT supported.\n", type);
		return -EINVAL;
	}
	zcdev->cdevno = MKDEV(zpdev->major, minor);

	/* bring character device live */
	rv = cdev_add(&zcdev->cdev, zcdev->cdevno, 1);
	if (rv < 0) {
		pr_err("cdev_add failed %d, type 0x%x.\n", rv, type);
		goto unregister_region;
	}

	dbg_init("zcdev 0x%p, %u:%u, %s, type 0x%x.\n",
		zcdev, zpdev->major, minor, zcdev->cdev.kobj.name, type);

	/* create device on our class */
	if (g_zdma_class) {
		rv = create_sys_device(zcdev, type);
		if (rv < 0)
			goto del_cdev;
	}

	return 0;

del_cdev:
	cdev_del(&zcdev->cdev);
unregister_region:
	unregister_chrdev_region(zcdev->cdevno, ZDMA_MINOR_COUNT);
	return rv;
}

void zpdev_destroy_interfaces(struct zdma_pci_dev *zpdev)
{
	int i = 0;
	int rv;
#ifdef __ZDMA_SYSFS__
	device_remove_file(&zpdev->pdev->dev, &dev_attr_zdma_dev_instance);
#endif

	if (zpdev_flag_test(zpdev, XDF_CDEV_SG)) {
		/* iterate over channels */
		for (i = 0; i < zpdev->h2c_channel_max; i++) {
			/* remove SG DMA character device */
			rv = destroy_zcdev(&zpdev->sgdma_h2c_cdev[i]);
			if (rv < 0)
				pr_err("Failed to destroy h2c zcdev %d error :0x%x\n",
						i, rv);
		}
		for (i = 0; i < zpdev->c2h_channel_max; i++) {
			rv = destroy_zcdev(&zpdev->sgdma_c2h_cdev[i]);
			if (rv < 0)
				pr_err("Failed to destroy c2h zcdev %d error 0x%x\n",
						i, rv);
		}
	}

	if (zpdev_flag_test(zpdev, XDF_CDEV_EVENT)) {
		for (i = 0; i < zpdev->user_max; i++) {
			rv = destroy_zcdev(&zpdev->events_cdev[i]);
			if (rv < 0)
				pr_err("Failed to destroy cdev event %d error 0x%x\n",
					i, rv);
		}
	}

	/* remove control character device */
	if (zpdev_flag_test(zpdev, XDF_CDEV_CTRL)) {
		rv = destroy_zcdev(&zpdev->ctrl_cdev);
		if (rv < 0)
			pr_err("Failed to destroy cdev ctrl event %d error 0x%x\n",
				i, rv);
	}

	/* remove user character device */
	if (zpdev_flag_test(zpdev, XDF_CDEV_USER)) {
		rv = destroy_zcdev(&zpdev->user_cdev);
		if (rv < 0)
			pr_err("Failed to destroy user cdev %d error 0x%x\n",
				i, rv);
	}

	if (zpdev->major)
		unregister_chrdev_region(
				MKDEV(zpdev->major, ZDMA_MINOR_BASE),
				ZDMA_MINOR_COUNT);
}

int zpdev_create_interfaces(struct zdma_pci_dev *zpdev)
{
	struct zdma_dev *zdev = zpdev->zdev;
	struct zdma_engine *engine;
	int i;
	int rv = 0;

	/* initialize control character device */
	rv = create_zcdev(zpdev, &zpdev->ctrl_cdev, zdev->config_bar_idx,
			NULL, CHAR_CTRL);
	if (rv < 0) {
		pr_err("create_char(ctrl_cdev) failed\n");
		goto fail;
	}
	zpdev_flag_set(zpdev, XDF_CDEV_CTRL);

	/* initialize events character device */
	for (i = 0; i < zpdev->user_max; i++) {
		rv = create_zcdev(zpdev, &zpdev->events_cdev[i], i, NULL,
			CHAR_EVENTS);
		if (rv < 0) {
			pr_err("create char event %d failed, %d.\n", i, rv);
			goto fail;
		}
	}
	zpdev_flag_set(zpdev, XDF_CDEV_EVENT);

	/* iterate over channels */
	for (i = 0; i < zpdev->h2c_channel_max; i++) {
		engine = &zdev->engine_h2c[i];

		if (engine->magic != MAGIC_ENGINE)
			continue;

		rv = create_zcdev(zpdev, &zpdev->sgdma_h2c_cdev[i], i, engine,
				 CHAR_ZDMA_H2C);
		if (rv < 0) {
			pr_err("create char h2c %d failed, %d.\n", i, rv);
			goto fail;
		}
	}

	for (i = 0; i < zpdev->c2h_channel_max; i++) {
		engine = &zdev->engine_c2h[i];

		if (engine->magic != MAGIC_ENGINE)
			continue;

		rv = create_zcdev(zpdev, &zpdev->sgdma_c2h_cdev[i], i, engine,
				 CHAR_ZDMA_C2H);
		if (rv < 0) {
			pr_err("create char c2h %d failed, %d.\n", i, rv);
			goto fail;
		}
	}
	zpdev_flag_set(zpdev, XDF_CDEV_SG);

	/* initialize user character device */
	if (zdev->user_bar_idx >= 0) {
		rv = create_zcdev(zpdev, &zpdev->user_cdev, zdev->user_bar_idx,
			NULL, CHAR_USER);
		if (rv < 0) {
			pr_err("create_char(user_cdev) failed\n");
			goto fail;
		}
		zpdev_flag_set(zpdev, XDF_CDEV_USER);
	}

#ifdef __ZDMA_SYSFS__
	/* sys file */
	rv = device_create_file(&zpdev->pdev->dev,
				&dev_attr_zdma_dev_instance);
	if (rv) {
		pr_err("Failed to create device file\n");
		goto fail;
	}
#endif

	return 0;

fail:
	rv = -1;
	zpdev_destroy_interfaces(zpdev);
	return rv;
}

static char *char_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return NULL;
}

int zdma_cdev_init(void)
{
	g_zdma_class = class_create(THIS_MODULE, ZDMA_NODE_NAME);
	if (IS_ERR(g_zdma_class)) {
		dbg_init(ZDMA_NODE_NAME ": failed to create class");
		return -1;
	}
	g_zdma_class->devnode = char_devnode;

	/* using kmem_cache_create to enable sequential cleanup */
	cdev_cache = kmem_cache_create("cdev_cache",
																 sizeof(struct cdev_async_io),
																 0,
																 SLAB_HWCACHE_ALIGN,
																 NULL);
	if (!cdev_cache) {
		pr_info("memory allocation for cdev_cache failed. OOM\n");
		return -ENOMEM;
	}

	return 0;
}

void zdma_cdev_cleanup(void)
{
	if (cdev_cache)
		kmem_cache_destroy(cdev_cache);

	if (g_zdma_class)
		class_destroy(g_zdma_class);
}

