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

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/aer.h>
/* include early, to verify it depends only on the headers above */
#include "libzdma_api.h"
#include "libzdma.h"
#include "zdma_mod.h"
#include "zdma_cdev.h"
#include "version.h"

#define DRV_MODULE_NAME		"zdma"
#define DRV_MODULE_DESC		"Zendar's Modified Xilinx ZDMA Reference Driver"
#define DRV_MODULE_RELDATE	"Feb. 2020"

static char version[] =
	DRV_MODULE_DESC " " DRV_MODULE_NAME " v" DRV_MODULE_VERSION "\n";

MODULE_AUTHOR("Xilinx, Inc.");
MODULE_DESCRIPTION(DRV_MODULE_DESC);
MODULE_VERSION(DRV_MODULE_VERSION);
MODULE_LICENSE("Dual BSD/GPL");

/* SECTION: Module global variables */
static int zpdev_cnt;

static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(0x10ee, 0x8038), },
	{0,}
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static void zpdev_free(struct zdma_pci_dev *zpdev)
{
	struct zdma_dev *zdev = zpdev->zdev;

	pr_info("zpdev 0x%p, destroy_interfaces, zdev 0x%p.\n", zpdev, zdev);
	zpdev_destroy_interfaces(zpdev);
	zpdev->zdev = NULL;
	pr_info("zpdev 0x%p, zdev 0x%p zdma_device_close.\n", zpdev, zdev);
	zdma_device_close(zpdev->pdev, zdev);
	zpdev_cnt--;

	kfree(zpdev);
}

static struct zdma_pci_dev *zpdev_alloc(struct pci_dev *pdev)
{
	struct zdma_pci_dev *zpdev = kmalloc(sizeof(*zpdev), GFP_KERNEL);

	if (!zpdev)
		return NULL;
	memset(zpdev, 0, sizeof(*zpdev));

	zpdev->magic = MAGIC_DEVICE;
	zpdev->pdev = pdev;
	zpdev->user_max = MAX_USER_IRQ;
	zpdev->h2c_channel_max = ZDMA_CHANNEL_NUM_MAX;
	zpdev->c2h_channel_max = ZDMA_CHANNEL_NUM_MAX;

	zpdev_cnt++;
	return zpdev;
}

static int probe_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int rv = 0;
	struct zdma_pci_dev *zpdev = NULL;
	struct zdma_dev *zdev;
	void *hndl;

	zpdev = zpdev_alloc(pdev);
	if (!zpdev)
		return -ENOMEM;

	hndl = zdma_device_open(DRV_MODULE_NAME, pdev, &zpdev->user_max,
			&zpdev->h2c_channel_max, &zpdev->c2h_channel_max);
	if (!hndl) {
		rv = -EINVAL;
		goto err_out;
	}

	if (zpdev->user_max > MAX_USER_IRQ) {
		pr_err("Maximum users limit reached\n");
		rv = -EINVAL;
		goto err_out;
	}

	if (zpdev->h2c_channel_max > ZDMA_CHANNEL_NUM_MAX) {
		pr_err("Maximun H2C channel limit reached\n");
		rv = -EINVAL;
		goto err_out;
	}

	if (zpdev->c2h_channel_max > ZDMA_CHANNEL_NUM_MAX) {
		pr_err("Maximun C2H channel limit reached\n");
		rv = -EINVAL;
		goto err_out;
	}

	if (!zpdev->h2c_channel_max && !zpdev->c2h_channel_max)
		pr_warn("NO engine found!\n");

	if (zpdev->user_max) {
		u32 mask = (1 << (zpdev->user_max + 1)) - 1;

		rv = zdma_user_isr_enable(hndl, mask);
		if (rv)
			goto err_out;
	}

	/* make sure no duplicate */
	zdev = zdev_find_by_pdev(pdev);
	if (!zdev) {
		pr_warn("NO zdev found!\n");
		rv =  -EINVAL;
		goto err_out;
	}

	if (hndl != zdev) {
		pr_err("zdev handle mismatch\n");
		rv =  -EINVAL;
		goto err_out;
	}

	pr_info("%s zdma%d, pdev 0x%p, zdev 0x%p, 0x%p, usr %d, ch %d,%d.\n",
		dev_name(&pdev->dev), zdev->idx, pdev, zpdev, zdev,
		zpdev->user_max, zpdev->h2c_channel_max,
		zpdev->c2h_channel_max);

	zpdev->zdev = hndl;

	rv = zpdev_create_interfaces(zpdev);
	if (rv)
		goto err_out;

	dev_set_drvdata(&pdev->dev, zpdev);

	return 0;

err_out:
	pr_err("pdev 0x%p, err %d.\n", pdev, rv);
	zpdev_free(zpdev);
	return rv;
}

static void remove_one(struct pci_dev *pdev)
{
	struct zdma_pci_dev *zpdev;

	if (!pdev)
		return;

	zpdev = dev_get_drvdata(&pdev->dev);
	if (!zpdev)
		return;

	pr_info("pdev 0x%p, zdev 0x%p, 0x%p.\n",
		pdev, zpdev, zpdev->zdev);
	zpdev_free(zpdev);

	dev_set_drvdata(&pdev->dev, NULL);
}

static pci_ers_result_t zdma_error_detected(struct pci_dev *pdev,
					pci_channel_state_t state)
{
	struct zdma_pci_dev *zpdev = dev_get_drvdata(&pdev->dev);

	switch (state) {
	case pci_channel_io_normal:
		return PCI_ERS_RESULT_CAN_RECOVER;
	case pci_channel_io_frozen:
		pr_warn("dev 0x%p,0x%p, frozen state error, reset controller\n",
			pdev, zpdev);
		zdma_device_offline(pdev, zpdev->zdev);
		pci_disable_device(pdev);
		return PCI_ERS_RESULT_NEED_RESET;
	case pci_channel_io_perm_failure:
		pr_warn("dev 0x%p,0x%p, failure state error, req. disconnect\n",
			pdev, zpdev);
		return PCI_ERS_RESULT_DISCONNECT;
	}
	return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t zdma_slot_reset(struct pci_dev *pdev)
{
	struct zdma_pci_dev *zpdev = dev_get_drvdata(&pdev->dev);

	pr_info("0x%p restart after slot reset\n", zpdev);
	if (pci_enable_device_mem(pdev)) {
		pr_info("0x%p failed to renable after slot reset\n", zpdev);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	pci_set_master(pdev);
	pci_restore_state(pdev);
	pci_save_state(pdev);
	zdma_device_online(pdev, zpdev->zdev);

	return PCI_ERS_RESULT_RECOVERED;
}

static void zdma_error_resume(struct pci_dev *pdev)
{
	struct zdma_pci_dev *zpdev = dev_get_drvdata(&pdev->dev);

	pr_info("dev 0x%p,0x%p.\n", pdev, zpdev);
	pci_cleanup_aer_uncorrect_error_status(pdev);
}

#if KERNEL_VERSION(4, 13, 0) <= LINUX_VERSION_CODE
static void zdma_reset_prepare(struct pci_dev *pdev)
{
	struct zdma_pci_dev *zpdev = dev_get_drvdata(&pdev->dev);

	pr_info("dev 0x%p,0x%p.\n", pdev, zpdev);
	zdma_device_offline(pdev, zpdev->zdev);
}

static void zdma_reset_done(struct pci_dev *pdev)
{
	struct zdma_pci_dev *zpdev = dev_get_drvdata(&pdev->dev);

	pr_info("dev 0x%p,0x%p.\n", pdev, zpdev);
	zdma_device_online(pdev, zpdev->zdev);
}

#elif KERNEL_VERSION(3, 16, 0) <= LINUX_VERSION_CODE
static void zdma_reset_notify(struct pci_dev *pdev, bool prepare)
{
	struct zdma_pci_dev *zpdev = dev_get_drvdata(&pdev->dev);

	pr_info("dev 0x%p,0x%p, prepare %d.\n", pdev, zpdev, prepare);

	if (prepare)
		zdma_device_offline(pdev, zpdev->zdev);
	else
		zdma_device_online(pdev, zpdev->zdev);
}
#endif

static const struct pci_error_handlers zdma_err_handler = {
	.error_detected	= zdma_error_detected,
	.slot_reset	= zdma_slot_reset,
	.resume		= zdma_error_resume,
#if KERNEL_VERSION(4, 13, 0) <= LINUX_VERSION_CODE
	.reset_prepare	= zdma_reset_prepare,
	.reset_done	= zdma_reset_done,
#elif KERNEL_VERSION(3, 16, 0) <= LINUX_VERSION_CODE
	.reset_notify	= zdma_reset_notify,
#endif
};

static struct pci_driver pci_driver = {
	.name = DRV_MODULE_NAME,
	.id_table = pci_ids,
	.probe = probe_one,
	.remove = remove_one,
	.err_handler = &zdma_err_handler,
};

static int __init zdma_mod_init(void)
{
	int rv;

	pr_info("%s", version);

	if (desc_blen_max > ZDMA_DESC_BLEN_MAX)
		desc_blen_max = ZDMA_DESC_BLEN_MAX;
	pr_info("desc_blen_max: 0x%x/%u, sgdma_timeout: %u sec.\n",
		desc_blen_max, desc_blen_max, sgdma_timeout);

	rv = zdma_cdev_init();
	if (rv < 0)
		return rv;

	return pci_register_driver(&pci_driver);
}

static void __exit zdma_mod_exit(void)
{
	/* unregister this driver from the PCI bus driver */
	dbg_init("pci_unregister_driver.\n");
	pci_unregister_driver(&pci_driver);
	zdma_cdev_cleanup();
}

module_init(zdma_mod_init);
module_exit(zdma_mod_exit);
