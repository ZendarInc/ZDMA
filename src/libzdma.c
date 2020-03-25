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

#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include "libzdma.h"
#include "libzdma_api.h"
#include "cdev_sgdma.h"

/* SECTION: Module licensing */

#ifdef __LIBZDMA_MOD__
#include "version.h"
#define DRV_MODULE_NAME "libzdma"
#define DRV_MODULE_DESC "Xilinx ZDMA Base Driver"
#define DRV_MODULE_RELDATE "Dec. 2019"

static char version[] =
	DRV_MODULE_DESC " " DRV_MODULE_NAME " v" DRV_MODULE_VERSION "\n";

MODULE_AUTHOR("Xilinx, Inc.");
MODULE_DESCRIPTION(DRV_MODULE_DESC);
MODULE_VERSION(DRV_MODULE_VERSION);
MODULE_LICENSE("Dual BSD/GPL");
#endif

extern unsigned int desc_blen_max;

static unsigned int interrupt_mode;
module_param(interrupt_mode, uint, 0644);
MODULE_PARM_DESC(interrupt_mode, "0 - MSI-x , 1 - MSI, 2 - Legacy");

unsigned int desc_blen_max = ZDMA_DESC_BLEN_MAX;
module_param(desc_blen_max, uint, 0644);
MODULE_PARM_DESC(desc_blen_max,
		 "per descriptor max. buffer length, default is (1 << 28) - 1");

#define ZDMA_PERF_NUM_DESC 128

/*
 * zdma device management
 * maintains a list of the zdma devices
 */
static LIST_HEAD(zdev_list);
static DEFINE_MUTEX(zdev_mutex);

static LIST_HEAD(zdev_rcu_list);
static DEFINE_SPINLOCK(zdev_rcu_lock);

#ifndef list_last_entry
#define list_last_entry(ptr, type, member) list_entry((ptr)->prev, type, member)
#endif

static inline void zdev_list_add(struct zdma_dev *zdev)
{
	mutex_lock(&zdev_mutex);
	if (list_empty(&zdev_list))
		zdev->idx = 0;
	else {
		struct zdma_dev *last;

		last = list_last_entry(&zdev_list, struct zdma_dev, list_head);
		zdev->idx = last->idx + 1;
	}
	list_add_tail(&zdev->list_head, &zdev_list);
	mutex_unlock(&zdev_mutex);

	dbg_init("dev %s, zdev 0x%p, zdma idx %d.\n",
		 dev_name(&zdev->pdev->dev), zdev, zdev->idx);

	spin_lock(&zdev_rcu_lock);
	list_add_tail_rcu(&zdev->rcu_node, &zdev_rcu_list);
	spin_unlock(&zdev_rcu_lock);
}

#undef list_last_entry

static inline void zdev_list_remove(struct zdma_dev *zdev)
{
	mutex_lock(&zdev_mutex);
	list_del(&zdev->list_head);
	mutex_unlock(&zdev_mutex);

	spin_lock(&zdev_rcu_lock);
	list_del_rcu(&zdev->rcu_node);
	spin_unlock(&zdev_rcu_lock);
	synchronize_rcu();
}

struct zdma_dev *zdev_find_by_pdev(struct pci_dev *pdev)
{
	struct zdma_dev *zdev, *tmp;

	mutex_lock(&zdev_mutex);
	list_for_each_entry_safe(zdev, tmp, &zdev_list, list_head) {
		if (zdev->pdev == pdev) {
			mutex_unlock(&zdev_mutex);
			return zdev;
		}
	}
	mutex_unlock(&zdev_mutex);
	return NULL;
}
EXPORT_SYMBOL_GPL(zdev_find_by_pdev);

static inline int debug_check_dev_hndl(const char *fname, struct pci_dev *pdev,
							 void *hndl)
{
	struct zdma_dev *zdev;

	if (!pdev)
		return -EINVAL;

	zdev = zdev_find_by_pdev(pdev);
	if (!zdev) {
		pr_info("%s pdev 0x%p, hndl 0x%p, NO match found!\n", fname,
			pdev, hndl);
		return -EINVAL;
	}
	if (zdev != hndl) {
		pr_err("%s pdev 0x%p, hndl 0x%p != 0x%p!\n", fname, pdev, hndl,
					 zdev);
		return -EINVAL;
	}

	return 0;
}

#ifdef __LIBZDMA_DEBUG__
/* SECTION: Function definitions */
inline void __write_register(const char *fn, u32 value, void *iomem,
					 unsigned long off)
{
	pr_err("%s: w reg 0x%lx(0x%p), 0x%x.\n", fn, off, iomem, value);
	iowrite32(value, iomem);
}
#define write_register(v, mem, off) __write_register(__func__, v, mem, off)
#else
#define write_register(v, mem, off) iowrite32(v, mem)
#endif

inline u32 read_register(void *iomem)
{
	return ioread32(iomem);
}

static inline u32 build_u32(u32 hi, u32 lo)
{
	return ((hi & 0xFFFFUL) << 16) | (lo & 0xFFFFUL);
}

static inline u64 build_u64(u64 hi, u64 lo)
{
	return ((hi & 0xFFFFFFFULL) << 32) | (lo & 0xFFFFFFFFULL);
}

static void check_nonzero_interrupt_status(struct zdma_dev *zdev)
{
	struct interrupt_regs *reg =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);
	u32 w;

	w = read_register(&reg->user_int_enable);
	if (w)
		pr_info("%s zdma%d user_int_enable = 0x%08x\n",
			dev_name(&zdev->pdev->dev), zdev->idx, w);

	w = read_register(&reg->channel_int_enable);
	if (w)
		pr_info("%s zdma%d channel_int_enable = 0x%08x\n",
			dev_name(&zdev->pdev->dev), zdev->idx, w);

	w = read_register(&reg->user_int_request);
	if (w)
		pr_info("%s zdma%d user_int_request = 0x%08x\n",
			dev_name(&zdev->pdev->dev), zdev->idx, w);
	w = read_register(&reg->channel_int_request);
	if (w)
		pr_info("%s zdma%d channel_int_request = 0x%08x\n",
			dev_name(&zdev->pdev->dev), zdev->idx, w);

	w = read_register(&reg->user_int_pending);
	if (w)
		pr_info("%s zdma%d user_int_pending = 0x%08x\n",
			dev_name(&zdev->pdev->dev), zdev->idx, w);
	w = read_register(&reg->channel_int_pending);
	if (w)
		pr_info("%s zdma%d channel_int_pending = 0x%08x\n",
			dev_name(&zdev->pdev->dev), zdev->idx, w);
}

/* Disable relaxed ordering */
static void disable_relaxed_ordering(struct zdma_dev *zdev)
{
	struct config_regs *reg =
		(struct config_regs *)(zdev->bar[zdev->config_bar_idx] +
			ZDMA_OFS_CONFIG);
	write_register(0, &reg->pci_control, ZDMA_OFS_CONFIG);
}

/* channel_interrupts_enable -- Enable interrupts we are interested in */
static void channel_interrupts_enable(struct zdma_dev *zdev, u32 mask)
{
	struct interrupt_regs *reg =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);

	write_register(mask, &reg->channel_int_enable_w1s, ZDMA_OFS_INT_CTRL);
}

/* channel_interrupts_disable -- Disable interrupts we not interested in */
static void channel_interrupts_disable(struct zdma_dev *zdev, u32 mask)
{
	struct interrupt_regs *reg =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);

	write_register(mask, &reg->channel_int_enable_w1c, ZDMA_OFS_INT_CTRL);
}

/* user_interrupts_enable -- Enable interrupts we are interested in */
static void user_interrupts_enable(struct zdma_dev *zdev, u32 mask)
{
	struct interrupt_regs *reg =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);

	write_register(mask, &reg->user_int_enable_w1s, ZDMA_OFS_INT_CTRL);
}

/* user_interrupts_disable -- Disable interrupts we not interested in */
static void user_interrupts_disable(struct zdma_dev *zdev, u32 mask)
{
	struct interrupt_regs *reg =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);

	write_register(mask, &reg->user_int_enable_w1c, ZDMA_OFS_INT_CTRL);
}

/* read_interrupts -- Print the interrupt controller status */
static u32 read_interrupts(struct zdma_dev *zdev)
{
	struct interrupt_regs *reg =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);
	u32 lo;
	u32 hi;

	/* extra debugging; inspect complete engine set of registers */
	hi = read_register(&reg->user_int_request);
	dbg_io("ioread32(0x%p) returned 0x%08x (user_int_request).\n",
				 &reg->user_int_request, hi);
	lo = read_register(&reg->channel_int_request);
	dbg_io("ioread32(0x%p) returned 0x%08x (channel_int_request)\n",
				 &reg->channel_int_request, lo);

	/* return interrupts: user in upper 16-bits, channel in lower 16-bits */
	return build_u32(hi, lo);
}

static int engine_reg_dump(struct zdma_engine *engine)
{
	u32 w;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	w = read_register(&engine->regs->identifier);
	pr_info("%s: ioread32(0x%p) = 0x%08x (id).\n", engine->name,
		&engine->regs->identifier, w);
	w &= BLOCK_ID_MASK;
	if (w != BLOCK_ID_HEAD) {
		pr_err("%s: engine id missing, 0x%08x exp. & 0x%x = 0x%x\n",
					 engine->name, w, BLOCK_ID_MASK, BLOCK_ID_HEAD);
		return -EINVAL;
	}
	/* extra debugging; inspect complete engine set of registers */
	w = read_register(&engine->regs->status);
	pr_info("%s: ioread32(0x%p) = 0x%08x (status).\n", engine->name,
		&engine->regs->status, w);
	w = read_register(&engine->regs->control);
	pr_info("%s: ioread32(0x%p) = 0x%08x (control)\n", engine->name,
		&engine->regs->control, w);
	w = read_register(&engine->sgdma_regs->first_desc_lo);
	pr_info("%s: ioread32(0x%p) = 0x%08x (first_desc_lo)\n", engine->name,
		&engine->sgdma_regs->first_desc_lo, w);
	w = read_register(&engine->sgdma_regs->first_desc_hi);
	pr_info("%s: ioread32(0x%p) = 0x%08x (first_desc_hi)\n", engine->name,
		&engine->sgdma_regs->first_desc_hi, w);
	w = read_register(&engine->sgdma_regs->first_desc_adjacent);
	pr_info("%s: ioread32(0x%p) = 0x%08x (first_desc_adjacent).\n",
		engine->name, &engine->sgdma_regs->first_desc_adjacent, w);
	w = read_register(&engine->regs->completed_desc_count);
	pr_info("%s: ioread32(0x%p) = 0x%08x (completed_desc_count).\n",
		engine->name, &engine->regs->completed_desc_count, w);
	w = read_register(&engine->regs->interrupt_enable_mask);
	pr_info("%s: ioread32(0x%p) = 0x%08x (interrupt_enable_mask)\n",
		engine->name, &engine->regs->interrupt_enable_mask, w);

	return 0;
}

static void interrupt_block_dump(struct zdma_dev* zdev)
{
	struct interrupt_regs *irq_regs;
	u32 r;

	BUG_ON(!zdev);

	irq_regs = (struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
							 ZDMA_OFS_INT_CTRL);
	r = read_register(&irq_regs->user_int_enable);
	pr_info("user_int_enable: 0x%08x\n", r);

	r = read_register(&irq_regs->channel_int_enable);
	pr_info("channel_int_enable: 0x%08x\n", r);

	r = read_register(&irq_regs->user_int_request);
	pr_info("user_int_request: 0x%08x\n", r);

	r = read_register(&irq_regs->channel_int_request);
	pr_info("channel_int_request: 0x%08x\n", r);

	r = read_register(&irq_regs->user_int_pending);
	pr_info("user_int_pending: 0x%08x\n", r);

	r = read_register(&irq_regs->channel_int_pending);
	pr_info("channel_int_pending: 0x%08x\n", r);
}

static void engine_status_dump(struct zdma_engine *engine)
{
	u32 v = engine->status;
	char buffer[256];
	char *buf = buffer;
	int len = 0;

	len = sprintf(buf, "SG engine %s status: 0x%08x: ", engine->name, v);

	if ((v & ZDMA_STAT_BUSY))
		len += sprintf(buf + len, "BUSY,");
	if ((v & ZDMA_STAT_DESC_STOPPED))
		len += sprintf(buf + len, "DESC_STOPPED,");
	if ((v & ZDMA_STAT_DESC_COMPLETED))
		len += sprintf(buf + len, "DESC_COMPL,");

	/* common H2C & C2H */
	if ((v & ZDMA_STAT_COMMON_ERR_MASK)) {
		if ((v & ZDMA_STAT_ALIGN_MISMATCH))
			len += sprintf(buf + len, "ALIGN_MISMATCH ");
		if ((v & ZDMA_STAT_MAGIC_STOPPED))
			len += sprintf(buf + len, "MAGIC_STOPPED ");
		if ((v & ZDMA_STAT_INVALID_LEN))
			len += sprintf(buf + len, "INVLIAD_LEN ");
		if ((v & ZDMA_STAT_IDLE_STOPPED))
			len += sprintf(buf + len, "IDLE_STOPPED ");
		buf[len - 1] = ',';
	}

	if (engine->dir == DMA_TO_DEVICE) {
		/* H2C only */
		if ((v & ZDMA_STAT_H2C_R_ERR_MASK)) {
			len += sprintf(buf + len, "R:");
			if ((v & ZDMA_STAT_H2C_R_UNSUPP_REQ))
				len += sprintf(buf + len, "UNSUPP_REQ ");
			if ((v & ZDMA_STAT_H2C_R_COMPL_ABORT))
				len += sprintf(buf + len, "COMPL_ABORT ");
			if ((v & ZDMA_STAT_H2C_R_PARITY_ERR))
				len += sprintf(buf + len, "PARITY ");
			if ((v & ZDMA_STAT_H2C_R_HEADER_EP))
				len += sprintf(buf + len, "HEADER_EP ");
			if ((v & ZDMA_STAT_H2C_R_UNEXP_COMPL))
				len += sprintf(buf + len, "UNEXP_COMPL ");
			buf[len - 1] = ',';
		}

		if ((v & ZDMA_STAT_H2C_W_ERR_MASK)) {
			len += sprintf(buf + len, "W:");
			if ((v & ZDMA_STAT_H2C_W_DECODE_ERR))
				len += sprintf(buf + len, "DECODE_ERR ");
			if ((v & ZDMA_STAT_H2C_W_SLAVE_ERR))
				len += sprintf(buf + len, "SLAVE_ERR ");
			buf[len - 1] = ',';
		}

	} else {
		/* C2H only */
		if ((v & ZDMA_STAT_C2H_R_ERR_MASK)) {
			len += sprintf(buf + len, "R:");
			if ((v & ZDMA_STAT_C2H_R_DECODE_ERR))
				len += sprintf(buf + len, "DECODE_ERR ");
			if ((v & ZDMA_STAT_C2H_R_SLAVE_ERR))
				len += sprintf(buf + len, "SLAVE_ERR ");
			buf[len - 1] = ',';
		}
	}

	/* common H2C & C2H */
	if ((v & ZDMA_STAT_DESC_ERR_MASK)) {
		len += sprintf(buf + len, "DESC_ERR:");
		if ((v & ZDMA_STAT_DESC_UNSUPP_REQ))
			len += sprintf(buf + len, "UNSUPP_REQ ");
		if ((v & ZDMA_STAT_DESC_COMPL_ABORT))
			len += sprintf(buf + len, "COMPL_ABORT ");
		if ((v & ZDMA_STAT_DESC_PARITY_ERR))
			len += sprintf(buf + len, "PARITY ");
		if ((v & ZDMA_STAT_DESC_HEADER_EP))
			len += sprintf(buf + len, "HEADER_EP ");
		if ((v & ZDMA_STAT_DESC_UNEXP_COMPL))
			len += sprintf(buf + len, "UNEXP_COMPL ");
		buf[len - 1] = ',';
	}

	buf[len - 1] = '\0';
	pr_info("%s\n", buffer);
}

/**
 * engine_status_read() - read status of SG DMA engine (optionally reset)
 *
 * Stores status in engine->status.
 *
 * @return error value on failure, 0 otherwise
 */
static int engine_status_read(struct zdma_engine *engine, bool clear, bool dump)
{
	int rv = 0;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	if (dump) {
		rv = engine_reg_dump(engine);
		if (rv < 0) {
			pr_err("Failed to dump register\n");
			return rv;
		}
	}

	/* read status register */
	if (clear)
		engine->status = read_register(&engine->regs->status_rc);
	else
		engine->status = read_register(&engine->regs->status);

	if (dump)
		engine_status_dump(engine);

	return rv;
}

/**
 * zdma_engine_stop() - stop an SG DMA engine
 *
 */
static int zdma_engine_stop(struct zdma_engine *engine)
{
	u32 w;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}
	dbg_tfr("%s(engine=%p)\n", __func__, engine);

	w = 0;
	w |= (u32)ZDMA_CTRL_IE_DESC_ALIGN_MISMATCH;
	w |= (u32)ZDMA_CTRL_IE_MAGIC_STOPPED;
	w |= (u32)ZDMA_CTRL_IE_READ_ERROR;
	w |= (u32)ZDMA_CTRL_IE_DESC_ERROR;

	w |= (u32)ZDMA_CTRL_IE_DESC_STOPPED;
	w |= (u32)ZDMA_CTRL_IE_DESC_COMPLETED;

	dbg_tfr("Stopping SG DMA %s engine; writing 0x%08x to 0x%p.\n",
		engine->name, w, (u32 *)&engine->regs->control);
	write_register(w, &engine->regs->control,
					 (unsigned long)(&engine->regs->control) -
						 (unsigned long)(&engine->regs));
	wmb();
	return 0;
}

static int engine_start_mode_config(struct zdma_engine *engine)
{
	u32 w;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	/* write control register of SG DMA engine */
	w = (u32)ZDMA_CTRL_RUN_STOP;
	w |= (u32)ZDMA_CTRL_IE_READ_ERROR;
	w |= (u32)ZDMA_CTRL_IE_DESC_ERROR;
	w |= (u32)ZDMA_CTRL_IE_DESC_ALIGN_MISMATCH;
	w |= (u32)ZDMA_CTRL_IE_MAGIC_STOPPED;

	w |= (u32)ZDMA_CTRL_IE_DESC_STOPPED;
	w |= (u32)ZDMA_CTRL_IE_DESC_COMPLETED;

	/* set non-incremental addressing mode */
	if (engine->non_incr_addr)
		w |= (u32)ZDMA_CTRL_NON_INCR_ADDR;

	dbg_tfr("iowrite32(0x%08x to 0x%p) (control)\n", w,
		(void *)&engine->regs->control);

	/* start the engine */
	write_register(w, &engine->regs->control,
					 (unsigned long)(&engine->regs->control) -
						 (unsigned long)(&engine->regs));

	wmb();
	return 0;
}

/* Checks whether an adjacent value violates the page boundary */
static int crosses_page(u64 addr, u16 adj)
{
	u64 start_page, end_page, end_addr;

	end_addr = addr + (adj + 1) * sizeof(struct zdma_desc) - 1;
	start_page = addr >> PAGE_SHIFT_X86;
	end_page = end_addr >> PAGE_SHIFT_X86;

	return end_page > start_page;
}

/**
 * engine_start() - start an idle engine with its first transfer on queue
 *
 * The engine will run and process all transfers that are queued using
 * transfer_queue() and thus have their descriptor lists chained.
 *
 * During the run, new transfers will be processed if transfer_queue() has
 * chained the descriptors before the hardware fetches the last descriptor.
 * A transfer that was chained too late will invoke a new run of the engine
 * initiated from the engine_service() routine.
 *
 * The engine must be idle and at least one transfer must be queued.
 * This function does not take locks; the engine spinlock must already be
 * taken.
 *
 */
static struct zdma_transfer *engine_start(struct zdma_engine *engine)
{
	struct zdma_transfer *transfer;
	u32 w;
	int extra_adj = 0;
	int rv;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return NULL;
	}

	/* engine must be idle */
	if (engine->running) {
		pr_info("%s engine is not in idle state to start\n",
			engine->name);
		return NULL;
	}

	/* engine transfer queue must not be empty */
	if (list_empty(&engine->transfer_list)) {
		pr_debug("%s engine transfer queue must not be empty\n",
			 engine->name);
		return NULL;
	}
	/* inspect first transfer queued on the engine */
	transfer = list_entry(engine->transfer_list.next, struct zdma_transfer,
						entry);
	if (!transfer) {
		pr_debug("%s queued transfer must not be empty\n",
			 engine->name);
		return NULL;
	}

	/* engine is no longer shutdown */
	engine->shutdown = ENGINE_SHUTDOWN_NONE;

	dbg_tfr("%s(%s): transfer=0x%p.\n", __func__, engine->name, transfer);

	/* initialize number of descriptors of dequeued transfers */
	engine->desc_dequeued = 0;

	/* write lower 32-bit of bus address of transfer first descriptor */
	w = cpu_to_le32(PCI_DMA_L(transfer->desc_bus));
	dbg_tfr("iowrite32(0x%08x to 0x%p) (first_desc_lo)\n", w,
		(void *)&engine->sgdma_regs->first_desc_lo);
	write_register(w, &engine->sgdma_regs->first_desc_lo,
					 (unsigned long)(&engine->sgdma_regs->first_desc_lo) -
						 (unsigned long)(&engine->sgdma_regs));
	/* write upper 32-bit of bus address of transfer first descriptor */
	w = cpu_to_le32(PCI_DMA_H(transfer->desc_bus));
	dbg_tfr("iowrite32(0x%08x to 0x%p) (first_desc_hi)\n", w,
		(void *)&engine->sgdma_regs->first_desc_hi);
	write_register(w, &engine->sgdma_regs->first_desc_hi,
					 (unsigned long)(&engine->sgdma_regs->first_desc_hi) -
						 (unsigned long)(&engine->sgdma_regs));

	if (transfer->desc_adjacent > 0) {
		u64 next_page_addr;
		next_page_addr =
			((transfer->desc_bus >> PAGE_SHIFT_X86) + 1) <<
				PAGE_SHIFT_X86;
		extra_adj = (next_page_addr - transfer->desc_bus) /
			sizeof (struct zdma_desc) - 1;
		if (extra_adj > transfer->desc_adjacent - 1)
			extra_adj = transfer->desc_adjacent - 1;
		else if (extra_adj > MAX_EXTRA_ADJ)
			extra_adj = MAX_EXTRA_ADJ;
	}

	BUG_ON(crosses_page(transfer->desc_bus, extra_adj));

	dbg_tfr("iowrite32(0x%08x to 0x%p) (first_desc_adjacent)\n", extra_adj,
		(void *)&engine->sgdma_regs->first_desc_adjacent);
	write_register(
		extra_adj, &engine->sgdma_regs->first_desc_adjacent,
		(unsigned long)(&engine->sgdma_regs->first_desc_adjacent) -
			(unsigned long)(&engine->sgdma_regs));

	mmiowb();

	rv = engine_start_mode_config(engine);
	if (rv < 0) {
		pr_err("Failed to start engine mode config\n");
		return NULL;
	}

	rv = engine_status_read(engine, 0, 0);
	if (rv < 0) {
		pr_err("Failed to read engine status\n");
		return NULL;
	}
	dbg_tfr("%s engine 0x%p now running\n", engine->name, engine);
	/* remember the engine is running */
	engine->running = 1;
	return transfer;
}

/**
 * engine_service() - service an SG DMA engine
 *
 * must be called with engine->lock already acquired
 *
 * @engine pointer to struct zdma_engine
 *
 */
static int engine_service_shutdown(struct zdma_engine *engine)
{
	int rv;
	/* if the engine stopped with RUN still asserted, de-assert RUN now */
	dbg_tfr("engine just went idle, resetting RUN_STOP.\n");
	rv = zdma_engine_stop(engine);
	if (rv < 0) {
		pr_err("Failed to stop engine\n");
		return rv;
	}
	engine->running = 0;

	/* awake task on engine's shutdown wait queue */
	wake_up_interruptible(&engine->shutdown_wq);
	return 0;
}

static struct zdma_transfer *engine_transfer_completion(
		struct zdma_engine *engine,
		struct zdma_transfer *transfer)
{
	if (!engine) {
		pr_err("dma engine NULL\n");
		return NULL;
	}

	if (unlikely(!transfer)) {
		pr_info("%s: xfer empty.\n", engine->name);
		return NULL;
	}

	/* synchronous I/O? */
	/* awake task on transfer's wait queue */
	wake_up_interruptible(&transfer->wq);

	/* Send completion notification for Last transfer */
	if (transfer->cb && transfer->last_in_request)
		transfer->cb->io_done((unsigned long)transfer->cb, 0);

	return transfer;
}

static struct zdma_transfer *
engine_service_transfer_list(struct zdma_engine *engine,
					 struct zdma_transfer *transfer,
					 u32 *pdesc_completed)
{
	if (!engine) {
		pr_err("dma engine NULL\n");
		return NULL;
	}

	if (!pdesc_completed) {
		pr_err("%s completed descriptors are null.\n", engine->name);
		return NULL;
	}

	if (unlikely(!transfer)) {
		pr_info("%s xfer empty, pdesc completed %u.\n", engine->name,
			*pdesc_completed);
		return NULL;
	}

	/*
	 * iterate over all the transfers completed by the engine,
	 * except for the last (i.e. use > instead of >=).
	 */
	while (transfer && (*pdesc_completed > transfer->desc_num)) {
		/* remove this transfer from pdesc_completed */
		*pdesc_completed -= transfer->desc_num;
		dbg_tfr("%s engine completed non-cyclic xfer 0x%p (%d desc)\n",
			engine->name, transfer, transfer->desc_num);

		/* remove completed transfer from list */
		list_del(engine->transfer_list.next);
		/* add to dequeued number of descriptors during this run */
		engine->desc_dequeued += transfer->desc_num;
		/* mark transfer as succesfully completed */
		transfer->state = TRANSFER_STATE_COMPLETED;

		/*
		 * Complete transfer - sets transfer to NULL if an async
		 * transfer has completed
		 */
		transfer = engine_transfer_completion(engine, transfer);

		/* if exists, get the next transfer on the list */
		if (!list_empty(&engine->transfer_list)) {
			transfer = list_entry(engine->transfer_list.next,
								struct zdma_transfer, entry);
			dbg_tfr("Non-completed transfer %p\n", transfer);
		} else {
			/* no further transfers? */
			transfer = NULL;
		}
	}

	return transfer;
}

static int engine_err_handle(struct zdma_engine *engine,
					 struct zdma_transfer *transfer, u32 desc_completed)
{
	u32 value;
	int rv = 0;
	/*
	 * The BUSY bit is expected to be clear now but older HW has a race
	 * condition which could cause it to be still set.	If it's set, re-read
	 * and check again.	If it's still set, log the issue.
	 */
	if (engine->status & ZDMA_STAT_BUSY) {
		value = read_register(&engine->regs->status);
		if ((value & ZDMA_STAT_BUSY))
			printk_ratelimited(KERN_INFO "%s has errors but is still BUSY\n",
				engine->name);
	}

	printk_ratelimited(KERN_INFO "%s, s 0x%x, aborted xfer 0x%p, cmpl %d/%d\n",
			engine->name, engine->status, transfer, desc_completed,
			transfer->desc_num);

	/* mark transfer as failed */
	transfer->state = TRANSFER_STATE_FAILED;
	rv = zdma_engine_stop(engine);
	if (rv < 0)
		pr_err("Failed to stop engine\n");
	return rv;
}

static struct zdma_transfer *
engine_service_final_transfer(struct zdma_engine *engine,
						struct zdma_transfer *transfer,
						u32 *pdesc_completed)
{
	if (!engine) {
		pr_err("dma engine NULL\n");
		return NULL;
	}

	if (!pdesc_completed) {
		pr_err("%s completed descriptors are null.\n", engine->name);
		return NULL;
	}

	/* inspect the current transfer */
	if (unlikely(!transfer)) {
		pr_info("%s xfer empty, pdesc completed %u.\n", engine->name,
			*pdesc_completed);
		return NULL;
	}
	if (((engine->dir == DMA_FROM_DEVICE) &&
			 (engine->status & ZDMA_STAT_C2H_ERR_MASK)) ||
			((engine->dir == DMA_TO_DEVICE) &&
			 (engine->status & ZDMA_STAT_H2C_ERR_MASK))) {
		pr_info("engine %s, status error 0x%x.\n", engine->name,
			engine->status);
		engine_status_dump(engine);
		engine_err_handle(engine, transfer, *pdesc_completed);
		goto transfer_del;
	}

	if (engine->status & ZDMA_STAT_BUSY)
		pr_debug("engine %s is unexpectedly busy - ignoring\n",
			 engine->name);

	/* the engine stopped on current transfer? */
	if (*pdesc_completed < transfer->desc_num) {
		transfer->state = TRANSFER_STATE_FAILED;
		pr_info("%s, xfer 0x%p, stopped half-way, %d/%d.\n",
			engine->name, transfer, *pdesc_completed,
			transfer->desc_num);
	} else {
		dbg_tfr("engine %s completed transfer\n", engine->name);
		dbg_tfr("Completed transfer ID = 0x%p\n", transfer);
		dbg_tfr("*pdesc_completed=%d, transfer->desc_num=%d",
			*pdesc_completed, transfer->desc_num);

		/* mark transfer as succesfully completed */
		transfer->state = TRANSFER_STATE_COMPLETED;
	}

transfer_del:
	/* remove completed transfer from list */
	list_del(engine->transfer_list.next);
	/* add to dequeued number of descriptors during this run */
	engine->desc_dequeued += transfer->desc_num;

	/*
	 * Complete transfer - sets transfer to NULL if an asynchronous
	 * transfer has completed
	 */
	transfer = engine_transfer_completion(engine, transfer);

	return transfer;
}

static int engine_service_resume(struct zdma_engine *engine)
{
	struct zdma_transfer *transfer_started;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	/* engine stopped? */
	if (!engine->running) {
		/* in the case of shutdown, let it finish what's in the Q */
		if (!list_empty(&engine->transfer_list)) {
			/* (re)start engine */
			transfer_started = engine_start(engine);
			if (!transfer_started) {
				pr_err("Failed to start dma engine\n");
				return -EINVAL;
			}
			dbg_tfr("re-started %s engine with pending xfer 0x%p\n",
				engine->name, transfer_started);
			/* engine was requested to be shutdown? */
		} else if (engine->shutdown & ENGINE_SHUTDOWN_REQUEST) {
			engine->shutdown |= ENGINE_SHUTDOWN_IDLE;
			/* awake task on engine's shutdown wait queue */
			wake_up_interruptible(&engine->shutdown_wq);
		} else {
			dbg_tfr("no pending transfers, %s engine stays idle.\n",
				engine->name);
		}
	} else {
		/* engine is still running? */
		if (list_empty(&engine->transfer_list)) {
			pr_warn("no queued transfers but %s engine running!\n",
				engine->name);
			WARN_ON(1);
		}
	}
	return 0;
}

/**
 * engine_service() - service an SG DMA engine
 *
 * must be called with engine->lock already acquired
 *
 * @engine pointer to struct zdma_engine
 *
 */
static int engine_service(struct zdma_engine *engine)
{
	struct zdma_transfer *transfer = NULL;
	u32 desc_count = 0;
	int rv = 0;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	/* Service the engine */
	if (!engine->running) {
		dbg_tfr("Engine was not running!!! Clearing status\n");
		rv = engine_status_read(engine, 1, 0);
		if (rv < 0) {
			pr_err("Failed to read engine status\n");
			return rv;
		}
		return 0;
	}

	/*
	 * If called by the ISR or polling detected an error, read and clear
	 * engine status. For polled mode descriptor completion, this read is
	 * unnecessary and is skipped to reduce latency
	 */
	rv = engine_status_read(engine, 1, 0);
	if (rv < 0) {
		pr_err("Failed to read engine status\n");
		return rv;
	}

	/*
	 * engine was running but is no longer busy, or writeback occurred,
	 * shut down
	 */
	if ((engine->running && !(engine->status & ZDMA_STAT_BUSY)) ||
			desc_count != 0)
	{
		rv = engine_service_shutdown(engine);
		if (rv < 0) {
			pr_err("Failed to shutdown engine\n");
			return rv;
		}
	}

	/*
	 * If called from the ISR, or if an error occurred, the descriptor
	 * count will be zero.	In this scenario, read the descriptor count
	 * from HW.
	 */
	desc_count = read_register(&engine->regs->completed_desc_count);
	dbg_tfr("desc_count = %d\n", desc_count);

	/* transfers on queue? */
	if (!list_empty(&engine->transfer_list)) {
		/* pick first transfer on queue (was submitted to the engine) */
		transfer = list_entry(engine->transfer_list.next,
							struct zdma_transfer, entry);

		dbg_tfr("head of queue transfer 0x%p has %d descriptors\n",
			transfer, (int)transfer->desc_num);

		dbg_tfr("Engine completed %d desc, %d not yet dequeued\n",
			(int)desc_count,
			(int)desc_count - engine->desc_dequeued);
	}

	/* account for already dequeued transfers during this engine run */
	desc_count -= engine->desc_dequeued;

	/* Process all but the last transfer */
	transfer = engine_service_transfer_list(engine, transfer, &desc_count);

	/*
	 * Process final transfer - includes checks of number of descriptors to
	 * detect faulty completion
	 */
	transfer = engine_service_final_transfer(engine, transfer, &desc_count);

	/* Restart the engine following the servicing */
	rv = engine_service_resume(engine);
	if (rv < 0)
		pr_err("Failed to resume engine\n");

	return rv;
}

/* engine_service_work */
static void engine_service_work(struct work_struct *work)
{
	struct zdma_engine *engine;
	unsigned long flags;
	int rv;

	engine = container_of(work, struct zdma_engine, work);
	if (engine->magic != MAGIC_ENGINE) {
		pr_err("%s has invalid magic number %lx\n", engine->name,
					 engine->magic);
		return;
	}

	/* lock the engine */
	spin_lock_irqsave(&engine->lock, flags);

	dbg_tfr("engine_service() for %s engine %p\n", engine->name, engine);
	rv = engine_service(engine);
	if (rv < 0) {
		pr_err("Failed to service engine\n");
		goto unlock;
	}

	/* re-enable interrupts for this engine */
	if (engine->zdev->msix_enabled) {
		write_register(
			engine->interrupt_enable_mask_value,
			&engine->regs->interrupt_enable_mask_w1s,
			(unsigned long)(&engine->regs
						 ->interrupt_enable_mask_w1s) -
				(unsigned long)(&engine->regs));
	} else
		channel_interrupts_enable(engine->zdev, engine->irq_bitmask);

	/* unlock the engine */
unlock:
	spin_unlock_irqrestore(&engine->lock, flags);
}

static irqreturn_t user_irq_service(int irq, struct zdma_user_irq *user_irq)
{
	unsigned long flags;

	if (!user_irq) {
		pr_err("Invalid user_irq\n");
		return IRQ_NONE;
	}

	if (user_irq->handler)
		return user_irq->handler(user_irq->user_idx, user_irq->dev);

	spin_lock_irqsave(&(user_irq->events_lock), flags);
	if (!user_irq->events_irq) {
		user_irq->events_irq = 1;
		wake_up_interruptible(&(user_irq->events_wq));
	}
	spin_unlock_irqrestore(&(user_irq->events_lock), flags);

	return IRQ_HANDLED;
}

/*
 * zdma_isr() - Interrupt handler
 *
 * @dev_id pointer to zdma_dev
 */
static irqreturn_t zdma_isr(int irq, void *dev_id)
{
	u32 ch_irq;
	u32 user_irq;
	u32 mask;
	struct zdma_dev *zdev;
	struct interrupt_regs *irq_regs;

	dbg_irq("(irq=%d, dev 0x%p) <<<< ISR.\n", irq, dev_id);
	if (!dev_id) {
		pr_err("Invalid dev_id on irq line %d\n", irq);
		return -IRQ_NONE;
	}
	zdev = (struct zdma_dev *)dev_id;

	if (!zdev) {
		WARN_ON(!zdev);
		dbg_irq("%s(irq=%d) zdev=%p ??\n", __func__, irq, zdev);
		return IRQ_NONE;
	}

	irq_regs = (struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
							 ZDMA_OFS_INT_CTRL);

	/* read channel interrupt requests */
	ch_irq = read_register(&irq_regs->channel_int_request);
	dbg_irq("ch_irq = 0x%08x\n", ch_irq);

	/*
	 * disable all interrupts that fired; these are re-enabled individually
	 * after the causing module has been fully serviced.
	 */
	if (ch_irq)
		channel_interrupts_disable(zdev, ch_irq);

	/* read user interrupts - this read also flushes the above write */
	user_irq = read_register(&irq_regs->user_int_request);
	dbg_irq("user_irq = 0x%08x\n", user_irq);

	if (user_irq) {
		int user = 0;
		u32 mask = 1;
		int max = zdev->user_max;

		for (; user < max && user_irq; user++, mask <<= 1) {
			if (user_irq & mask) {
				user_irq &= ~mask;
				user_irq_service(irq, &zdev->user_irq[user]);
			}
		}
	}

	mask = ch_irq & zdev->mask_irq_h2c;
	if (mask) {
		int channel = 0;
		int max = zdev->h2c_channel_max;

		/* iterate over H2C (PCIe read) */
		for (channel = 0; channel < max && mask; channel++) {
			struct zdma_engine *engine = &zdev->engine_h2c[channel];

			/* engine present and its interrupt fired? */
			if ((engine->irq_bitmask & mask) &&
					(engine->magic == MAGIC_ENGINE)) {
				mask &= ~engine->irq_bitmask;
				dbg_tfr("schedule_work, %s.\n", engine->name);
				schedule_work(&engine->work);
			}
		}
	}

	mask = ch_irq & zdev->mask_irq_c2h;
	if (mask) {
		int channel = 0;
		int max = zdev->c2h_channel_max;

		/* iterate over C2H (PCIe write) */
		for (channel = 0; channel < max && mask; channel++) {
			struct zdma_engine *engine = &zdev->engine_c2h[channel];

			/* engine present and its interrupt fired? */
			if ((engine->irq_bitmask & mask) &&
					(engine->magic == MAGIC_ENGINE)) {
				mask &= ~engine->irq_bitmask;
				dbg_tfr("schedule_work, %s.\n", engine->name);
				schedule_work(&engine->work);
			}
		}
	}

	return IRQ_HANDLED;
}

/*
 * zdma_user_irq() - Interrupt handler for user interrupts in MSI-X mode
 *
 * @dev_id pointer to zdma_dev
 */
static irqreturn_t zdma_user_irq(int irq, void *dev_id)
{
	struct zdma_user_irq *user_irq;

	dbg_irq("(irq=%d) <<<< INTERRUPT SERVICE ROUTINE\n", irq);

	if (!dev_id) {
		pr_err("Invalid dev_id on irq line %d\n", irq);
		return IRQ_NONE;
	}
	user_irq = (struct zdma_user_irq *)dev_id;

	return user_irq_service(irq, user_irq);
}

/*
 * zdma_channel_irq() - Interrupt handler for channel interrupts in MSI-X mode
 *
 * @dev_id pointer to zdma_dev
 */
static irqreturn_t zdma_channel_irq(int irq, void *dev_id)
{
	struct zdma_dev *zdev;
	struct zdma_engine *engine;

	dbg_irq("(irq=%d) <<<< INTERRUPT service ROUTINE\n", irq);
	if (!dev_id) {
		pr_err("Invalid dev_id on irq line %d\n", irq);
		return IRQ_NONE;
	}

	engine = (struct zdma_engine *)dev_id;
	zdev = engine->zdev;
	if (!zdev) {
		WARN_ON(!zdev);
		dbg_irq("%s(irq=%d) zdev=%p ??\n", __func__, irq, zdev);
		return IRQ_NONE;
	}

	/* Disable the interrupt for this engine */
	spin_lock(&engine->lock);
	write_register(
		engine->interrupt_enable_mask_value,
		&engine->regs->interrupt_enable_mask_w1c,
		(unsigned long)(&engine->regs->interrupt_enable_mask_w1c) -
			(unsigned long)(&engine->regs));
	wmb();
	spin_unlock(&engine->lock);
	/* Schedule the bottom half */
	schedule_work(&engine->work);

	return IRQ_HANDLED;
}

/*
 * Unmap the BAR regions that had been mapped earlier using map_bars()
 */
static void unmap_bars(struct zdma_dev *zdev, struct pci_dev *dev)
{
	int i;

	for (i = 0; i < ZDMA_BAR_NUM; i++) {
		/* is this BAR mapped? */
		if (zdev->bar[i]) {
			/* unmap BAR */
			pci_iounmap(dev, zdev->bar[i]);
			/* mark as unmapped */
			zdev->bar[i] = NULL;
		}
	}
}

static int map_single_bar(struct zdma_dev *zdev, struct pci_dev *dev, int idx)
{
	resource_size_t bar_start;
	resource_size_t bar_len;
	resource_size_t map_len;

	bar_start = pci_resource_start(dev, idx);
	bar_len = pci_resource_len(dev, idx);
	map_len = bar_len;

	zdev->bar[idx] = NULL;

	/* do not map BARs with length 0. Note that start MAY be 0! */
	if (!bar_len) {
		//pr_info("BAR #%d is not present - skipping\n", idx);
		return 0;
	}

	/* BAR size exceeds maximum desired mapping? */
	if (bar_len > INT_MAX) {
		pr_info("Limit BAR %d mapping from %llu to %d bytes\n", idx,
			(u64)bar_len, INT_MAX);
		map_len = (resource_size_t)INT_MAX;
	}
	/*
	 * map the full device memory or IO region into kernel virtual
	 * address space
	 */
	dbg_init("BAR%d: %llu bytes to be mapped.\n", idx, (u64)map_len);
	zdev->bar[idx] = pci_iomap(dev, idx, map_len);

	if (!zdev->bar[idx]) {
		pr_info("Could not map BAR %d.\n", idx);
		return -1;
	}

	pr_info("BAR%d at 0x%llx mapped at 0x%p, length=%llu(/%llu)\n", idx,
		(u64)bar_start, zdev->bar[idx], (u64)map_len, (u64)bar_len);

	return (int)map_len;
}

static int is_config_bar(struct zdma_dev *zdev, int idx)
{
	u32 irq_id = 0;
	u32 cfg_id = 0;
	int flag = 0;
	u32 mask = 0xffff0000; /* Compare only ZDMA ID's not Version number */
	struct interrupt_regs *irq_regs =
		(struct interrupt_regs *)(zdev->bar[idx] + ZDMA_OFS_INT_CTRL);
	struct config_regs *cfg_regs =
		(struct config_regs *)(zdev->bar[idx] + ZDMA_OFS_CONFIG);

	irq_id = read_register(&irq_regs->identifier);
	cfg_id = read_register(&cfg_regs->identifier);

	if (((irq_id & mask) == IRQ_BLOCK_ID) &&
			((cfg_id & mask) == CONFIG_BLOCK_ID)) {
		dbg_init("BAR %d is the ZDMA config BAR\n", idx);
		flag = 1;
	} else {
		dbg_init("BAR %d is NOT the ZDMA config BAR: 0x%x, 0x%x.\n",
			 idx, irq_id, cfg_id);
		flag = 0;
	}

	return flag;
}

#ifndef ZDMA_CONFIG_BAR_NUM
static int identify_bars(struct zdma_dev *zdev, int *bar_id_list, int num_bars,
			 int config_bar_pos)
{
	/*
	 * The following logic identifies which BARs contain what functionality
	 * based on the position of the ZDMA config BAR and the number of BARs
	 * detected. The rules are that the user logic and bypass logic BARs
	 * are optional.	When both are present, the ZDMA config BAR will be the
	 * 2nd BAR detected (config_bar_pos = 1), with the user logic being
	 * detected first and the bypass being detected last. When one is
	 * omitted, the type of BAR present can be identified by whether the
	 * ZDMA config BAR is detected first or last.	When both are omitted,
	 * only the ZDMA config BAR is present.	This somewhat convoluted
	 * approach is used instead of relying on BAR numbers in order to work
	 * correctly with both 32-bit and 64-bit BARs.
	 */

	if (!zdev) {
		pr_err("Invalid zdev\n");
		return -EINVAL;
	}

	if (!bar_id_list) {
		pr_err("Invalid bar id list.\n");
		return -EINVAL;
	}

	dbg_init("zdev 0x%p, bars %d, config at %d.\n", zdev, num_bars,
		 config_bar_pos);

	switch (num_bars) {
	case 1:
		/* Only one BAR present - no extra work necessary */
		break;

	case 2:
		if (config_bar_pos == 0) {
			zdev->bypass_bar_idx = bar_id_list[1];
		} else if (config_bar_pos == 1) {
			zdev->user_bar_idx = bar_id_list[0];
		} else {
			pr_info("2, ZDMA config BAR unexpected %d.\n",
				config_bar_pos);
		}
		break;

	case 3:
	case 4:
		if ((config_bar_pos == 1) || (config_bar_pos == 2)) {
			/* user bar at bar #0 */
			zdev->user_bar_idx = bar_id_list[0];
			/* bypass bar at the last bar */
			zdev->bypass_bar_idx = bar_id_list[num_bars - 1];
		} else {
			pr_info("3/4, ZDMA config BAR unexpected %d.\n",
				config_bar_pos);
		}
		break;

	default:
		/* Should not occur - warn user but safe to continue */
		pr_info("Unexpected # BARs (%d), ZDMA config BAR only.\n",
			num_bars);
		break;
	}
	pr_info("%d BARs: config %d, user %d, bypass %d.\n", num_bars,
		config_bar_pos, zdev->user_bar_idx, zdev->bypass_bar_idx);
	return 0;
}
#endif

/* map_bars() -- map device regions into kernel virtual address space
 *
 * Map the device memory regions into kernel virtual address space after
 * verifying their sizes respect the minimum sizes needed
 */
static int map_bars(struct zdma_dev *zdev, struct pci_dev *dev)
{
	int rv;

#ifdef ZDMA_CONFIG_BAR_NUM
	rv = map_single_bar(zdev, dev, ZDMA_CONFIG_BAR_NUM);
	if (rv <= 0) {
		pr_info("%s, map config bar %d failed, %d.\n",
			dev_name(&dev->dev), ZDMA_CONFIG_BAR_NUM, rv);
		return -EINVAL;
	}

	if (is_config_bar(zdev, ZDMA_CONFIG_BAR_NUM) == 0) {
		pr_info("%s, unable to identify config bar %d.\n",
			dev_name(&dev->dev), ZDMA_CONFIG_BAR_NUM);
		return -EINVAL;
	}
	zdev->config_bar_idx = ZDMA_CONFIG_BAR_NUM;

	return 0;
#else
	int i;
	int bar_id_list[ZDMA_BAR_NUM];
	int bar_id_idx = 0;
	int config_bar_pos = 0;

	/* iterate through all the BARs */
	for (i = 0; i < ZDMA_BAR_NUM; i++) {
		int bar_len;

		bar_len = map_single_bar(zdev, dev, i);
		if (bar_len == 0) {
			continue;
		} else if (bar_len < 0) {
			rv = -EINVAL;
			goto fail;
		}

		/* Try to identify BAR as ZDMA control BAR */
		if ((bar_len >= ZDMA_BAR_SIZE) && (zdev->config_bar_idx < 0)) {
			if (is_config_bar(zdev, i)) {
				zdev->config_bar_idx = i;
				config_bar_pos = bar_id_idx;
				pr_info("config bar %d, pos %d.\n",
					zdev->config_bar_idx, config_bar_pos);
			}
		}

		bar_id_list[bar_id_idx] = i;
		bar_id_idx++;
	}

	/* The ZDMA config BAR must always be present */
	if (zdev->config_bar_idx < 0) {
		pr_info("Failed to detect ZDMA config BAR\n");
		rv = -EINVAL;
		goto fail;
	}

	rv = identify_bars(zdev, bar_id_list, bar_id_idx, config_bar_pos);
	if (rv < 0) {
		pr_err("Failed to identify bars\n");
		return rv;
	}

	/* successfully mapped all required BAR regions */
	return 0;

fail:
	/* unwind; unmap any BARs that we did map */
	unmap_bars(zdev, dev);
	return rv;
#endif
}

/*
 * MSI-X interrupt:
 *	<h2c+c2h channel_max> vectors, followed by <user_max> vectors
 */

/*
 * RTO - code to detect if MSI/MSI-X capability exists is derived
 * from linux/pci/msi.c - pci_msi_check_device
 */

#ifndef arch_msi_check_device
static int arch_msi_check_device(struct pci_dev *dev, int nvec, int type)
{
	return 0;
}
#endif

/* type = PCI_CAP_ID_MSI or PCI_CAP_ID_MSIX */
static int msi_msix_capable(struct pci_dev *dev, int type)
{
	struct pci_bus *bus;
	int ret;

	if (!dev || dev->no_msi)
		return 0;

	for (bus = dev->bus; bus; bus = bus->parent)
		if (bus->bus_flags & PCI_BUS_FLAGS_NO_MSI)
			return 0;

	ret = arch_msi_check_device(dev, 1, type);
	if (ret)
		return 0;

	if (!pci_find_capability(dev, type))
		return 0;

	return 1;
}

static void disable_msi_msix(struct zdma_dev *zdev, struct pci_dev *pdev)
{
	if (zdev->msix_enabled) {
		pci_disable_msix(pdev);
		zdev->msix_enabled = 0;
	} else if (zdev->msi_enabled) {
		pci_disable_msi(pdev);
		zdev->msi_enabled = 0;
	}
}

static int enable_msi_msix(struct zdma_dev *zdev, struct pci_dev *pdev)
{
	int rv = 0;

	if (!zdev) {
		pr_err("Invalid zdev\n");
		return -EINVAL;
	}

	if (!pdev) {
		pr_err("Invalid pdev\n");
		return -EINVAL;
	}

	if (!interrupt_mode && msi_msix_capable(pdev, PCI_CAP_ID_MSIX)) {
		int req_nvec = zdev->c2h_channel_max + zdev->h2c_channel_max +
						 zdev->user_max;

#if KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE
		dbg_init("Enabling MSI-X\n");
		rv = pci_alloc_irq_vectors(pdev, req_nvec, req_nvec,
						 PCI_IRQ_MSIX);
#else
		int i;

		dbg_init("Enabling MSI-X\n");
		for (i = 0; i < req_nvec; i++)
			zdev->entry[i].entry = i;

		rv = pci_enable_msix(pdev, zdev->entry, req_nvec);
#endif
		if (rv < 0)
			dbg_init("Couldn't enable MSI-X mode: %d\n", rv);

		zdev->msix_enabled = 1;

	} else if (interrupt_mode == 1 &&
			 msi_msix_capable(pdev, PCI_CAP_ID_MSI)) {
		/* enable message signalled interrupts */
		dbg_init("pci_enable_msi()\n");
		rv = pci_enable_msi(pdev);
		if (rv < 0)
			dbg_init("Couldn't enable MSI mode: %d\n", rv);
		zdev->msi_enabled = 1;

	} else {
		dbg_init("MSI/MSI-X not detected - using legacy interrupts\n");
	}

	return rv;
}

static void pci_check_intr_pend(struct pci_dev *pdev)
{
	u16 v;

	pci_read_config_word(pdev, PCI_STATUS, &v);
	if (v & PCI_STATUS_INTERRUPT) {
		pr_info("%s PCI STATUS Interrupt pending 0x%x.\n",
			dev_name(&pdev->dev), v);
		pci_write_config_word(pdev, PCI_STATUS, PCI_STATUS_INTERRUPT);
	}
}

static void pci_keep_intx_enabled(struct pci_dev *pdev)
{
	/* workaround to a h/w bug:
	 * when msix/msi become unavaile, default to legacy.
	 * However the legacy enable was not checked.
	 * If the legacy was disabled, no ack then everything stuck
	 */
	u16 pcmd, pcmd_new;

	pci_read_config_word(pdev, PCI_COMMAND, &pcmd);
	pcmd_new = pcmd & ~PCI_COMMAND_INTX_DISABLE;
	if (pcmd_new != pcmd) {
		pr_info("%s: clear INTX_DISABLE, 0x%x -> 0x%x.\n",
			dev_name(&pdev->dev), pcmd, pcmd_new);
		pci_write_config_word(pdev, PCI_COMMAND, pcmd_new);
	}
}

static void prog_irq_msix_user(struct zdma_dev *zdev, bool clear)
{
	/* user */
	struct interrupt_regs *int_regs =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);
	u32 i = zdev->c2h_channel_max + zdev->h2c_channel_max;
	u32 max = i + zdev->user_max;
	int j;

	for (j = 0; i < max; j++) {
		u32 val = 0;
		int k;
		int shift = 0;

		if (clear)
			i += 4;
		else
			for (k = 0; k < 4 && i < max; i++, k++, shift += 8)
				val |= (i & 0x1f) << shift;

		write_register(
			val, &int_regs->user_msi_vector[j],
			ZDMA_OFS_INT_CTRL +
				((unsigned long)&int_regs->user_msi_vector[j] -
				 (unsigned long)int_regs));

		dbg_init("vector %d, 0x%x.\n", j, val);
	}
}

static void prog_irq_msix_channel(struct zdma_dev *zdev, bool clear)
{
	struct interrupt_regs *int_regs =
		(struct interrupt_regs *)(zdev->bar[zdev->config_bar_idx] +
						ZDMA_OFS_INT_CTRL);
	u32 max = zdev->c2h_channel_max + zdev->h2c_channel_max;
	u32 i;
	int j;

	/* engine */
	for (i = 0, j = 0; i < max; j++) {
		u32 val = 0;
		int k;
		int shift = 0;

		if (clear)
			i += 4;
		else
			for (k = 0; k < 4 && i < max; i++, k++, shift += 8)
				val |= (i & 0x1f) << shift;

		write_register(val, &int_regs->channel_msi_vector[j],
						 ZDMA_OFS_INT_CTRL +
							 ((unsigned long)&int_regs
						->channel_msi_vector[j] -
					(unsigned long)int_regs));
		dbg_init("vector %d, 0x%x.\n", j, val);
	}
}

static void irq_msix_channel_teardown(struct zdma_dev *zdev)
{
	struct zdma_engine *engine;
	int j = 0;
	int i = 0;

	if (!zdev->msix_enabled)
		return;

	prog_irq_msix_channel(zdev, 1);

	engine = zdev->engine_h2c;
	for (i = 0; i < zdev->h2c_channel_max; i++, j++, engine++) {
		if (!engine->msix_irq_line)
			break;
		dbg_sg("Release IRQ#%d for engine %p\n", engine->msix_irq_line,
					 engine);
		free_irq(engine->msix_irq_line, engine);
	}

	engine = zdev->engine_c2h;
	for (i = 0; i < zdev->c2h_channel_max; i++, j++, engine++) {
		if (!engine->msix_irq_line)
			break;
		dbg_sg("Release IRQ#%d for engine %p\n", engine->msix_irq_line,
					 engine);
		free_irq(engine->msix_irq_line, engine);
	}
}

static int irq_msix_channel_setup(struct zdma_dev *zdev)
{
	int i;
	int j;
	int rv = 0;
	u32 vector;
	struct zdma_engine *engine;

	if (!zdev) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	if (!zdev->msix_enabled)
		return 0;

	j = zdev->h2c_channel_max;
	engine = zdev->engine_h2c;
	for (i = 0; i < zdev->h2c_channel_max; i++, engine++) {
#if KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE
		vector = pci_irq_vector(zdev->pdev, i);
#else
		vector = zdev->entry[i].vector;
#endif
		rv = request_irq(vector, zdma_channel_irq, 0, zdev->mod_name,
				 engine);
		if (rv) {
			pr_info("requesti irq#%d failed %d, engine %s.\n",
				vector, rv, engine->name);
			return rv;
		}
		pr_info("engine %s, irq#%d.\n", engine->name, vector);
		engine->msix_irq_line = vector;
	}

	engine = zdev->engine_c2h;
	for (i = 0; i < zdev->c2h_channel_max; i++, j++, engine++) {
#if KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE
		vector = pci_irq_vector(zdev->pdev, j);
#else
		vector = zdev->entry[j].vector;
#endif
		rv = request_irq(vector, zdma_channel_irq, 0, zdev->mod_name,
				 engine);
		if (rv) {
			pr_info("requesti irq#%d failed %d, engine %s.\n",
				vector, rv, engine->name);
			return rv;
		}
		pr_info("engine %s, irq#%d.\n", engine->name, vector);
		engine->msix_irq_line = vector;
	}

	return 0;
}

static void irq_msix_user_teardown(struct zdma_dev *zdev)
{
	int i;
	int j;

	if (!zdev) {
		pr_err("Invalid zdev\n");
		return;
	}

	if (!zdev->msix_enabled)
		return;

	j = zdev->h2c_channel_max + zdev->c2h_channel_max;

	prog_irq_msix_user(zdev, 1);

	for (i = 0; i < zdev->user_max; i++, j++) {
#if KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE
		u32 vector = pci_irq_vector(zdev->pdev, j);
#else
		u32 vector = zdev->entry[j].vector;
#endif
		dbg_init("user %d, releasing IRQ#%d\n", i, vector);
		free_irq(vector, &zdev->user_irq[i]);
	}
}

static int irq_msix_user_setup(struct zdma_dev *zdev)
{
	int i;
	int j = zdev->h2c_channel_max + zdev->c2h_channel_max;
	int rv = 0;

	/* vectors set in probe_scan_for_msi() */
	for (i = 0; i < zdev->user_max; i++, j++) {
#if KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE
		u32 vector = pci_irq_vector(zdev->pdev, j);
#else
		u32 vector = zdev->entry[j].vector;
#endif
		rv = request_irq(vector, zdma_user_irq, 0, zdev->mod_name,
				 &zdev->user_irq[i]);
		if (rv) {
			pr_info("user %d couldn't use IRQ#%d, %d\n", i, vector,
				rv);
			break;
		}
		pr_info("%d-USR-%d, IRQ#%d with 0x%p\n", zdev->idx, i, vector,
			&zdev->user_irq[i]);
	}

	/* If any errors occur, free IRQs that were successfully requested */
	if (rv) {
		for (i--, j--; i >= 0; i--, j--) {
#if KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE
			u32 vector = pci_irq_vector(zdev->pdev, j);
#else
			u32 vector = zdev->entry[j].vector;
#endif
			free_irq(vector, &zdev->user_irq[i]);
		}
	}

	return rv;
}

static int irq_msi_setup(struct zdma_dev *zdev, struct pci_dev *pdev)
{
	int rv;

	zdev->irq_line = (int)pdev->irq;
	rv = request_irq(pdev->irq, zdma_isr, 0, zdev->mod_name, zdev);
	if (rv)
		dbg_init("Couldn't use IRQ#%d, %d\n", pdev->irq, rv);
	else
		dbg_init("Using IRQ#%d with 0x%p\n", pdev->irq, zdev);

	return rv;
}

static int irq_legacy_setup(struct zdma_dev *zdev, struct pci_dev *pdev)
{
	u32 w;
	u8 val;
	void *reg;
	int rv;

	pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &val);
	dbg_init("Legacy Interrupt register value = %d\n", val);
	if (val > 1) {
		val--;
		w = (val << 24) | (val << 16) | (val << 8) | val;
		/* Program IRQ Block Channel vactor and IRQ Block User vector
		 * with Legacy interrupt value
		 */
		reg = zdev->bar[zdev->config_bar_idx] + 0x2080; // IRQ user
		write_register(w, reg, 0x2080);
		write_register(w, reg + 0x4, 0x2084);
		write_register(w, reg + 0x8, 0x2088);
		write_register(w, reg + 0xC, 0x208C);
		reg = zdev->bar[zdev->config_bar_idx] + 0x20A0; // IRQ Block
		write_register(w, reg, 0x20A0);
		write_register(w, reg + 0x4, 0x20A4);
	}

	zdev->irq_line = (int)pdev->irq;
	rv = request_irq(pdev->irq, zdma_isr, IRQF_SHARED, zdev->mod_name,
			 zdev);
	if (rv)
		dbg_init("Couldn't use IRQ#%d, %d\n", pdev->irq, rv);
	else
		dbg_init("Using IRQ#%d with 0x%p\n", pdev->irq, zdev);

	return rv;
}

static void irq_teardown(struct zdma_dev *zdev)
{
	if (zdev->msix_enabled) {
		irq_msix_channel_teardown(zdev);
		irq_msix_user_teardown(zdev);
	} else if (zdev->irq_line != -1) {
		dbg_init("Releasing IRQ#%d\n", zdev->irq_line);
		free_irq(zdev->irq_line, zdev);
	}
}

static int irq_setup(struct zdma_dev *zdev, struct pci_dev *pdev)
{
	pci_keep_intx_enabled(pdev);

	if (zdev->msix_enabled) {
		int rv = irq_msix_channel_setup(zdev);

		if (rv)
			return rv;
		rv = irq_msix_user_setup(zdev);
		if (rv)
			return rv;
		prog_irq_msix_channel(zdev, 0);
		prog_irq_msix_user(zdev, 0);

		return 0;
	} else if (zdev->msi_enabled)
		return irq_msi_setup(zdev, pdev);

	return irq_legacy_setup(zdev, pdev);
}

#ifdef __LIBZDMA_DEBUG__
static void dump_desc(struct zdma_desc *desc_virt)
{
	int j;
	u32 *p = (u32 *)desc_virt;
	static char *const field_name[] = { "magic|extra_adjacent|control",
							"bytes",
							"src_addr_lo",
							"src_addr_hi",
							"dst_addr_lo",
							"dst_addr_hi",
							"next_addr",
							"next_addr_pad" };
	char *dummy;

	/* remove warning about unused variable when debug printing is off */
	dummy = field_name[0];

	for (j = 0; j < 8; j += 1) {
		pr_info("0x%08lx/0x%02lx: 0x%08x %s\n", (uintptr_t)p,
			(uintptr_t)p & 15, (int)*p, field_name[j]);
		p++;
	}
	pr_info("\n");
}

static void transfer_dump(struct zdma_transfer *transfer)
{
	int i;
	struct zdma_desc *desc_virt = transfer->desc_virt;

	pr_info("xfer 0x%p, state 0x%x, f 0x%x, dir %d, len %u, last %d.\n",
		transfer, transfer->state, transfer->flags, transfer->dir,
		transfer->len, transfer->last_in_request);

	pr_info("transfer 0x%p, desc %d, bus 0x%llx, adj %d.\n", transfer,
		transfer->desc_num, (u64)transfer->desc_bus,
		transfer->desc_adjacent);
	for (i = 0; i < transfer->desc_num; i += 1)
		dump_desc(desc_virt + i);
}
#endif /* __LIBZDMA_DEBUG__ */

/* transfer_desc_init() - Chains the descriptors as a singly-linked list
 *
 * Each descriptor's next * pointer specifies the bus address
 * of the next descriptor.
 * Terminates the last descriptor to form a singly-linked list
 *
 * @transfer Pointer to SG DMA transfers
 * @count Number of descriptors allocated in continuous PCI bus addressable
 * memory
 *
 * @return 0 on success, EINVAL on failure
 */
static int transfer_desc_init(struct zdma_transfer *transfer, int count)
{
	struct zdma_desc *desc_virt = transfer->desc_virt;
	dma_addr_t desc_bus = transfer->desc_bus;
	int i;
	int adj = count - 1;
	int extra_adj;
	u32 temp_control;

	if (count > ZDMA_TRANSFER_MAX_DESC) {
		pr_err("Engine cannot transfer more than %d descriptors\n",
					 ZDMA_TRANSFER_MAX_DESC);
		return -EINVAL;
	}

	/* create singly-linked list for SG DMA controller */
	for (i = 0; i < count - 1; i++) {
		/* increment bus address to next in array */
		desc_bus += sizeof(struct zdma_desc);

		/* singly-linked list uses bus addresses */
		desc_virt[i].next_lo = cpu_to_le32(PCI_DMA_L(desc_bus));
		desc_virt[i].next_hi = cpu_to_le32(PCI_DMA_H(desc_bus));
		desc_virt[i].bytes = cpu_to_le32(0);

		/* any adjacent descriptors? */
		if (adj > 0) {
			extra_adj = adj - 1;
			if (extra_adj > MAX_EXTRA_ADJ)
				extra_adj = MAX_EXTRA_ADJ;

			adj--;
		} else {
			extra_adj = 0;
		}

		temp_control = DESC_MAGIC | (extra_adj << 8);

		desc_virt[i].control = cpu_to_le32(temp_control);
	}
	/* { i = number - 1 } */
	/* zero the last descriptor next pointer */
	desc_virt[i].next_lo = cpu_to_le32(0);
	desc_virt[i].next_hi = cpu_to_le32(0);
	desc_virt[i].bytes = cpu_to_le32(0);

	temp_control = DESC_MAGIC;

	desc_virt[i].control = cpu_to_le32(temp_control);

	return 0;
}

/* zdma_desc_adjacent -- Set how many descriptors are adjacent to this one */
static void zdma_desc_adjacent(struct zdma_desc *desc, int next_adjacent)
{
	int extra_adj = 0;
	/* remember reserved and control bits */
	u32 control = le32_to_cpu(desc->control) & 0x0000c0ffUL;
	u32 max_adj_page = 0;

	if (next_adjacent > 0) {
		extra_adj = next_adjacent - 1;
		if (extra_adj > MAX_EXTRA_ADJ)
			extra_adj = MAX_EXTRA_ADJ;
		max_adj_page = (PAGE_SIZE_X86 - (le32_to_cpu(desc->next_lo) &
			PAGE_MASK_X86)) / sizeof(struct zdma_desc) - 1;
		if (extra_adj > max_adj_page)
			extra_adj = max_adj_page;
		if (extra_adj < 0) {
			pr_warn("extra_adj<0, converting it to 0\n");
			extra_adj = 0;
		}
	}
	/* merge adjacent and control field */
	control |= DESC_MAGIC | (extra_adj << 8);
	/* write control and next_adjacent */
	desc->control = cpu_to_le32(control);
}

/* zdma_desc_control -- Set complete control field of a descriptor. */
static int zdma_desc_control_set(struct zdma_desc *first, u32 control_field)
{
	/* remember magic and adjacent number */
	u32 control = le32_to_cpu(first->control) & ~(LS_BYTE_MASK);

	if (control_field & ~(LS_BYTE_MASK)) {
		pr_err("Invalid control field\n");
		return -EINVAL;
	}
	/* merge adjacent and control field */
	control |= control_field;
	/* write control and next_adjacent */
	first->control = cpu_to_le32(control);
	return 0;
}

/* zdma_desc_done - recycle cache-coherent linked list of descriptors.
 *
 * @dev Pointer to pci_dev
 * @number Number of descriptors to be allocated
 * @desc_virt Pointer to (i.e. virtual address of) first descriptor in list
 * @desc_bus Bus address of first descriptor in list
 */
static inline void zdma_desc_done(struct zdma_desc *desc_virt, int count)
{
	memset(desc_virt, 0, count * sizeof(struct zdma_desc));
}

/* zdma_desc() - Fill a descriptor with the transfer details
 *
 * @desc pointer to descriptor to be filled
 * @addr root complex address
 * @ep_addr end point address
 * @len number of bytes, must be a (non-negative) multiple of 4.
 * @dir, dma direction
 * is the end point address. If zero, vice versa.
 *
 * Does not modify the next pointer
 */
static void zdma_desc_set(struct zdma_desc *desc, dma_addr_t rc_bus_addr,
				u64 ep_addr, int len, int dir)
{
	/* transfer length */
	desc->bytes = cpu_to_le32(len);
	if (dir == DMA_TO_DEVICE) {
		/* read from root complex memory (source address) */
		desc->src_addr_lo = cpu_to_le32(PCI_DMA_L(rc_bus_addr));
		desc->src_addr_hi = cpu_to_le32(PCI_DMA_H(rc_bus_addr));
		/* write to end point address (destination address) */
		desc->dst_addr_lo = cpu_to_le32(PCI_DMA_L(ep_addr));
		desc->dst_addr_hi = cpu_to_le32(PCI_DMA_H(ep_addr));
	} else {
		/* read from end point address (source address) */
		desc->src_addr_lo = cpu_to_le32(PCI_DMA_L(ep_addr));
		desc->src_addr_hi = cpu_to_le32(PCI_DMA_H(ep_addr));
		/* write to root complex memory (destination address) */
		desc->dst_addr_lo = cpu_to_le32(PCI_DMA_L(rc_bus_addr));
		desc->dst_addr_hi = cpu_to_le32(PCI_DMA_H(rc_bus_addr));
	}
}

/*
 * should hold the engine->lock;
 */
static int transfer_abort(struct zdma_engine *engine,
				struct zdma_transfer *transfer)
{
	struct zdma_transfer *head;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	if (!transfer) {
		pr_err("Invalid DMA transfer\n");
		return -EINVAL;
	}

	if (transfer->desc_num == 0) {
		pr_err("%s void descriptors in the transfer list\n",
					 engine->name);
		return -EINVAL;
	}

	pr_info("abort transfer 0x%p, desc %d, engine desc queued %d.\n",
		transfer, transfer->desc_num, engine->desc_dequeued);

	head = list_entry(engine->transfer_list.next, struct zdma_transfer,
				entry);
	if (head == transfer)
		list_del(engine->transfer_list.next);
	else
		pr_info("engine %s, transfer 0x%p NOT found, 0x%p.\n",
			engine->name, transfer, head);

	if (transfer->state == TRANSFER_STATE_SUBMITTED)
		transfer->state = TRANSFER_STATE_ABORTED;
	return 0;
}

/* transfer_queue() - Queue a DMA transfer on the engine
 *
 * @engine DMA engine doing the transfer
 * @transfer DMA transfer submitted to the engine
 *
 * Takes and releases the engine spinlock
 */
static int transfer_queue(struct zdma_engine *engine,
				struct zdma_transfer *transfer)
{
	int rv = 0;
	struct zdma_transfer *transfer_started;
	struct zdma_dev *zdev;
	unsigned long flags;

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	if (!engine->zdev) {
		pr_err("Invalid zdev\n");
		return -EINVAL;
	}

	if (!transfer) {
		pr_err("%s Invalid DMA transfer\n", engine->name);
		return -EINVAL;
	}

	if (transfer->desc_num == 0) {
		pr_err("%s void descriptors in the transfer list\n",
					 engine->name);
		return -EINVAL;
	}
	dbg_tfr("%s (transfer=0x%p).\n", __func__, transfer);

	zdev = engine->zdev;
	if (zdma_device_flag_check(zdev, XDEV_FLAG_OFFLINE)) {
		pr_info("dev 0x%p offline, transfer 0x%p not queued.\n", zdev,
			transfer);
		return -EBUSY;
	}

	/* lock the engine state */
	spin_lock_irqsave(&engine->lock, flags);

	/* engine is being shutdown; do not accept new transfers */
	if (engine->shutdown & ENGINE_SHUTDOWN_REQUEST) {
		pr_info("engine %s offline, transfer 0x%p not queued.\n",
			engine->name, transfer);
		rv = -EBUSY;
		goto shutdown;
	}

	/* mark the transfer as submitted */
	transfer->state = TRANSFER_STATE_SUBMITTED;
	/* add transfer to the tail of the engine transfer queue */
	list_add_tail(&transfer->entry, &engine->transfer_list);

	/* engine is idle? */
	if (!engine->running) {
		/* start engine */
		dbg_tfr("%s(): starting %s engine.\n", __func__, engine->name);
		transfer_started = engine_start(engine);
		if (!transfer_started) {
			pr_err("Failed to start dma engine\n");
			goto shutdown;
		}
		dbg_tfr("transfer=0x%p started %s engine with transfer 0x%p.\n",
			transfer, engine->name, transfer_started);
	} else {
		dbg_tfr("transfer=0x%p queued, with %s engine running.\n",
			transfer, engine->name);
	}

shutdown:
	/* unlock the engine state */
	dbg_tfr("engine->running = %d\n", engine->running);
	spin_unlock_irqrestore(&engine->lock, flags);
	return rv;
}

static void engine_alignments(struct zdma_engine *engine)
{
	u32 w;
	u32 align_bytes;
	u32 granularity_bytes;
	u32 address_bits;

	w = read_register(&engine->regs->alignments);
	dbg_init("engine %p name %s alignments=0x%08x\n", engine, engine->name,
		 (int)w);

	/* RTO	- add some macros to extract these fields */
	align_bytes = (w & 0x00ff0000U) >> 16;
	granularity_bytes = (w & 0x0000ff00U) >> 8;
	address_bits = (w & 0x000000ffU);

	dbg_init("align_bytes = %d\n", align_bytes);
	dbg_init("granularity_bytes = %d\n", granularity_bytes);
	dbg_init("address_bits = %d\n", address_bits);

	if (w) {
		engine->addr_align = align_bytes;
		engine->len_granularity = granularity_bytes;
		engine->addr_bits = address_bits;
	} else {
		/* Some default values if alignments are unspecified */
		engine->addr_align = 1;
		engine->len_granularity = 1;
		engine->addr_bits = 64;
	}
}

static void engine_free_resource(struct zdma_engine *engine)
{
	struct zdma_dev *zdev = engine->zdev;

	/* Release memory use for descriptor writebacks */
	if (engine->desc) {
		dbg_init("device %s, engine %s pre-alloc desc 0x%p,0x%llx.\n",
			 dev_name(&zdev->pdev->dev), engine->name, engine->desc,
			 engine->desc_bus);
		dma_free_coherent(&zdev->pdev->dev,
					ZDMA_TRANSFER_MAX_DESC *
						sizeof(struct zdma_desc),
					engine->desc, engine->desc_bus);
		engine->desc = NULL;
	}
}

static int engine_destroy(struct zdma_dev *zdev, struct zdma_engine *engine)
{
	if (!zdev) {
		pr_err("Invalid zdev\n");
		return -EINVAL;
	}

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	dbg_sg("Shutting down engine %s%d", engine->name, engine->channel);

	/* Disable interrupts to stop processing new events during shutdown */
	write_register(0x0, &engine->regs->interrupt_enable_mask,
					 (unsigned long)(&engine->regs->interrupt_enable_mask) -
						 (unsigned long)(&engine->regs));

	/* Release memory use for descriptor writebacks */
	engine_free_resource(engine);

	memset(engine, 0, sizeof(struct zdma_engine));
	/* Decrement the number of engines available */
	zdev->engines_num--;
	return 0;
}

/* engine_create() - Create an SG DMA engine bookkeeping data structure
 *
 * An SG DMA engine consists of the resources for a single-direction transfer
 * queue; the SG DMA hardware, the software queue and interrupt handling.
 *
 * @dev Pointer to pci_dev
 * @offset byte address offset in BAR[zdev->config_bar_idx] resource for the
 * SG DMA * controller registers.
 * @dir: DMA_TO/FROM_DEVICE
 */
static int engine_init_regs(struct zdma_engine *engine)
{
	u32 reg_value;

	write_register(ZDMA_CTRL_NON_INCR_ADDR, &engine->regs->control_w1c,
					 (unsigned long)(&engine->regs->control_w1c) -
						 (unsigned long)(&engine->regs));

	engine_alignments(engine);

	/* Configure error interrupts by default */
	reg_value = ZDMA_CTRL_IE_DESC_ALIGN_MISMATCH;
	reg_value |= ZDMA_CTRL_IE_MAGIC_STOPPED;
	reg_value |= ZDMA_CTRL_IE_MAGIC_STOPPED;
	reg_value |= ZDMA_CTRL_IE_READ_ERROR;
	reg_value |= ZDMA_CTRL_IE_DESC_ERROR;

	/* enable the relevant completion interrupts */
	reg_value |= ZDMA_CTRL_IE_DESC_STOPPED;
	reg_value |= ZDMA_CTRL_IE_DESC_COMPLETED;

	/* Apply engine configurations */
	write_register(reg_value, &engine->regs->interrupt_enable_mask,
					 (unsigned long)(&engine->regs->interrupt_enable_mask) -
						 (unsigned long)(&engine->regs));

	engine->interrupt_enable_mask_value = reg_value;

	return 0;
}

static int engine_alloc_resource(struct zdma_engine *engine)
{
	struct zdma_dev *zdev = engine->zdev;

	engine->desc = dma_alloc_coherent(&zdev->pdev->dev,
						ZDMA_TRANSFER_MAX_DESC *
							sizeof(struct zdma_desc),
						&engine->desc_bus, GFP_KERNEL);
	engine->desc_idx = 0;
	if (!engine->desc) {
		pr_warn("dev %s, %s pre-alloc desc OOM.\n",
			dev_name(&zdev->pdev->dev), engine->name);
		goto err_out;
	}

	return 0;

err_out:
	engine_free_resource(engine);
	return -ENOMEM;
}

static int engine_init(struct zdma_engine *engine, struct zdma_dev *zdev,
					 int offset, enum dma_data_direction dir, int channel)
{
	int rv;
	u32 val;

	dbg_init("channel %d, offset 0x%x, dir %d.\n", channel, offset, dir);

	/* set magic */
	engine->magic = MAGIC_ENGINE;

	engine->channel = channel;

	/* engine interrupt request bit */
	engine->irq_bitmask = (1 << ZDMA_ENG_IRQ_NUM) - 1;
	engine->irq_bitmask <<= (zdev->engines_num * ZDMA_ENG_IRQ_NUM);
	engine->bypass_offset = zdev->engines_num * BYPASS_MODE_SPACING;

	/* parent */
	engine->zdev = zdev;
	/* register address */
	engine->regs = (zdev->bar[zdev->config_bar_idx] + offset);
	engine->sgdma_regs = zdev->bar[zdev->config_bar_idx] + offset +
					 SGDMA_OFFSET_FROM_CHANNEL;
	val = read_register(&engine->regs->identifier);
	if (val & 0x8000U) {
		pr_err("Streaming not supported by this driver");
		BUG();
	}

	/* remember SG DMA direction */
	engine->dir = dir;
	sprintf(engine->name, "%d-%s%d", zdev->idx,
		(dir == DMA_TO_DEVICE) ? "H2C" : "C2H", channel);

	dbg_init("engine %p name %s irq_bitmask=0x%08x\n", engine, engine->name,
		 (int)engine->irq_bitmask);

	/* initialize the deferred work for transfer completion */
	INIT_WORK(&engine->work, engine_service_work);

	if (dir == DMA_TO_DEVICE)
		zdev->mask_irq_h2c |= engine->irq_bitmask;
	else
		zdev->mask_irq_c2h |= engine->irq_bitmask;
	zdev->engines_num++;

	rv = engine_alloc_resource(engine);
	if (rv)
		return rv;

	rv = engine_init_regs(engine);
	if (rv)
		return rv;

	return 0;
}

/* transfer_destroy() - free transfer */
static void transfer_destroy(struct zdma_dev *zdev, struct zdma_transfer *xfer)
{
		/* free descriptors */
	zdma_desc_done(xfer->desc_virt, xfer->desc_num);

	if (xfer->last_in_request) {
		struct sg_table *sgt = xfer->sgt;

		if (sgt->nents) {
			dma_unmap_sg(&zdev->pdev->dev, sgt->sgl, sgt->orig_nents,
				xfer->dir);
			sgt->nents = 0;
		}
	}
}

static int transfer_build(struct zdma_engine *engine,
				struct zdma_request_cb *req, struct zdma_transfer *xfer, unsigned int desc_max)
{
	struct sw_desc *sdesc = &(req->sdesc[req->sw_desc_idx]);
	int i = 0;
	int j = 0;

	dbg_desc("desc_max: %d\n", desc_max);
	for (; i < desc_max; i++, j++, sdesc++) {
		dbg_desc("sw desc %d/%u: 0x%llx, 0x%x, ep 0x%llx.\n",
			 i + req->sw_desc_idx + 1, req->sw_desc_cnt,
			 sdesc->addr, sdesc->len, req->ep_addr);

		/* fill in descriptor entry j with transfer details */
		zdma_desc_set(xfer->desc_virt + j, sdesc->addr, req->ep_addr,
						sdesc->len, xfer->dir);
		xfer->len += sdesc->len;

		/* for non-inc-add mode don't increment ep_addr */
		if (!engine->non_incr_addr)
			req->ep_addr += sdesc->len;
	}
	req->sw_desc_idx += desc_max;
	return 0;
}


static int transfer_init(struct zdma_engine *engine, struct zdma_request_cb *req, struct zdma_transfer *xfer)
{
	unsigned int desc_max = min_t(unsigned int,
				req->sw_desc_cnt - req->sw_desc_idx,
				ZDMA_TRANSFER_MAX_DESC);
	unsigned int desc_align = 0;
	int i = 0;
	int last = 0;
	u32 control;
	unsigned long flags;

	memset(xfer, 0, sizeof(*xfer));

	/* lock the engine state */
	spin_lock_irqsave(&engine->lock, flags);
	/* initialize wait queue */
	init_waitqueue_head(&xfer->wq);

	/* remember direction of transfer */
	xfer->dir = engine->dir;
	xfer->desc_virt = engine->desc + engine->desc_idx;
	xfer->desc_bus = engine->desc_bus + (sizeof(struct zdma_desc) * engine->desc_idx);
	xfer->desc_index = engine->desc_idx;

	if ((engine->desc_idx + desc_max) >= ZDMA_TRANSFER_MAX_DESC )
		desc_max = ZDMA_TRANSFER_MAX_DESC - engine->desc_idx;

	transfer_desc_init(xfer, desc_max);

	dbg_sg("xfer= %p transfer->desc_bus = 0x%llx.\n",xfer, (u64)xfer->desc_bus);
	transfer_build(engine, req, xfer, desc_max);

	/* Contiguous descriptors cannot cross PAGE boundry. Adjust max accordingly */
	desc_align = engine->desc_idx + desc_max - 1;
	desc_align = desc_align % (PAGE_SIZE_X86 / sizeof(struct zdma_desc));
	if (desc_align < desc_max)
		desc_align = desc_max - desc_align - 1;
	else
		desc_align = desc_max;

	xfer->desc_adjacent = desc_align;

	/* terminate last descriptor */
	last = desc_max - 1;
	/* stop engine, EOP for AXI ST, req IRQ on last descriptor */
	control = ZDMA_DESC_STOPPED;
	control |= ZDMA_DESC_EOP;
	control |= ZDMA_DESC_COMPLETED;
	zdma_desc_control_set(xfer->desc_virt + last, control);

	xfer->desc_num = desc_max;
	engine->desc_idx = (engine->desc_idx + desc_max) % ZDMA_TRANSFER_MAX_DESC;
	engine->desc_used += desc_max;

	/* fill in adjacent numbers */
	for (i = 0; i < xfer->desc_num; i++)
		zdma_desc_adjacent(xfer->desc_virt + i, xfer->desc_num - i - 1);

	spin_unlock_irqrestore(&engine->lock, flags);
	return 0;
}

#ifdef __LIBZDMA_DEBUG__
static void sgt_dump(struct sg_table *sgt)
{
	int i;
	struct scatterlist *sg = sgt->sgl;

	pr_info("sgt 0x%p, sgl 0x%p, nents %u/%u.\n", sgt, sgt->sgl, sgt->nents,
		sgt->orig_nents);

	for (i = 0; i < sgt->orig_nents; i++, sg = sg_next(sg))
		pr_info("%d, 0x%p, pg 0x%p,%u+%u, dma 0x%llx,%u.\n", i, sg,
			sg_page(sg), sg->offset, sg->length, sg_dma_address(sg),
			sg_dma_len(sg));
}

static void zdma_request_cb_dump(struct zdma_request_cb *req)
{
	int i;

	pr_info("request 0x%p, total %u, ep 0x%llx, sw_desc %u, sgt 0x%p.\n",
		req, req->total_len, req->ep_addr, req->sw_desc_cnt, req->sgt);
	sgt_dump(req->sgt);
	for (i = 0; i < req->sw_desc_cnt; i++)
		pr_info("%d/%u, 0x%llx, %u.\n", i+1, req->sw_desc_cnt,
			req->sdesc[i].addr, req->sdesc[i].len);
}
#endif

static void zdma_request_free(struct zdma_request_cb *req)
{
	if (((unsigned long)req) >= VMALLOC_START &&
			((unsigned long)req) < VMALLOC_END)
		vfree(req);
	else
		kfree(req);
}

static struct zdma_request_cb *zdma_request_alloc(unsigned int sdesc_nr)
{
	struct zdma_request_cb *req;
	unsigned int size = sizeof(struct zdma_request_cb) +
					sdesc_nr * sizeof(struct sw_desc);

	req = kzalloc(size, GFP_KERNEL);
	if (!req) {
		req = vmalloc(size);
		if (req)
			memset(req, 0, size);
	}
	if (!req) {
		pr_info("OOM, %u sw_desc, %u.\n", sdesc_nr, size);
		return NULL;
	}

	return req;
}

static struct zdma_request_cb *zdma_init_request(struct sg_table *sgt,
						 u64 ep_addr)
{
	struct zdma_request_cb *req;
	struct scatterlist *sg = sgt->sgl;
	int max = sgt->nents;
	int extra = 0;
	int i, j = 0;

	for (i = 0; i < max; i++, sg = sg_next(sg)) {
		unsigned int len = sg_dma_len(sg);

		if (unlikely(len > desc_blen_max))
			extra += (len + desc_blen_max - 1) / desc_blen_max;
	}

	dbg_tfr("ep 0x%llx, desc %u+%u.\n", ep_addr, max, extra);

	max += extra;
	req = zdma_request_alloc(max);
	if (!req)
		return NULL;

	req->sgt = sgt;
	req->ep_addr = ep_addr;

	for (i = 0, sg = sgt->sgl; i < sgt->nents; i++, sg = sg_next(sg)) {
		unsigned int tlen = sg_dma_len(sg);
		dma_addr_t addr = sg_dma_address(sg);

		req->total_len += tlen;
		while (tlen) {
			req->sdesc[j].addr = addr;
			if (tlen > desc_blen_max) {
				req->sdesc[j].len = desc_blen_max;
				addr += desc_blen_max;
				tlen -= desc_blen_max;
			} else {
				req->sdesc[j].len = tlen;
				tlen = 0;
			}
			j++;
		}
	}

	if (j > max) {
		pr_err("Cannot transfer more than supported length %d\n",
					 desc_blen_max);
		zdma_request_free(req);
		return NULL;
	}
	req->sw_desc_cnt = j;
#ifdef __LIBZDMA_DEBUG__
	zdma_request_cb_dump(req);
#endif
	return req;
}

ssize_t zdma_xfer_submit(void *dev_hndl, int channel, bool write, u64 ep_addr,
			 struct sg_table *sgt, int timeout_ms)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;
	struct zdma_engine *engine;
	int rv = 0, tfer_idx = 0;
	ssize_t done = 0;
	struct scatterlist *sg = sgt->sgl;
	int nents;
	enum dma_data_direction dir = write ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	struct zdma_request_cb *req = NULL;

	if (!dev_hndl)
		return -EINVAL;

	if (debug_check_dev_hndl(__func__, zdev->pdev, dev_hndl) < 0)
		return -EINVAL;

	if (write == 1) {
		if (channel >= zdev->h2c_channel_max) {
			pr_err("H2C channel %d >= %d.\n", channel,
				zdev->h2c_channel_max);
			return -EINVAL;
		}
		engine = &zdev->engine_h2c[channel];
	} else if (write == 0) {
		if (channel >= zdev->c2h_channel_max) {
			pr_err("C2H channel %d >= %d.\n", channel,
				zdev->c2h_channel_max);
			return -EINVAL;
		}
		engine = &zdev->engine_c2h[channel];
	}

	if (!engine) {
		pr_err("dma engine NULL\n");
		return -EINVAL;
	}

	if (engine->magic != MAGIC_ENGINE) {
		pr_err("%s has invalid magic number %lx\n", engine->name,
					 engine->magic);
		return -EINVAL;
	}

	zdev = engine->zdev;
	if (zdma_device_flag_check(zdev, XDEV_FLAG_OFFLINE)) {
		pr_info("zdev 0x%p, offline.\n", zdev);
		return -EBUSY;
	}

	/* check the direction */
	if (engine->dir != dir) {
		pr_info("0x%p, %s, %d, W %d, 0x%x/0x%x mismatch.\n", engine,
			engine->name, channel, write, engine->dir, dir);
		return -EINVAL;
	}

	/* This may communicate with the IOMMU */
	nents = dma_map_sg(&zdev->pdev->dev, sg, sgt->orig_nents, dir);
	if (!nents) {
		pr_info("map sgl failed, sgt 0x%p.\n", sgt);
		return -EIO;
	}
	sgt->nents = nents;

	req = zdma_init_request(sgt, ep_addr);
	if (!req) {
		rv = -ENOMEM;
		goto unmap_sgl;
	}

	dbg_tfr("%s, len %u sg cnt %u.\n", engine->name, req->total_len,
		req->sw_desc_cnt);

	sg = sgt->sgl;
	nents = req->sw_desc_cnt;
	//spin_lock(&engine->desc_lock);
	mutex_lock(&engine->desc_lock);

	while (nents) {
		unsigned long flags;
		struct zdma_transfer *xfer;

		/* build transfer */
		rv = transfer_init(engine, req, &req->tfer[0]);
		if (rv < 0) {
			//spin_unlock(&engine->desc_lock);
			mutex_unlock(&engine->desc_lock);
			goto unmap_sgl;
		}
		xfer = &req->tfer[0];

		/* last transfer for the given request? */
		nents -= xfer->desc_num;
		if (!nents) {
			xfer->last_in_request = 1;
			xfer->sgt = sgt;
		}

		dbg_tfr("xfer, %u, ep 0x%llx, done %lu, sg %u/%u.\n", xfer->len,
			req->ep_addr, done, req->sw_desc_idx, req->sw_desc_cnt);

#ifdef __LIBZDMA_DEBUG__
		transfer_dump(xfer);
#endif

		rv = transfer_queue(engine, xfer);
		if (rv < 0) {
			//spin_unlock(&engine->desc_lock);
			mutex_unlock(&engine->desc_lock);
			pr_info("unable to submit %s, %d.\n", engine->name, rv);
			goto unmap_sgl;
		}

		/*
		 * When polling, determine how many descriptors have been queued
		 * on the engine to determine the writeback value expected
		 */
		wait_event_interruptible_timeout(
			xfer->wq,
			(xfer->state != TRANSFER_STATE_SUBMITTED),
			msecs_to_jiffies(timeout_ms));

		spin_lock_irqsave(&engine->lock, flags);

		switch (xfer->state) {
		case TRANSFER_STATE_COMPLETED:
			spin_unlock_irqrestore(&engine->lock, flags);

			dbg_tfr("transfer %p, %u, ep 0x%llx compl, +%lu.\n",
				xfer, xfer->len, req->ep_addr - xfer->len,
				done);

			done += xfer->len;

			rv = 0;
			break;
		case TRANSFER_STATE_FAILED:
			pr_info("xfer 0x%p,%u, failed, ep 0x%llx.\n", xfer,
				xfer->len, req->ep_addr - xfer->len);
			spin_unlock_irqrestore(&engine->lock, flags);

#ifdef __LIBZDMA_DEBUG__
			transfer_dump(xfer);
			sgt_dump(sgt);
#endif
			rv = -EIO;
			break;
		default:
			/* transfer can still be in-flight */
			pr_info("xfer 0x%p,%u, s 0x%x timed out, ep 0x%llx.\n",
				xfer, xfer->len, xfer->state, req->ep_addr);
			interrupt_block_dump(engine->zdev);
			rv = engine_status_read(engine, 0, 1);
			if (rv < 0) {
				pr_err("Failed to read engine status\n");
			} else if (rv == 0) {
				//engine_status_dump(engine);
				rv = transfer_abort(engine, xfer);
				if (rv < 0) {
					pr_err("Failed to stop engine\n");
				} else if (rv == 0) {
					rv = zdma_engine_stop(engine);
					if (rv < 0)
						pr_err("Failed to stop engine\n");
				}
			}
			spin_unlock_irqrestore(&engine->lock, flags);

#ifdef __LIBZDMA_DEBUG__
			transfer_dump(xfer);
			sgt_dump(sgt);
#endif
			rv = -ERESTARTSYS;
			break;
		}

		engine->desc_used -= xfer->desc_num;
		transfer_destroy(zdev, xfer);

		/* use multiple transfers per request if we could not fit all data within
		 * single descriptor chain.
		 */
		tfer_idx++;

		if (rv < 0) {
			mutex_unlock(&engine->desc_lock);
			//spin_unlock(&engine->desc_lock);
			goto unmap_sgl;
		}
	} /* while (sg) */
	mutex_unlock(&engine->desc_lock);
	//spin_unlock(&engine->desc_lock);

unmap_sgl:
	if (sgt->nents) {
		dma_unmap_sg(&zdev->pdev->dev, sgt->sgl, sgt->orig_nents, dir);
		sgt->nents = 0;
	}

	if (req)
		zdma_request_free(req);

	if (rv < 0)
		return rv;

	return done;
}
EXPORT_SYMBOL_GPL(zdma_xfer_submit);

static struct zdma_dev *alloc_dev_instance(struct pci_dev *pdev)
{
	int i;
	struct zdma_dev *zdev;
	struct zdma_engine *engine;

	if (!pdev) {
		pr_err("Invalid pdev\n");
		return NULL;
	}

	/* allocate zeroed device book keeping structure */
	zdev = kzalloc(sizeof(struct zdma_dev), GFP_KERNEL);
	if (!zdev) {
		pr_info("OOM, zdma_dev.\n");
		return NULL;
	}
	spin_lock_init(&zdev->lock);

	zdev->magic = MAGIC_DEVICE;
	zdev->config_bar_idx = -1;
	zdev->user_bar_idx = -1;
	zdev->bypass_bar_idx = -1;
	zdev->irq_line = -1;

	/* create a driver to device reference */
	zdev->pdev = pdev;
	dbg_init("zdev = 0x%p\n", zdev);

	/* Set up data user IRQ data structures */
	for (i = 0; i < 16; i++) {
		zdev->user_irq[i].zdev = zdev;
		spin_lock_init(&zdev->user_irq[i].events_lock);
		init_waitqueue_head(&zdev->user_irq[i].events_wq);
		zdev->user_irq[i].handler = NULL;
		zdev->user_irq[i].user_idx = i; /* 0 based */
	}

	engine = zdev->engine_h2c;
	for (i = 0; i < ZDMA_CHANNEL_NUM_MAX; i++, engine++) {
		spin_lock_init(&engine->lock);
		//spin_lock_init(&engine->desc_lock);
		mutex_init(&engine->desc_lock);
		INIT_LIST_HEAD(&engine->transfer_list);
		init_waitqueue_head(&engine->shutdown_wq);
	}

	engine = zdev->engine_c2h;
	for (i = 0; i < ZDMA_CHANNEL_NUM_MAX; i++, engine++) {
		spin_lock_init(&engine->lock);
		//spin_lock_init(&engine->desc_lock);
		mutex_init(&engine->desc_lock);
		INIT_LIST_HEAD(&engine->transfer_list);
		init_waitqueue_head(&engine->shutdown_wq);
	}

	return zdev;
}

static int request_regions(struct zdma_dev *zdev, struct pci_dev *pdev)
{
	int rv;

	if (!zdev) {
		pr_err("Invalid zdev\n");
		return -EINVAL;
	}

	if (!pdev) {
		pr_err("Invalid pdev\n");
		return -EINVAL;
	}

	dbg_init("pci_request_regions()\n");
	rv = pci_request_regions(pdev, zdev->mod_name);
	/* could not request all regions? */
	if (rv) {
		dbg_init("pci_request_regions() = %d, device in use?\n", rv);
		/* assume device is in use so do not disable it later */
		zdev->regions_in_use = 1;
	} else {
		zdev->got_regions = 1;
	}

	return rv;
}

static int set_dma_mask(struct pci_dev *pdev)
{
	if (!pdev) {
		pr_err("Invalid pdev\n");
		return -EINVAL;
	}

	dbg_init("sizeof(dma_addr_t) == %ld\n", sizeof(dma_addr_t));
	/* 64-bit addressing capability for ZDMA? */
	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		/* query for DMA transfer */
		/* @see Documentation/DMA-mapping.txt */
		dbg_init("pci_set_dma_mask()\n");
		/* use 64-bit DMA */
		dbg_init("Using a 64-bit DMA mask.\n");
		/* use 32-bit DMA for descriptors */
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		/* use 64-bit DMA, 32-bit for consistent */
	} else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		dbg_init("Could not set 64-bit DMA mask.\n");
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		/* use 32-bit DMA */
		dbg_init("Using a 32-bit DMA mask.\n");
	} else {
		dbg_init("No suitable DMA possible.\n");
		return -EINVAL;
	}

	return 0;
}

static int get_engine_channel_id(struct engine_regs *regs)
{
	int value;

	if (!regs) {
		pr_err("Invalid engine registers\n");
		return -EINVAL;
	}

	value = read_register(&regs->identifier);

	return (value & 0x00000f00U) >> 8;
}

static int get_engine_id(struct engine_regs *regs)
{
	int value;

	if (!regs) {
		pr_err("Invalid engine registers\n");
		return -EINVAL;
	}

	value = read_register(&regs->identifier);
	return (value & 0xffff0000U) >> 16;
}

static void remove_engines(struct zdma_dev *zdev)
{
	struct zdma_engine *engine;
	int i;
	int rv;

	if (!zdev) {
		pr_err("Invalid zdev\n");
		return;
	}

	/* iterate over channels */
	for (i = 0; i < zdev->h2c_channel_max; i++) {
		engine = &zdev->engine_h2c[i];
		if (engine->magic == MAGIC_ENGINE) {
			dbg_sg("Remove %s, %d", engine->name, i);
			rv = engine_destroy(zdev, engine);
			if (rv < 0)
				pr_err("Failed to destroy H2C engine %d\n", i);
			dbg_sg("%s, %d removed", engine->name, i);
		}
	}

	for (i = 0; i < zdev->c2h_channel_max; i++) {
		engine = &zdev->engine_c2h[i];
		if (engine->magic == MAGIC_ENGINE) {
			dbg_sg("Remove %s, %d", engine->name, i);
			rv = engine_destroy(zdev, engine);
			if (rv < 0)
				pr_err("Failed to destroy C2H engine %d\n", i);
			dbg_sg("%s, %d removed", engine->name, i);
		}
	}
}

static int probe_for_engine(struct zdma_dev *zdev, enum dma_data_direction dir,
					int channel)
{
	struct engine_regs *regs;
	int offset = channel * CHANNEL_SPACING;
	u32 engine_id;
	u32 engine_id_expected;
	u32 channel_id;
	struct zdma_engine *engine;
	int rv;

	/* register offset for the engine */
	/* read channels at 0x0000, write channels at 0x1000,
	 * channels at 0x100 interval
	 */
	if (dir == DMA_TO_DEVICE) {
		engine_id_expected = ZDMA_ID_H2C;
		engine = &zdev->engine_h2c[channel];
	} else {
		offset += H2C_CHANNEL_OFFSET;
		engine_id_expected = ZDMA_ID_C2H;
		engine = &zdev->engine_c2h[channel];
	}

	regs = zdev->bar[zdev->config_bar_idx] + offset;
	engine_id = get_engine_id(regs);
	channel_id = get_engine_channel_id(regs);

	if ((engine_id != engine_id_expected) || (channel_id != channel)) {
		dbg_init(
			"%s %d engine, reg off 0x%x, id mismatch 0x%x,0x%x,exp 0x%x,0x%x, SKIP.\n",
			dir == DMA_TO_DEVICE ? "H2C" : "C2H", channel, offset,
			engine_id, channel_id, engine_id_expected,
			channel_id != channel);
		return -EINVAL;
	}

	dbg_init("found AXI %s %d engine, reg. off 0x%x, id 0x%x,0x%x.\n",
		 dir == DMA_TO_DEVICE ? "H2C" : "C2H", channel, offset,
		 engine_id, channel_id);

	/* allocate and initialize engine */
	rv = engine_init(engine, zdev, offset, dir, channel);
	if (rv != 0) {
		pr_info("failed to create AXI %s %d engine.\n",
			dir == DMA_TO_DEVICE ? "H2C" : "C2H", channel);
		return rv;
	}

	return 0;
}

static int probe_engines(struct zdma_dev *zdev)
{
	int i;
	int rv = 0;

	if (!zdev) {
		pr_err("Invalid zdev\n");
		return -EINVAL;
	}

	/* iterate over channels */
	for (i = 0; i < zdev->h2c_channel_max; i++) {
		rv = probe_for_engine(zdev, DMA_TO_DEVICE, i);
		if (rv)
			break;
	}
	zdev->h2c_channel_max = i;

	for (i = 0; i < zdev->c2h_channel_max; i++) {
		rv = probe_for_engine(zdev, DMA_FROM_DEVICE, i);
		if (rv)
			break;
	}
	zdev->c2h_channel_max = i;

	return 0;
}

#if KERNEL_VERSION(3, 5, 0) <= LINUX_VERSION_CODE
static void pci_enable_capability(struct pci_dev *pdev, int cap)
{
	pcie_capability_set_word(pdev, PCI_EXP_DEVCTL, cap);
}
#else
static void pci_enable_capability(struct pci_dev *pdev, int cap)
{
	u16 v;
	int pos;

	pos = pci_pcie_cap(pdev);
	if (pos > 0) {
		pci_read_config_word(pdev, pos + PCI_EXP_DEVCTL, &v);
		v |= cap;
		pci_write_config_word(pdev, pos + PCI_EXP_DEVCTL, v);
	}
}
#endif

void *zdma_device_open(const char *mname, struct pci_dev *pdev, int *user_max,
					 int *h2c_channel_max, int *c2h_channel_max)
{
	struct zdma_dev *zdev = NULL;
	int rv = 0;

	pr_info("%s device %s, 0x%p.\n", mname, dev_name(&pdev->dev), pdev);

	/* allocate zeroed device book keeping structure */
	zdev = alloc_dev_instance(pdev);
	if (!zdev)
		return NULL;
	zdev->mod_name = mname;
	zdev->user_max = *user_max;
	zdev->h2c_channel_max = *h2c_channel_max;
	zdev->c2h_channel_max = *c2h_channel_max;

	zdma_device_flag_set(zdev, XDEV_FLAG_OFFLINE);
	zdev_list_add(zdev);

	if (zdev->user_max == 0 || zdev->user_max > MAX_USER_IRQ)
		zdev->user_max = MAX_USER_IRQ;
	if (zdev->h2c_channel_max == 0 ||
			zdev->h2c_channel_max > ZDMA_CHANNEL_NUM_MAX)
		zdev->h2c_channel_max = ZDMA_CHANNEL_NUM_MAX;
	if (zdev->c2h_channel_max == 0 ||
			zdev->c2h_channel_max > ZDMA_CHANNEL_NUM_MAX)
		zdev->c2h_channel_max = ZDMA_CHANNEL_NUM_MAX;

	rv = pci_enable_device(pdev);
	if (rv) {
		dbg_init("pci_enable_device() failed, %d.\n", rv);
		goto err_enable;
	}

	/* keep INTx enabled */
	pci_check_intr_pend(pdev);

	/* enable relaxed ordering */
	//pci_enable_capability(pdev, PCI_EXP_DEVCTL_RELAX_EN);

	/* enable extended tag */
	pci_enable_capability(pdev, PCI_EXP_DEVCTL_EXT_TAG);

	/* force MRRS to be 512 */
	rv = pcie_set_readrq(pdev, 512);
	if (rv)
		pr_info("device %s, error set PCI_EXP_DEVCTL_READRQ: %d.\n",
			dev_name(&pdev->dev), rv);

	/* enable bus master capability */
	pci_set_master(pdev);

	rv = request_regions(zdev, pdev);
	if (rv)
		goto err_regions;

	rv = map_bars(zdev, pdev);
	if (rv)
		goto err_map;

	rv = set_dma_mask(pdev);
	if (rv)
		goto err_mask;

	disable_relaxed_ordering(zdev);
	check_nonzero_interrupt_status(zdev);
	/* explicitely zero all interrupt enable masks */
	channel_interrupts_disable(zdev, ~0);
	user_interrupts_disable(zdev, ~0);
	read_interrupts(zdev);

	rv = probe_engines(zdev);
	if (rv)
		goto err_engines;

	rv = enable_msi_msix(zdev, pdev);
	if (rv < 0)
		goto err_enable_msix;

	rv = irq_setup(zdev, pdev);
	if (rv < 0)
		goto err_interrupts;

	channel_interrupts_enable(zdev, ~0);

	/* Flush writes */
	read_interrupts(zdev);

	*user_max = zdev->user_max;
	*h2c_channel_max = zdev->h2c_channel_max;
	*c2h_channel_max = zdev->c2h_channel_max;

	zdma_device_flag_clear(zdev, XDEV_FLAG_OFFLINE);
	return (void *)zdev;

err_interrupts:
	irq_teardown(zdev);
err_enable_msix:
	disable_msi_msix(zdev, pdev);
err_engines:
	remove_engines(zdev);
err_mask:
	unmap_bars(zdev, pdev);
err_map:
	if (zdev->got_regions)
		pci_release_regions(pdev);
err_regions:
	if (!zdev->regions_in_use)
		pci_disable_device(pdev);
err_enable:
	zdev_list_remove(zdev);
	kfree(zdev);
	return NULL;
}
EXPORT_SYMBOL_GPL(zdma_device_open);

void zdma_device_close(struct pci_dev *pdev, void *dev_hndl)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;

	dbg_init("pdev 0x%p, zdev 0x%p.\n", pdev, dev_hndl);

	if (!dev_hndl)
		return;

	if (debug_check_dev_hndl(__func__, pdev, dev_hndl) < 0)
		return;

	dbg_sg("remove(dev = 0x%p) where pdev->dev.driver_data = 0x%p\n", pdev,
				 zdev);
	if (zdev->pdev != pdev) {
		dbg_sg("pci_dev(0x%lx) != pdev(0x%lx)\n",
					 (unsigned long)zdev->pdev, (unsigned long)pdev);
	}

	channel_interrupts_disable(zdev, ~0);
	user_interrupts_disable(zdev, ~0);
	read_interrupts(zdev);

	irq_teardown(zdev);
	disable_msi_msix(zdev, pdev);

	remove_engines(zdev);
	unmap_bars(zdev, pdev);

	if (zdev->got_regions) {
		dbg_init("pci_release_regions 0x%p.\n", pdev);
		pci_release_regions(pdev);
	}

	if (!zdev->regions_in_use) {
		dbg_init("pci_disable_device 0x%p.\n", pdev);
		pci_disable_device(pdev);
	}

	zdev_list_remove(zdev);

	kfree(zdev);
}
EXPORT_SYMBOL_GPL(zdma_device_close);

void zdma_device_offline(struct pci_dev *pdev, void *dev_hndl)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;
	struct zdma_engine *engine;
	int i;
	int rv;

	if (!dev_hndl)
		return;

	if (debug_check_dev_hndl(__func__, pdev, dev_hndl) < 0)
		return;

	pr_info("pdev 0x%p, zdev 0x%p.\n", pdev, zdev);
	zdma_device_flag_set(zdev, XDEV_FLAG_OFFLINE);

	/* wait for all engines to be idle */
	for (i = 0; i < zdev->h2c_channel_max; i++) {
		unsigned long flags;

		engine = &zdev->engine_h2c[i];

		if (engine->magic == MAGIC_ENGINE) {
			spin_lock_irqsave(&engine->lock, flags);
			engine->shutdown |= ENGINE_SHUTDOWN_REQUEST;

			rv = zdma_engine_stop(engine);
			if (rv < 0)
				pr_err("Failed to stop engine\n");
			else
				engine->running = 0;
			spin_unlock_irqrestore(&engine->lock, flags);
		}
	}

	for (i = 0; i < zdev->c2h_channel_max; i++) {
		unsigned long flags;

		engine = &zdev->engine_c2h[i];
		if (engine->magic == MAGIC_ENGINE) {
			spin_lock_irqsave(&engine->lock, flags);
			engine->shutdown |= ENGINE_SHUTDOWN_REQUEST;

			rv = zdma_engine_stop(engine);
			if (rv < 0)
				pr_err("Failed to stop engine\n");
			else
				engine->running = 0;
			spin_unlock_irqrestore(&engine->lock, flags);
		}
	}

	/* turn off interrupts */
	channel_interrupts_disable(zdev, ~0);
	user_interrupts_disable(zdev, ~0);
	read_interrupts(zdev);
	irq_teardown(zdev);

	pr_info("zdev 0x%p, done.\n", zdev);
}
EXPORT_SYMBOL_GPL(zdma_device_offline);

void zdma_device_online(struct pci_dev *pdev, void *dev_hndl)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;
	struct zdma_engine *engine;
	unsigned long flags;
	int i;

	if (!dev_hndl)
		return;

	if (debug_check_dev_hndl(__func__, pdev, dev_hndl) < 0)
		return;

	pr_info("pdev 0x%p, zdev 0x%p.\n", pdev, zdev);

	for (i = 0; i < zdev->h2c_channel_max; i++) {
		engine = &zdev->engine_h2c[i];
		if (engine->magic == MAGIC_ENGINE) {
			engine_init_regs(engine);
			spin_lock_irqsave(&engine->lock, flags);
			engine->shutdown &= ~ENGINE_SHUTDOWN_REQUEST;
			spin_unlock_irqrestore(&engine->lock, flags);
		}
	}

	for (i = 0; i < zdev->c2h_channel_max; i++) {
		engine = &zdev->engine_c2h[i];
		if (engine->magic == MAGIC_ENGINE) {
			engine_init_regs(engine);
			spin_lock_irqsave(&engine->lock, flags);
			engine->shutdown &= ~ENGINE_SHUTDOWN_REQUEST;
			spin_unlock_irqrestore(&engine->lock, flags);
		}
	}

	/* re-write the interrupt table */
	irq_setup(zdev, pdev);

	channel_interrupts_enable(zdev, ~0);
	user_interrupts_enable(zdev, zdev->mask_irq_user);
	read_interrupts(zdev);

	zdma_device_flag_clear(zdev, XDEV_FLAG_OFFLINE);
	pr_info("zdev 0x%p, done.\n", zdev);
}
EXPORT_SYMBOL_GPL(zdma_device_online);

int zdma_device_restart(struct pci_dev *pdev, void *dev_hndl)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;

	if (!dev_hndl)
		return -EINVAL;

	if (debug_check_dev_hndl(__func__, pdev, dev_hndl) < 0)
		return -EINVAL;

	pr_info("NOT implemented, 0x%p.\n", zdev);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(zdma_device_restart);

int zdma_user_isr_register(void *dev_hndl, unsigned int mask,
				 irq_handler_t handler, void *dev)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;
	int i;

	if (!dev_hndl)
		return -EINVAL;

	if (debug_check_dev_hndl(__func__, zdev->pdev, dev_hndl) < 0)
		return -EINVAL;

	for (i = 0; i < zdev->user_max && mask; i++) {
		unsigned int bit = (1 << i);

		if ((bit & mask) == 0)
			continue;

		mask &= ~bit;
		zdev->user_irq[i].handler = handler;
		zdev->user_irq[i].dev = dev;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(zdma_user_isr_register);

int zdma_user_isr_enable(void *dev_hndl, unsigned int mask)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;

	if (!dev_hndl)
		return -EINVAL;

	if (debug_check_dev_hndl(__func__, zdev->pdev, dev_hndl) < 0)
		return -EINVAL;

	zdev->mask_irq_user |= mask;
	/* enable user interrupts */
	user_interrupts_enable(zdev, mask);
	read_interrupts(zdev);

	return 0;
}
EXPORT_SYMBOL_GPL(zdma_user_isr_enable);

int zdma_user_isr_disable(void *dev_hndl, unsigned int mask)
{
	struct zdma_dev *zdev = (struct zdma_dev *)dev_hndl;

	if (!dev_hndl)
		return -EINVAL;

	if (debug_check_dev_hndl(__func__, zdev->pdev, dev_hndl) < 0)
		return -EINVAL;

	zdev->mask_irq_user &= ~mask;
	user_interrupts_disable(zdev, mask);
	read_interrupts(zdev);

	return 0;
}
EXPORT_SYMBOL_GPL(zdma_user_isr_disable);

#ifdef __LIBZDMA_MOD__
static int __init zdma_base_init(void)
{
	pr_info("%s", version);
	return 0;
}

static void __exit zdma_base_exit(void)
{
	pr_info("%s", __func__);
}

module_init(zdma_base_init);
module_exit(zdma_base_exit);
#endif

