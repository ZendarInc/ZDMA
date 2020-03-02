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

#ifndef _ZDMA_IOCALLS_POSIX_H_
#define _ZDMA_IOCALLS_POSIX_H_

#include <linux/ioctl.h>

/* Use 'z' as magic number */
#define ZDMA_IOC_MAGIC	'z'
/* XL OpenCL X->58(ASCII), L->6C(ASCII), O->0 C->C L->6C(ASCII); */
#define ZDMA_XCL_MAGIC 0X586C0C6C

/*
 * S means "Set" through a ptr,
 * T means "Tell" directly with the argument value
 * G means "Get": reply by setting through a pointer
 * Q means "Query": response is on the return value
 * X means "eXchange": switch G and S atomically
 * H means "sHift": switch T and Q atomically
 *
 * _IO(type,nr)		    no arguments
 * _IOR(type,nr,datatype)   read data from driver
 * _IOW(type,nr.datatype)   write data to driver
 * _IORW(type,nr,datatype)  read/write data
 *
 * _IOC_DIR(nr)		    returns direction
 * _IOC_TYPE(nr)	    returns magic
 * _IOC_NR(nr)		    returns number
 * _IOC_SIZE(nr)	    returns size
 */

enum ZDMA_IOC_TYPES {
	ZDMA_IOC_NOP,
	ZDMA_IOC_INFO,
	ZDMA_IOC_OFFLINE,
	ZDMA_IOC_ONLINE,
	ZDMA_IOC_MAX
};

struct zdma_ioc_base {
	unsigned int magic;
	unsigned int command;
};

struct zdma_ioc_info {
	struct zdma_ioc_base	base;
	unsigned short		vendor;
	unsigned short		device;
	unsigned short		subsystem_vendor;
	unsigned short		subsystem_device;
	unsigned int		dma_engine_version;
	unsigned int		driver_version;
	unsigned short		domain;
	unsigned char		bus;
	unsigned char		dev;
	unsigned char		func;
};

/* IOCTL codes */
#define ZDMA_IOCINFO		_IOWR(ZDMA_IOC_MAGIC, ZDMA_IOC_INFO, \
					struct zdma_ioc_info)
#define ZDMA_IOCOFFLINE		_IO(ZDMA_IOC_MAGIC, ZDMA_IOC_OFFLINE)
#define ZDMA_IOCONLINE		_IO(ZDMA_IOC_MAGIC, ZDMA_IOC_ONLINE)

#define IOCTL_ZDMA_ADDRMODE_SET	_IOW('q', 4, int)
#define IOCTL_ZDMA_ADDRMODE_GET	_IOR('q', 5, int)
#define IOCTL_ZDMA_ALIGN_GET	_IOR('q', 6, int)

#endif /* _ZDMA_IOCALLS_POSIX_H_ */

