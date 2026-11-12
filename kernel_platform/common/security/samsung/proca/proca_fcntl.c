// SPDX-License-Identifier: GPL-2.0
/*
 * PROCA fcntl implementation
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 * Hryhorii Tur, <hryhorii.tur@partner.samsung.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/xattr.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define XATTR_PA_SUFFIX "pa"
#define XATTR_NAME_PA (XATTR_USER_PREFIX XATTR_PA_SUFFIX)

#if defined(CONFIG_PROCA_GKI_20)
#include "task_integrity.h"
#include "proca.h"
#else
#include <linux/task_integrity.h>
#include <linux/proca.h>
#endif

#include "proca_porting.h"

/**
 * Length/Value structure
 */
struct lv {
	uint16_t length;
	uint8_t value[];
} __packed;

/* This function is copied from __vfs_setxattr_noperm() */
// kernel_device_modules-6.18/drivers/proca/proca_src/proca_fcntl.c:45:5: error: no previous prototype for function 'proca_setxattr_noperm' [-Werror,-Wmissing-prototypes]
/*int proca_setxattr_noperm(struct dentry *dentry, const char *name,
						const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error = -EAGAIN;
	int issec = !strncmp(name, XATTR_SECURITY_PREFIX,
							XATTR_SECURITY_PREFIX_LEN);
	if (issec)
		inode->i_flags &= ~S_NOSEC;
	if (inode->i_opflags & IOP_XATTR) {
		error = __vfs_setxattr(dentry, inode, name, value, size, flags);
	} else {
		if (unlikely(is_bad_inode(inode)))
			return -EIO;
	}
	return error;
}*/

int proca_fcntl_setxattr(struct file *file, void __user *lv_xattr)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(proca_fcntl_setxattr);
