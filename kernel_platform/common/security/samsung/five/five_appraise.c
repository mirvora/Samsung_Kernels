// SPDX-License-Identifier: GPL-2.0
/*
 * This code is based on IMA's code
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
 *
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
 * Viacheslav Vovchenko <v.vovchenko@samsung.com>
 * Yevgen Kopylov <y.kopylov@samsung.com>
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

#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/magic.h>

#if IS_BUILTIN(CONFIG_FIVE)
#include <linux/task_integrity.h>
#else
#include "task_integrity.h"
#endif

#include "five.h"
#include "five_audit.h"
#include "five_hooks.h"
#include "five_porting.h"
#include "five_cache.h"
#include "five_dmverity.h"
#include "five_log.h"
#if IS_BUILTIN(CONFIG_FIVE)
#include "five_iint.h"
#endif
#include "five_vfs.h"

static bool bad_fs(struct inode *inode)
{
	if (inode->i_sb->s_magic == EXT4_SUPER_MAGIC ||
	    inode->i_sb->s_magic == F2FS_SUPER_MAGIC ||
	    inode->i_sb->s_magic == OVERLAYFS_SUPER_MAGIC ||
	    inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1)
		return false;

	return true;
}

/*
 * five_is_fsverity_protected - checks if file is protected by FSVERITY
 *
 * Return true/false
 */
static bool five_is_fsverity_protected(const struct inode *inode)
{
	return IS_VERITY(inode);
}

/*
 * five_appraise_measurement - appraise file measurement
 *
 * Return 0 on success, error code otherwise
 */
int five_appraise_measurement(struct task_struct *task, int func,
			      struct five_iint_cache *iint,
			      struct file *file)
{
	enum task_integrity_reset_cause cause = CAUSE_UNKNOWN;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	enum five_file_integrity status = FIVE_FILE_UNKNOWN;
	enum task_integrity_value prev_integrity;
	int rc = 0;

	FIVE_BUG_ON(!task || !iint || !file);

	prev_integrity = task_integrity_read(TASK_INTEGRITY(task));
	dentry = file->f_path.dentry;
	inode = d_backing_inode(dentry);

	if (bad_fs(inode)) {
		status = FIVE_FILE_FAIL;
		cause = CAUSE_BAD_FS;
		rc = -EOPNOTSUPP;
		goto out;
	}

	cause = CAUSE_NO_CERT;
	if (five_is_fsverity_protected(inode))
		status = FIVE_FILE_FSVERITY;
	else if (five_is_dmverity_protected(file))
		status = FIVE_FILE_DMVERITY;

out:
	if (status == FIVE_FILE_FAIL || status == FIVE_FILE_UNKNOWN) {
		task_integrity_set_reset_reason(TASK_INTEGRITY(task),
						cause, file);
		five_audit_verbose(task, file, five_get_string_fn(func),
				prev_integrity, prev_integrity,
				tint_reset_cause_to_string(cause), rc);
	}

	five_set_cache_status(iint, status);

	return rc;
}

/**
 * five_inode_post_setattr, five_inode_setxattr, five_inode_removexattr
 * are dummy functions left to avoid changes in files
 * kernel/6.12/src/security/security.c and kernel/6.12/src/fs/attr.c
 * which are individual for every platform.
 */
void five_inode_post_setattr(struct task_struct *task, struct dentry *dentry)
{
	return;
}

int five_inode_setxattr(struct dentry *dentry, const char *xattr_name,
			const void *xattr_value, size_t xattr_value_len)
{
	return 0;
}

int five_inode_removexattr(struct dentry *dentry, const char *xattr_name)
{
	return 0;
}

/* Called from do_fcntl */
int five_fcntl_sign(struct file *file, struct integrity_label __user *label)
{
	return -EOPNOTSUPP;
}

int five_fcntl_edit(struct file *file)
{
	return -EOPNOTSUPP;
}

int five_fcntl_close(struct file *file)
{
	return -EOPNOTSUPP;
}
