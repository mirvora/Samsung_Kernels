/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef __LINUX_FIVE_H
#define __LINUX_FIVE_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/security.h>
#include <linux/audit.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>

/* set during initialization */
struct worker_context {
	struct work_struct data_work;
	struct task_integrity *tint;
};

struct five_stat {
	u64 inode_iversion;
	u64 cache_iversion;
	u32 cache_status;
	u32 is_dm_verity;
};

/* Internal FIVE function definitions */
int five_init(void);

/* FIVE policy related functions */
enum five_hooks {
	FILE_CHECK = 1,
	MMAP_CHECK,
	BPRM_CHECK,
	POST_SETATTR
};

struct file_verification_result {
	struct task_struct *task;
	struct file *file;
	struct five_iint_cache *iint;
	enum five_hooks fn;
	int five_result;
	void *xattr;
	size_t xattr_len;
};

static inline void file_verification_result_init(
		struct file_verification_result *result)
{
	memset(result, 0, sizeof(*result));
}

static inline void file_verification_result_deinit(
		struct file_verification_result *result)
{
	kfree(result->xattr);
	memset(result, 0, sizeof(*result));
}

int five_appraise_measurement(struct task_struct *task, int func,
			      struct five_iint_cache *iint,
			      struct file *file);

int five_check_params(struct task_struct *task, struct file *file);
const char *five_d_path(const struct path *path, char **pathbuf,
			char *namebuf);

#if IS_MODULE(CONFIG_FIVE)
int __init five_task_integrity_cache_init(void);
#endif

const char *five_get_string_fn(enum five_hooks fn);
#endif
