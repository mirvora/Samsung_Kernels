// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <asm/barrier.h>
#include <linux/binfmts.h>
#include <linux/compiler.h>
#include <linux/const.h>
#ifdef DEFEX_DSMS_ENABLE
#include <linux/dsms.h>
#endif
#include <linux/file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/dcache.h>
#ifdef DEFEX_DSMS_ENABLE
#include <linux/string.h>
#endif
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include "include/defex_caches.h"
#include "include/defex_catch_list.h"
#include "include/defex_config.h"
#include "include/defex_debug.h"
#include "include/defex_internal.h"
#include "include/defex_rules.h"
#include "include/defex_tree.h"

#if KERNEL_VER_GTE(4, 11, 0)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif

#if KERNEL_VER_GTE(5, 1, 0)
#define is_task_used(tsk)	refcount_read(&(tsk)->usage)
#else
#define is_task_used(tsk)	atomic_read(&(tsk)->usage)
#endif


__visible_for_testing struct task_struct *get_parent_task(const struct task_struct *p)
{
	struct task_struct *parent = NULL;

	read_lock(&tasklist_lock);
	parent = p->parent;
	if (parent)
		get_task_struct(parent);
	read_unlock(&tasklist_lock);
	return parent;
}

#ifdef DEFEX_DSMS_ENABLE

#	define PED_VIOLATION "DFX1"
#	define SAFEPLACE_VIOLATION "DFX2"
#	define INTEGRITY_VIOLATION "DFX3"
#	define IMMUTABLE_VIOLATION "DFX4"
#	define LINK_VIOLATION "DFX5"
#	define MESSAGE_BUFFER_SIZE 200
#	define STORED_CREDS_SIZE 100

__visible_for_testing void defex_report_violation(const char *violation, uint64_t counter,
	struct defex_context *dc, uid_t stored_uid,
	uid_t stored_fsuid, uid_t stored_egid, int case_num)
{
	int usermode_result;
	char message[MESSAGE_BUFFER_SIZE + 1];

	struct task_struct *parent = NULL, *p = dc->task;
	const uid_t uid = uid_get_value(dc->cred->uid);
	const uid_t euid = uid_get_value(dc->cred->euid);
	const uid_t fsuid = uid_get_value(dc->cred->fsuid);
	const uid_t egid = uid_get_value(dc->cred->egid);
	const char *process_name = p->comm;
	const char *prt_process_name = NULL;
	const char *program_path = get_dc_process_name(dc);
	char *prt_program_path = NULL;
	char *file_path = NULL;
	char stored_creds[STORED_CREDS_SIZE + 1];

	parent = get_parent_task(p);
	if (!parent)
		return;

	prt_process_name = parent->comm;
	prt_program_path = defex_get_filename(parent);

	if (dc->target_file && (!case_num || case_num == 11)) {
		file_path = get_dc_target_name(dc);
	} else {
		snprintf(stored_creds, sizeof(stored_creds),
			"[%ld, %ld, %ld]", (long)stored_uid, (long)stored_fsuid,
			(long)stored_egid);
		stored_creds[sizeof(stored_creds) - 1] = 0;
	}
	snprintf(message, sizeof(message), "%d, %d, sc=%d, tsk=%s(%s), %s(%s),"
		" [%ld %ld %ld %ld], %s%s, %d",
		 get_warranty_bit(), is_boot_state_unlocked(), dc->syscall_no, process_name,
		program_path, prt_process_name, prt_program_path, (long)uid, (long)euid,
		(long)fsuid, (long)egid, (file_path ? "file=" : "stored "),
		(file_path ? file_path : stored_creds), case_num);
	message[sizeof(message) - 1] = 0;

	usermode_result = dsms_send_message(violation, message, counter);
#ifdef DEFEX_DEBUG_ENABLE
	defex_log_err("Violation : feature=%s value=%ld, detail=[%s]", violation,
		(long)counter, message);
	defex_log_err("Result : %d", usermode_result);
#endif /* DEFEX_DEBUG_ENABLE */

	safe_str_free(prt_program_path);
	put_task_struct(parent);
}
#endif /* DEFEX_DSMS_ENABLE */

#if defined(DEFEX_SAFEPLACE_ENABLE) || defined(DEFEX_TRUSTED_MAP_ENABLE) \
	|| defined(DEFEX_INTEGRITY_ENABLE)
__visible_for_testing long kill_process(struct task_struct *p)
{
	read_lock(&tasklist_lock);
	send_sig(SIGKILL, p, 0);
	read_unlock(&tasklist_lock);
	return 0;
}
#endif /* DEFEX_SAFEPLACE_ENABLE || DEFEX_TRUSTED_MAP_ENABLE || DEFEX_INTEGRITY_ENABLE */

#ifdef DEFEX_PED_ENABLE
__visible_for_testing long kill_process_group(int tgid)
{
	struct task_struct *p;

	read_lock(&tasklist_lock);
	for_each_process(p) {
		if (p->tgid == tgid)
			send_sig(SIGKILL, p, 0);
	}
	send_sig(SIGKILL, current, 0);
	read_unlock(&tasklist_lock);
	return 0;
}

static int check_path_is_system(const char *path)
{
	int i;
	static const int path_size_list[] = { 8, 9, 6, 12, 20 };
	static const char * const path_list[] = {
		"/system/",
		"/product/",
		"/apex/",
		"/system_ext/",
		"/postinstall/system/"
	};

	if (!path)
		return 0;

	for (i = 0; i < ARRAY_SIZE(path_list); i++) {
		if (!strncmp(path_list[i], path, path_size_list[i]))
			return 1;
	}
	return 0;
}

__visible_for_testing int task_defex_is_secured(struct defex_context *dc)
{
	struct file *exe_file = get_dc_process_file(dc);
	char *proc_name = get_dc_process_name(dc);
	int rules_iter, rules_max, is_system;

	if (!get_dc_process_dpath(dc))
		return 0;

	is_system = check_path_is_system(proc_name);

	FOR_EACH_RULES(rules_iter, rules_max, is_system) {
		if (rules_lookup(proc_name, feature_ped_exception,
				 exe_file, NULL, 0, is_system))
			return 0;
	}

	return 1;
}

__visible_for_testing int at_same_group(unsigned int uid1, unsigned int uid2)
{
	/* allow the weaken privilege */
	if (uid1 >= 10000 && uid2 < 10000)
		return 1;
	/* allow traverse in the same class */
	if ((uid1 / 1000) == (uid2 / 1000))
		return 1;
	/* allow traverse to isolated ranges */
	if (uid1 >= 90000)
		return 1;
	return 0;
}

__visible_for_testing int at_same_group_gid(unsigned int gid1, unsigned int gid2)
{
	/* allow the weaken privilege */
	if (gid1 >= 10000 && gid2 < 10000)
		return 1;
	/* allow traverse in the same class */
	if ((gid1 / 1000) == (gid2 / 1000))
		return 1;
	/* allow traverse to isolated ranges */
	if (gid1 >= 90000)
		return 1;
	return 0;
}

#ifdef DEFEX_LP_ENABLE
/* Lower Permission feature decision function */
__visible_for_testing int lower_adb_permission(struct defex_context *dc,
		unsigned short cred_flags)
{
	char *parent_file;
	struct task_struct *parent = NULL, *p = dc->task;
#ifndef DEFEX_PERMISSIVE_LP
	struct cred *shellcred;
	static const char adbd_str[] = "/apex/com.android.adbd/bin/adbd";
#endif /* DEFEX_PERMISSIVE_LP */
	int ret = 0;

	parent = get_parent_task(p);
	if (!parent || p->pid == 1 || parent->pid == 1)
		goto out;

	parent_file = defex_get_filename(parent);

#ifndef DEFEX_PERMISSIVE_LP
	if (!strncmp(parent_file, adbd_str, sizeof(adbd_str))) {
		shellcred = prepare_creds();
		defex_log_crit("ADB with root");
		if (!shellcred) {
			defex_log_crit("Prepare_creds fail");
			ret = 0;
			goto out;
		}

		uid_set_value(shellcred->uid, 2000);
		uid_set_value(shellcred->suid, 2000);
		uid_set_value(shellcred->euid, 2000);
		uid_set_value(shellcred->fsuid, 2000);
		uid_set_value(shellcred->gid, 2000);
		uid_set_value(shellcred->sgid, 2000);
		uid_set_value(shellcred->egid, 2000);
		uid_set_value(shellcred->fsgid, 2000);
		commit_creds(shellcred);
		dc->cred = (struct cred *)current_cred(); //shellcred;
		set_task_creds(p, 2000, 2000, 2000, cred_flags);

		ret = 1;
	}
#endif /* DEFEX_PERMISSIVE_LP */

	safe_str_free(parent_file);
out:
	if (parent)
		put_task_struct(parent);
	return ret;
}
#endif /* DEFEX_LP_ENABLE */

/* Cred. violation feature decision function */
#define AID_MEDIA_RW	1023
#define AID_MEDIA_OBB	1059
#define AID_SYSTEM	1000

__visible_for_testing int task_defex_check_creds(struct defex_context *dc)
{
	char *path = NULL;
	int check_deeper, case_num;
	unsigned int cur_uid, cur_euid, cur_fsuid, cur_egid;
	unsigned int ref_uid, ref_fsuid, ref_egid;
	struct task_struct *parent, *p = dc->task;
	unsigned short cred_flags;
	const struct cred *parent_cred;
	static const unsigned int dead_uid = 0xDEADBEAF;

	if (!is_task_creds_ready() || !p->cred)
		goto out;

	get_task_creds(p, &ref_uid, &ref_fsuid, &ref_egid, &cred_flags);

	cur_uid = uid_get_value(dc->cred->uid);
	cur_euid = uid_get_value(dc->cred->euid);
	cur_fsuid = uid_get_value(dc->cred->fsuid);
	cur_egid = uid_get_value(dc->cred->egid);

	if (!ref_uid) {
		if (p->tgid != p->pid && p->tgid != 1 && p->real_parent->pid != 1) {
			path = get_dc_process_name(dc);
			defex_log_crit("[6]: cred wasn't stored [task=%s, filename=%s,"
				" uid=%d, tgid=%u, pid=%u, ppid=%u]",
				p->comm, path, cur_uid, p->tgid, p->pid, p->real_parent->pid);
			defex_log_crit("[6]: stored [euid=%d fsuid=%d egid=%d]"
				" current [uid=%d euid=%d fsuid=%d egid=%d]",
				ref_uid, ref_fsuid, ref_egid, cur_uid, cur_euid, cur_fsuid,
				cur_egid);
			goto exit;
		}

		parent = get_parent_task(p);
		if (parent) {
			parent_cred = get_task_cred(parent);
			if (CHECK_ROOT_CREDS(parent_cred))
				cred_flags |= CRED_FLAGS_PROOT;
			put_cred(parent_cred);
			put_task_struct(parent);
		}

		if (CHECK_ROOT_CREDS(dc->cred)) {
#ifdef DEFEX_LP_ENABLE
			if (!lower_adb_permission(dc, cred_flags))
#endif /* DEFEX_LP_ENABLE */
			{
				set_task_creds(p, 1, 1, 1, cred_flags);
			}
		} else
			set_task_creds(p, cur_euid, cur_fsuid, cur_egid, cred_flags);
	} else if (ref_uid == 1) {
		if (!CHECK_ROOT_CREDS(dc->cred))
			set_task_creds(p, cur_euid, cur_fsuid, cur_egid, cred_flags);
	} else if (ref_uid == dead_uid) {
		path = get_dc_process_name(dc);
		defex_log_crit("[5]: process wasn't killed [task=%s, filename=%s, uid=%d,"
			" tgid=%u, pid=%u, ppid=%u]",
			p->comm, path, cur_uid, p->tgid, p->pid, p->real_parent->pid);
		defex_log_crit("[5]: stored [euid=%d fsuid=%d egid=%d] current [uid=%d"
			" euid=%d fsuid=%d egid=%d]",
			ref_uid, ref_fsuid, ref_egid, cur_uid, cur_euid, cur_fsuid, cur_egid);
		goto exit;
	} else {
		check_deeper = 0;
		/* temporary allow fsuid changes to "media_rw" */
		if ((cur_uid != ref_uid)
				|| (cur_euid != ref_uid)
				|| (cur_egid != ref_egid)
				|| !((cur_fsuid == ref_fsuid)
				|| (cur_fsuid == ref_uid)
				|| (cur_fsuid%100000 == AID_SYSTEM)
				|| (cur_fsuid%100000 == AID_MEDIA_RW)
				|| (cur_fsuid%100000 == AID_MEDIA_OBB))) {
			check_deeper = 1;
			if (CHECK_ROOT_CREDS(dc->cred))
				set_task_creds(p, 1, 1, 1, cred_flags);
			else
				set_task_creds(p, cur_euid, cur_fsuid, cur_egid, cred_flags);
		}
		if (check_deeper &&
				(!at_same_group(cur_uid, ref_uid)
				|| !at_same_group(cur_euid, ref_uid)
				|| !at_same_group_gid(cur_egid, ref_egid)
				|| !at_same_group(cur_fsuid, ref_fsuid))
				&& task_defex_is_secured(dc)) {
			case_num = ((p->tgid == p->pid) ?
				1:2);
			goto trigger_violation;
		}
	}

	if (CHECK_ROOT_CREDS(dc->cred) && !(cred_flags & CRED_FLAGS_PROOT)
			&& task_defex_is_secured(dc)) {
		if (p->tgid != p->pid) {
			case_num = 3;
			goto trigger_violation;
		}
		case_num = 4;
		goto trigger_violation;
	}

out:
	return DEFEX_ALLOW;

trigger_violation:
	set_task_creds(p, dead_uid, dead_uid, dead_uid, cred_flags);
	path = get_dc_process_name(dc);
	defex_log_crit("[%d]: credential violation [task=%s, filename=%s, uid=%d, tgid=%u,"
		" pid=%u, ppid=%u]",
		case_num, p->comm, path, cur_uid, p->tgid, p->pid, p->real_parent->pid);
	defex_log_crit("[%d]: stored [euid=%d fsuid=%d egid=%d] current [uid=%d euid=%d"
		" fsuid=%d egid=%d]",
		case_num, ref_uid, ref_fsuid, ref_egid, cur_uid, cur_euid, cur_fsuid, cur_egid);

#ifdef DEFEX_DSMS_ENABLE
	defex_report_violation(PED_VIOLATION, 0, dc, ref_uid, ref_fsuid, ref_egid, case_num);
#endif /* DEFEX_DSMS_ENABLE */

exit:
	return -DEFEX_DENY;
}

/* Credential escalation feature */
static int check_ped(struct defex_context *dc, struct task_struct *p, int feature_flag)
{
	if (feature_flag & FEATURE_CHECK_CREDS) {
		if (task_defex_check_creds(dc)) {
			if (!(feature_flag & FEATURE_CHECK_CREDS_SOFT)) {
				kill_process_group(p->tgid);
				return -DEFEX_DENY;
			}
		}
	}
	return DEFEX_ALLOW;
}
#else
#define check_ped(...) DEFEX_ALLOW
#endif /* DEFEX_PED_ENABLE */

#ifdef DEFEX_INTEGRITY_ENABLE
__visible_for_testing int task_defex_integrity(struct defex_context *dc)
{
	int ret = DEFEX_ALLOW, is_violation = 0;
	char *proc_file, *new_file;
	struct task_struct *p = dc->task;
	int rules_iter, rules_max, is_system;

	if (!get_dc_target_dpath(dc))
		goto out;

	new_file = get_dc_target_name(dc);
	is_system = check_path_is_system(new_file);

	FOR_EACH_RULES(rules_iter, rules_max, is_system) {
		is_violation = rules_lookup(new_file, feature_integrity_check,
					    dc->target_file, NULL, 0,
					    is_system);
		if (is_violation)
			break;
	}

	if (is_violation == DEFEX_INTEGRITY_FAIL) {
		ret = -DEFEX_DENY;
		proc_file = get_dc_process_name(dc);

		defex_log_crit("Integrity violation [task=%s (%s), child=%s, uid=%d]",
				p->comm, proc_file, new_file, uid_get_value(dc->cred->uid));
#ifdef DEFEX_DSMS_ENABLE
			defex_report_violation(INTEGRITY_VIOLATION, 0, dc, 0, 0, 0, 0);
#endif /* DEFEX_DSMS_ENABLE */
	}
out:
	return ret;
}

/* Integrity feature */
static int check_integrity(struct defex_context *dc, struct task_struct *p,
				int feature_flag, int syscall)
{
	if (feature_flag & FEATURE_INTEGRITY) {
		if (syscall == __DEFEX_execve) {
			if (task_defex_integrity(dc) == -DEFEX_DENY) {
				if (!(feature_flag & FEATURE_INTEGRITY_SOFT)) {
					kill_process(p);
					return -DEFEX_DENY;
				}
			}
		}
	}
	return DEFEX_ALLOW;
}
#else
#define check_integrity(...) DEFEX_ALLOW
#endif /* DEFEX_INTEGRITY_ENABLE */

#ifdef DEFEX_SAFEPLACE_ENABLE
/* Safeplace feature decision function */
__visible_for_testing int task_defex_safeplace(struct defex_context *dc)
{
	int ret = DEFEX_ALLOW, is_violation = 1;
	char *proc_file, *new_file;
	struct task_struct *p = dc->task;
	int rules_iter, rules_max, is_system;

	if (!CHECK_ROOT_CREDS(dc->cred))
		goto out;

	if (!get_dc_target_dpath(dc))
		goto out;

	new_file = get_dc_target_name(dc);
	is_system = check_path_is_system(new_file);

	FOR_EACH_RULES(rules_iter, rules_max, is_system) {
		if (rules_lookup(new_file, feature_safeplace_path,
				 dc->target_file, NULL, 0, is_system)) {
			is_violation = 0;
			break;
		}
	}

	if (is_violation) {
		ret = -DEFEX_DENY;
		proc_file = get_dc_process_name(dc);

		defex_log_crit("Safeplace violation [task=%s (%s), child=%s, uid=%d]",
			p->comm, proc_file, new_file, uid_get_value(dc->cred->uid));
#ifdef DEFEX_DSMS_ENABLE
			defex_report_violation(SAFEPLACE_VIOLATION, 0, dc, 0, 0, 0, 0);
#endif /* DEFEX_DSMS_ENABLE */
	}
out:
	return ret;
}

/* Safeplace feature */
static int check_safeplace(struct defex_context *dc, struct task_struct *p,
				int feature_flag, int syscall)
{
	if (feature_flag & FEATURE_SAFEPLACE) {
		if (syscall == __DEFEX_execve) {
			if (task_defex_safeplace(dc) == -DEFEX_DENY) {
				if (!(feature_flag & FEATURE_SAFEPLACE_SOFT)) {
					kill_process(p);
					return -DEFEX_DENY;
				}
			}
		}
	}
	return DEFEX_ALLOW;
}
#else
#define check_safeplace(...) DEFEX_ALLOW
#endif /* DEFEX_SAFEPLACE_ENABLE */

#ifdef DEFEX_TRUSTED_MAP_ENABLE
/* Trusted map feature decision function */
#if KERNEL_VER_GTE(5, 9, 0)
__visible_for_testing int task_defex_trusted_map(struct defex_context *dc, va_list ap)
{
	int ret = DEFEX_ALLOW, argc;
	struct linux_binprm *bprm;

	if (!CHECK_ROOT_CREDS(dc->cred))
		goto out;

	bprm = va_arg(ap, struct linux_binprm *);
	argc = bprm->argc;
#ifdef DEFEX_DEBUG_ENABLE
	if (argc <= 0)
		defex_log_crit("[DTM] Invalid trusted map arguments - check integration on"
			" fs/exec.c (argc %d)", argc);
#endif

	ret = defex_trusted_map_lookup(dc, argc, bprm);
	if (defex_get_features() & FEATURE_TRUSTED_MAP_SOFT)
		ret = DEFEX_ALLOW;
out:
	return ret;
}
#else
__visible_for_testing int task_defex_trusted_map(struct defex_context *dc, va_list ap)
{
	int ret = DEFEX_ALLOW, argc;
	void *argv;

	if (!CHECK_ROOT_CREDS(dc->cred))
		goto out;

	argc = va_arg(ap, int);
	argv = va_arg(ap, void *);
#ifdef DEFEX_DEBUG_ENABLE
	if (argc <= 0)
		defex_log_crit(
			"[DTM] Invalid trusted map arguments - check integration on fs/exec.c"
			" (argc %d)", argc);
#endif

	ret = defex_trusted_map_lookup(dc, argc, argv);
	if (defex_get_features() & FEATURE_TRUSTED_MAP_SOFT)
		ret = DEFEX_ALLOW;
out:
	return ret;
}
#endif

/* Trusted map feature */
static int check_trusted_map(struct defex_context *dc, struct task_struct *p,
				int feature_flag, int syscall, va_list ap)
{
	int ret = DEFEX_ALLOW;

	if (feature_flag & FEATURE_TRUSTED_MAP) {
		if (syscall == __DEFEX_execve) {
			ret = task_defex_trusted_map(dc, ap);
			if (ret == -DEFEX_DENY) {
				if (!(feature_flag & FEATURE_TRUSTED_MAP_SOFT)) {
					kill_process(p);
					return ret;
				}
			}
		}
	}
	return ret;
}
#else
#define check_trusted_map(...) DEFEX_ALLOW
#endif /* DEFEX_TRUSTED_MAP_ENABLE */

#ifdef DEFEX_LINK_PROTECTION_ENABLE

__visible_for_testing int has_trailing(const char *s)
{
	size_t len, i;
	if (!s)
		return 0;
	len = strlen(s);
	if (len && s[len -1] == '/')
		return 1;
	i = len;
	while (i && s[i-1] != '/')
		i--;
	if (!strcmp(s + i, ".") || !strcmp(s + i, ".."))
		return 1;

	return 0;
}

__visible_for_testing char *normalize_path_name(const char *base, const char *name)
{
	char *dup = NULL, *joined = NULL, *out = NULL;
	char **stack = NULL;
	size_t stack_sz = 0, stack_cap = 8, total_len = 0;
	size_t in_len, base_len, joined_len, i;
	int is_dir = has_trailing(name);
	char *s, *tok, *tmp;
	int pos = 0, len;

	if (!name || *name == '\0')
		return NULL;

	// if name is absolute, ignore base
	if (*name == '/') {
		dup = kstrdup(name, GFP_KERNEL);
		if (!dup)
			return NULL;
	} else {
		// name is relative => base must be absolute
		if (!base || *base != '/')
			return NULL;
		
		in_len = strlen(name);
		base_len = strlen(base);

		joined_len = base_len + (base_len && base[base_len - 1] == '/' ? 0 : 1) + in_len + 1;
		joined = kmalloc(joined_len, GFP_KERNEL);
		
		if (!joined)
			return NULL;

		dup = joined;
		memcpy(dup, base, base_len);
		dup += base_len;
		if (!(base_len && base[base_len - 1] == '/'))
			*dup++ = '/';
		
		memcpy(dup, name, in_len);
		dup += in_len;
		*dup = '\0';
		dup = joined;
	}

	stack = kmalloc_array(stack_cap, sizeof(char *), GFP_KERNEL);
	if(!stack)
		goto clean;
	
	s = dup;
	// Skip leading slash
	while (s && *s == '/') s++;

	while(*s) {
		tok = s;
		while (*s && *s != '/') s++;
		if (*s) *s++ = '\0'; // terminate current token

		// handle '.' and '..'
		if (tok[0] == '.') {
			if (tok[1] == '\0') {
				while(*s == '/')
					s++;
				continue;
			}

			if (tok[1] == '.' && tok[2] == '\0') { 
				if (stack_sz > 0)
					stack_sz--;
				while(*s == '/')
					s++;
				continue;
			}
		}

		if (stack_sz == stack_cap) {
			size_t new_cap = stack_cap ? stack_cap * 2 : 8;
			char **tmp = krealloc(stack, sizeof(char *) * new_cap, GFP_KERNEL);
			if (!tmp)
				goto clean;

			stack = tmp;
			stack_cap = new_cap;
		}
		stack[stack_sz++] = tok;

		while(*s == '/')
			s++;
	}

	if (stack_sz == 0) {
		out = kstrdup("/", GFP_KERNEL);
		if(!out)
			goto clean;
	}else {
		total_len = 0;
		for (i = 0; i < stack_sz; ++i) total_len += 1 + strlen(stack[i]);

		if (is_dir) total_len += 1;

		if (total_len > PATH_MAX)
			goto clean;

		out = kmalloc(total_len + 1, GFP_KERNEL);
		if (!out) 
			goto clean;

		tmp = out;

		for (i = 0; i < stack_sz; ++i) {
			tmp[pos++] = '/';
			len = strlen(stack[i]);
			memcpy(tmp + pos, stack[i], len);
			pos += len;
		}

		if (is_dir && tmp[pos-1] != '/')
			tmp[pos++] = '/';
		tmp[pos] = '\0';
	}

clean:
	kfree(stack);
	kfree(dup);
	return out;
}

__visible_for_testing struct path *defex_get_root_path(struct defex_context *dc, const char *file_name)
{
	struct path *root;

	if (!file_name)
		return NULL;

	root = kmalloc(sizeof(struct path), GFP_KERNEL);
	if (!root)
		return NULL;

	dc->root_path = root;
	dc->root_grabbed = 1;
	if (*file_name == '/' && !(dc->open_flags & LOOKUP_IN_ROOT)) {
		get_fs_root(current->fs, root);
		return root;
	}

	if (dc->dfd == AT_FDCWD) {
		get_fs_pwd(current->fs, root);
	} else {
		struct fd f = fdget_raw(dc->dfd);
#if KERNEL_VER_LESS(6,12,0)
		if (!f.file)
#else
		if (!fd_file(f))
#endif
			return NULL;

#if KERNEL_VER_LESS(6,12,0)
		*root = f.file->f_path;
#else
		*root = fd_file(f)->f_path;
#endif
		path_get(root);
		fdput(f);
	}

	return root;
}

/* Helper function to allocate buffer and get path 
   Caller must free the buffer
*/
static char *get_fname_from_path(const struct path *path, char **buffer)
{
	*buffer = (char *)__get_free_page(GFP_KERNEL | GFP_NOWAIT);
	if (!*buffer)
		return NULL;

	return d_path(path, *buffer, PAGE_SIZE);
}

static char *get_symlink_target_name(struct defex_context *dc, const char *file_name)
{
	if (!dc->root_path)
		return NULL;

	if (*file_name == '/') {
		dc->normalized_name = normalize_path_name(NULL, file_name);
		return dc->normalized_name;
	}

	dc->root_name = get_fname_from_path(dc->root_path, &dc->root_name_buff);
	if (!dc->root_name)
		return NULL;

	dc->normalized_name = normalize_path_name(dc->root_name, file_name);
	return dc->normalized_name;
}

static char *get_openat_target_name(struct defex_context *dc, const char *file_name)
{
	if (*file_name == '/') {
		dc->normalized_name = normalize_path_name(NULL, file_name);
		return dc->normalized_name;
	}

	if (!defex_get_root_path(dc, file_name))
		return NULL;

	dc->root_name = get_fname_from_path(dc->root_path, &dc->root_name_buff);
	if (!dc->root_name)
		return NULL;

	dc->normalized_name = normalize_path_name(dc->root_name, file_name);
	return dc->normalized_name;
}

static char *get_target_name(struct defex_context *dc)
{
	dc->target_name = get_fname_from_path(dc->target_dpath, &dc->target_name_buff);
	if (!dc->target_name)
		return NULL;

	return dc->target_name;
}

__visible_for_testing char *get_dc_link_name(struct defex_context *dc, const char *file_name)
{
	if (dc->syscall_no == __DEFEX_symlinkat)
		return get_symlink_target_name(dc, file_name);

	if (!dc->target_dpath && dc->syscall_no == __DEFEX_openat)
		return get_openat_target_name(dc, file_name);

	if (dc->target_dpath)
		return get_target_name(dc);

	return NULL;
}

__visible_for_testing int task_defex_link_lookup(struct defex_context *dc, const char *file_name)
{
	int ret = DEFEX_ALLOW;
	int offset_part1, is_violation = 0, saw_violation = 0;
	struct file *proc_file;
	char *proc_name = NULL, *target_name = NULL;
	struct task_struct *p = dc->task;
	struct d_tree_item found_item;
	int rules_iter, rules_max, is_system;

	if (!get_dc_process_dpath(dc))
		return ret;

	if (!(target_name = get_dc_link_name(dc, file_name)))
		return ret;

	proc_file = get_dc_process_file(dc);
	proc_name = get_dc_process_name(dc);
	is_system = check_path_is_system(target_name);

	FOR_EACH_RULES(rules_iter, rules_max, is_system) {
		is_violation = rules_lookup(target_name, feature_immutable_link, NULL,
						&found_item, 0, is_system);

		if (!is_violation || is_violation == 1)
			continue;

		is_violation = !rules_lookup(proc_name, feature_link_src_exception,
						proc_file, &found_item, 0, is_system);
		if (!is_violation) {
			saw_violation = 0;
			break;
		}

		offset_part1 = rules_lookup(proc_name, feature_link_protection, proc_file,
						&found_item, 0, is_system);

		if (!offset_part1) {
			saw_violation = 1;
			continue;
		}

		is_violation = !rules_lookup(target_name, feature_link_protection, NULL,
						&found_item, offset_part1,
						is_system);
		if (!is_violation) {
			saw_violation = 0;
			break;
		}

		saw_violation = 1;
	}

	if (saw_violation) {
		if (defex_get_features() & FEATURE_LINK_PROTECTION_ENFORCE)
			ret = -DEFEX_DENY;

		defex_log_crit("%slink protection violation [task=%s (%s), access to :%s]",
			(dc->syscall_no == __DEFEX_openat) ? "Immutable " : "",
			p->comm, proc_name, target_name);
#ifdef DEFEX_DSMS_ENABLE
		defex_report_violation(LINK_VIOLATION, 0, dc, 0, 0, 0, 0);
#endif /* DEFEX_DSMS_ENABLE */
	}

	return ret;
}

int task_defex_link_protection(struct task_struct *p, int syscall, struct path *target_path, int dfd, const char *file_name, unsigned int open_flags)
{
	int ret = DEFEX_ALLOW;

	struct defex_context dc;
	const struct local_syscall_struct *item;

	if (is_boot_state_unlocked())
		return ret;

	if (!p || p->pid == 1 || !p->mm || !is_task_used(p))
		return ret;

#if (KERNEL_VER_LESS(5, 14, 0))
	if ((p->state & (__TASK_STOPPED | TASK_DEAD))
		|| (p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)))
#else
	if ((p->__state & (__TASK_STOPPED | TASK_DEAD))
		|| (p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)))
#endif
		return ret;

	if (syscall < 0) {
		item = get_local_syscall(-syscall);
		if (!item) {
			return ret;
		}
		syscall = item->local_syscall;
	}

	if (syscall != __DEFEX_openat && syscall != __DEFEX_symlinkat && syscall != __DEFEX_linkat)
		return ret;

	get_task_struct(p);
	if (!init_defex_link_context(&dc, p, syscall, target_path, dfd, file_name, open_flags)) {
		ret =  DEFEX_ALLOW;
		goto exit;
	}

	ret = task_defex_link_lookup(&dc, file_name);
exit:
	release_defex_context(&dc);
	put_task_struct(p);
	return ret;
}
#else
int task_defex_link_protection(struct task_struct *p, int syscall, struct path *target_path, int dfd, const char *file_name, unsigned int open_flags)
{
	return DEFEX_ALLOW;
}
#endif //DEFEX_LINK_PROTECTION_ENABLE

#ifdef DEFEX_IMMUTABLE_ENABLE

/* Immutable feature decision function */
__visible_for_testing int task_defex_src_exception(struct defex_context *dc, int attribute)
{
	struct file *proc_file;
	char *target_name, *proc_name = get_dc_process_name(dc);
	int allow = 0 , standalone_allow = 0, iter_allow;
	struct d_tree_item found_item;
	int rules_iter, rules_max, is_system;

	if (!get_dc_process_dpath(dc))
		return 1;

	proc_file = get_dc_process_file(dc);
	is_system = check_path_is_system(proc_name);

	FOR_EACH_RULES(rules_iter, rules_max, is_system) {
		iter_allow = rules_lookup(proc_name, attribute,
					  proc_file, &found_item, 0, is_system);
		if (!iter_allow)
			continue;

		if ((found_item.features & d_tree_item_linked) &&
		    (found_item.features & feature_is_file) &&
		    (found_item.linked_features &
		     (feature_immutable_src_open_exception |
		      feature_immutable_src_write_exception))) {
			target_name = get_dc_target_name(dc);

			allow = rules_lookup(target_name,
					     feature_immutable_dst_exception,
					     dc->target_file, NULL, iter_allow,
					     is_system);
			if (allow)
				return allow;

			continue;
		}
		if (!standalone_allow)
			standalone_allow = iter_allow;
	}
	return standalone_allow;
}

/* Immutable feature decision function */
__visible_for_testing int task_defex_immutable(struct defex_context *dc, int attribute)
{
	int ret = DEFEX_ALLOW, is_violation = 0;
	char *proc_name, *target_name;
	struct task_struct *p = dc->task;
	int main_found = 0, exception_found = 0, exception_kind;
	int rules_iter, rules_max, is_system;

	if (!get_dc_target_dpath(dc))
		goto out;

	target_name = get_dc_target_name(dc);
	is_system = check_path_is_system(target_name);

	FOR_EACH_RULES(rules_iter, rules_max, is_system) {
		if (!rules_lookup(target_name, attribute, dc->target_file, NULL,
				  0, is_system))
			continue;

		main_found = 1;

		if (rules_lookup(target_name, feature_immutable_tgt_exception,
				 dc->target_file, NULL, 0, is_system)) {
			exception_found = 1;
			break;
		}
	}

	is_violation = main_found && !exception_found;

	if (is_violation) {
		if (!get_dc_process_dpath(dc))
			goto out;

		/* Check the Source exception and self-access */
		exception_kind = (attribute == feature_immutable_path_open) ?
					 feature_immutable_src_open_exception :
					 feature_immutable_src_write_exception;
		if (task_defex_src_exception(dc, exception_kind) ||
		    defex_files_identical(get_dc_process_file(dc),
					  dc->target_file))
			goto out;

		ret = -DEFEX_DENY;
		proc_name = get_dc_process_name(dc);
		defex_log_crit("Immutable %s violation [task=%s (%s), access to:%s]",
			(attribute == feature_immutable_path_open) ? "open" : "write",
			p->comm, proc_name, target_name);
#ifdef DEFEX_DSMS_ENABLE
		defex_report_violation(IMMUTABLE_VIOLATION, 0, dc, 0, 0, 0, 0);
#endif /* DEFEX_DSMS_ENABLE */
	}
out:
	return ret;
}

/* Immutable feature */

DEFINE_SYSCALL_CHECK(is_immutable_syscall, IMMUTABLE_SYSCALL_LIST)

static int check_immutable(struct defex_context *dc, int feature_flag, int syscall)
{
	int attribute = (syscall == __DEFEX_openat) ?
				feature_immutable_path_open : feature_immutable_path_write;

	if (feature_flag & FEATURE_IMMUTABLE) {
		if (is_immutable_syscall(syscall)) {
			if (task_defex_immutable(dc, attribute) == -DEFEX_DENY) {
				if (!(feature_flag & FEATURE_IMMUTABLE_SOFT))
					return -DEFEX_DENY;
			}
		}
	}
	return DEFEX_ALLOW;
}
#else
#define check_immutable(...) DEFEX_ALLOW
#endif /* DEFEX_IMMUTABLE_ENABLE */

#if defined(DEFEX_IMMUTABLE_ROOT_ENABLE) || defined(DEFEX_IMMUTABLE_ROOT_V2_ENABLE)
DEFINE_SYSCALL_CHECK(is_immutable_root_syscall, IMMUTABLE_ROOT_SYSCALL_LIST)
DEFINE_SYSCALL_CHECK(is_immutable_root_write_syscall, IMMUTABLE_ROOT_WRITE_SYSCALL_LIST)
#endif

#ifdef DEFEX_IMMUTABLE_ROOT_ENABLE

static inline bool path_has_prefix(const char *path, const char *prefix)
{
	return !strncmp(path, prefix, strlen(prefix));
}

/* Immutable root feature decision function */
__visible_for_testing int task_defex_immutable_root(struct defex_context *dc)
{
	int ret = DEFEX_ALLOW;
	int offset_part1, is_violation = 1;
	unsigned int attribute;
	struct file *proc_file;
	char *proc_name, *target_name;
	struct task_struct *p = dc->task;
	struct d_tree_item found_item;
	int rules_iter, rules_max, is_system;
	bool efs_access;

	if (!get_dc_target_dpath(dc) || !get_dc_process_dpath(dc))
		goto out;

	target_name = get_dc_target_name(dc);
	efs_access = path_has_prefix(target_name, "/efs/");

	/* handle feature_immutable_root case */
	if (CHECK_ROOT_CREDS(dc->cred) &&
	    (path_has_prefix(target_name, "/data/") || efs_access)) {

		/* check only write access to "/efs/" */
		if (efs_access && !is_immutable_root_write_syscall(dc->syscall_no))
			goto out;

		attribute = feature_immutable_root;
		proc_file = get_dc_process_file(dc);
		proc_name = get_dc_process_name(dc);
		is_system = check_path_is_system(proc_name);

		FOR_EACH_RULES(rules_iter, rules_max, is_system) {
			/* Check the process file */
			offset_part1 = rules_lookup(proc_name, attribute,
						    proc_file, &found_item, 0,
						    is_system);
			if (offset_part1 == 1)
				goto out;

			if (offset_part1 == 0)
				continue;

			/* Check the opening file, generate violation if rule not found */
			if (rules_lookup(target_name, attribute,
					 dc->target_file, &found_item,
					 offset_part1, is_system)) {
				is_violation = 0;
				break;
			}
		}

		if (is_violation) {
			/* Check the Source exception and self-access */
			if (defex_files_identical(get_dc_process_file(dc),
						  dc->target_file))
				goto out;

			ret = -DEFEX_DENY;

			defex_log_crit(	"Immutable root violation [task=%s (%s), access to:%s]",
					p->comm, proc_name, target_name);
#ifdef DEFEX_DSMS_ENABLE
		defex_report_violation(IMMUTABLE_VIOLATION, 0, dc, 0, 0, 0, 11);
#endif /* DEFEX_DSMS_ENABLE */
		}
	}
out:
	return ret;
}

/* Immutable root feature */
static int check_immutable_root(struct defex_context *dc, int feature_flag, int syscall)
{
	if (feature_flag & FEATURE_IMMUTABLE_ROOT) {
		if (is_immutable_root_syscall(syscall)) {
			if (task_defex_immutable_root(dc) == -DEFEX_DENY) {
				if (!(feature_flag & FEATURE_IMMUTABLE_ROOT_SOFT))
					return -DEFEX_DENY;
			}
		}
	}
	return DEFEX_ALLOW;
}
#else
#define check_immutable_root(...) DEFEX_ALLOW
#endif /* DEFEX_IMMUTABLE_ROOT_ENABLE */

#ifdef DEFEX_IMMUTABLE_ROOT_V2_ENABLE
__visible_for_testing char *get_dc_full_package_name(struct defex_context *dc)
{
	struct mm_struct *mm = get_task_mm(dc->task);
	unsigned long arg_start, arg_end;
	size_t sz, i;
	char *buffer = NULL, *ret = NULL;

	if (!mm) {
		defex_log_crit("%s: mm is null\n", __func__);
		goto out;
	}

	spin_lock(&mm->arg_lock);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	spin_unlock(&mm->arg_lock);

	sz = (arg_end > arg_start) ? (size_t)(arg_end - arg_start) : 0;

	if (sz <= 0 || sz > PAGE_SIZE) {
		defex_log_crit("%s: invalid argument length\n", __func__);
		goto out;
	}

	buffer = kzalloc(sz + 2, GFP_KERNEL);

	if (!buffer)
		goto out;

	if (copy_from_user(buffer, (void __user *) arg_start, sz) != 0) {
		defex_log_crit("%s: Failed to copy from user\n", __func__);
		goto out;
	}

	for (i = 0; i < sz; i++)
		if (buffer[i] == '\0')
			break;

	if (*buffer != '/') {
		memmove(buffer + 1, buffer, i);
		buffer[0] = '/';
		buffer[i+1] = '\0';
	}
	ret = buffer;

out:
	if (mm)
		mmput(mm);
	if (!ret && buffer)
		kfree(buffer);

	return ret;
}

__visible_for_testing int get_dc_package_name(char *full_package_name)
{
	char *colon = NULL;

	if (!full_package_name || !(*full_package_name)) {
		defex_log_crit("%s: full_package_name is null or empty\n", __func__);
		return -1;
	}

	colon = strchr(full_package_name, ':');
	if (colon)
		*colon = '\0';

	return 0;
}

/* Immutable root v2 feature decision function */
__visible_for_testing int task_defex_immutable_root_v2(struct defex_context *dc)
{
	int ret = DEFEX_ALLOW;
	int offset_part1, is_violation = 1;
	unsigned int attribute;
	struct file *proc_file;
	char *proc_name, *target_name, *pkg_name = NULL;
	struct task_struct *p = dc->task;
	struct d_tree_item found_item;
	static const char data_path_header[15] = "/data/sec_pass/";
	int rules_iter, rules_max, is_system;

	if (!get_dc_target_dpath(dc) || !get_dc_process_dpath(dc))
		goto out;

	target_name = get_dc_target_name(dc);

	if (!CHECK_ROOT_CREDS(dc->cred)
			&& !strncmp(data_path_header, target_name, sizeof(data_path_header))) {
		attribute = feature_immutable_root_v2;
		proc_file = get_dc_process_file(dc);
		proc_name = get_dc_process_name(dc);
		pkg_name = get_dc_full_package_name(dc);

		if (pkg_name) {
			if (get_dc_package_name(pkg_name) == -1)
				defex_log_crit("%s: Failed to get package name\n", __func__);
		}
		proc_name = pkg_name ? pkg_name : proc_name;
		is_system = check_path_is_system(proc_name);

		FOR_EACH_RULES(rules_iter, rules_max, is_system) {
			/* Check the process file */
			offset_part1 = rules_lookup(proc_name, attribute,
						    proc_file, &found_item, 0,
						    is_system);
			if (offset_part1 == 1)
				goto out;

			if (offset_part1 == 0)
				continue;

			/* Check the opening file, generate violation if rule not found */
			if (rules_lookup(target_name, attribute,
					 dc->target_file, &found_item,
					 offset_part1, is_system)) {
				is_violation = 0;
				break;
			}
		}

		if (is_violation) {
			/* Check the Source exception and self-access */
			if (defex_files_identical(get_dc_process_file(dc),
						  dc->target_file))
				goto out;

			ret = -DEFEX_DENY;
			defex_log_crit(
				"Immutable root v2 violation [task=%s (%s), access to:%s]",
				p->comm, proc_name, target_name);
		}
	}
out:
	kfree(pkg_name);
	return ret;
}

DEFINE_SYSCALL_CHECK(is_immutable_root_v2_syscall, IMMUTABLE_ROOT_V2_SYSCALL_LIST)

/* Immutable root feature */
static int check_immutable_root_v2(struct defex_context *dc, int feature_flag, int syscall)
{
	if (feature_flag & FEATURE_IMMUTABLE_ROOT_V2) {
		if (is_immutable_root_v2_syscall(syscall)) {
			if (task_defex_immutable_root_v2(dc) == -DEFEX_DENY) {
				if (!(feature_flag & FEATURE_IMMUTABLE_ROOT_V2_SOFT))
					return -DEFEX_DENY;
			}
		}
	}
	return DEFEX_ALLOW;
}
#else
#define check_immutable_root_v2(...) DEFEX_ALLOW
#endif /* DEFEX_IMMUTABLE_ROOT_V2_ENABLE */

/* Main decision function */
int task_defex_enforce(struct task_struct *p, struct file *f, int syscall, ...)
{
	int ret = DEFEX_ALLOW;
	int feature_flag;
	const struct local_syscall_struct *item;
	struct defex_context dc;
	va_list ap;

	if (is_boot_state_unlocked())
		return ret;

	if (!p || p->pid == 1 || !p->mm || !is_task_used(p))
		return ret;

#if (KERNEL_VER_LESS(5, 14, 0))
	if ((p->state & (__TASK_STOPPED | TASK_DEAD))
		|| (p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)))
#else
	if ((p->__state & (__TASK_STOPPED | TASK_DEAD))
		|| (p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)))
#endif
		return ret;

	if (syscall < 0) {
		item = get_local_syscall(-syscall);
		if (!item)
			return ret;
		syscall = item->local_syscall;
	}

	feature_flag = defex_get_features();
	get_task_struct(p);
	if (!init_defex_context(&dc, syscall, p, f)) {
		release_defex_context(&dc);
		put_task_struct(p);
		return DEFEX_ALLOW;
	}

	ret = check_ped(&dc, p, feature_flag);
	if (ret == -DEFEX_DENY)
		goto exit;

	ret = check_integrity(&dc, p, feature_flag, syscall);
	if (ret == -DEFEX_DENY)
		goto exit;

	ret = check_safeplace(&dc, p, feature_flag, syscall);
	if (ret == -DEFEX_DENY)
		goto exit;

	ret = check_immutable(&dc, feature_flag, syscall);
	if (ret == -DEFEX_DENY)
		goto exit;

	ret = check_immutable_root(&dc, feature_flag, syscall);
	if (ret == -DEFEX_DENY)
		goto exit;

	ret = check_immutable_root_v2(&dc, feature_flag, syscall);
	if (ret == -DEFEX_DENY)
		goto exit;

	va_start(ap, syscall);
	ret = check_trusted_map(&dc, p, feature_flag, syscall, ap);
	va_end(ap);
	if (ret == -DEFEX_DENY)
		goto exit;

exit:
	release_defex_context(&dc);
	put_task_struct(p);
	return ret;
}

int task_defex_zero_creds(struct task_struct *tsk)
{
	int is_fork = -1;

	if (tsk->flags & (PF_KTHREAD | PF_WQ_WORKER))
		return 0;
	if (is_task_creds_ready()) {
		is_fork = ((tsk->flags & PF_FORKNOEXEC) && (!tsk->on_rq));
#ifdef TASK_NEW
#if (KERNEL_VER_LESS(5, 14, 0))
		if (!is_fork && (tsk->state & TASK_NEW))
#else
		if (!is_fork && (tsk->__state & TASK_NEW))
#endif
			is_fork = 1;
#endif /* TASK_NEW */
		set_task_creds_tcnt(tsk, is_fork ? 1 : -1);
	}

#ifdef DEFEX_CACHES_ENABLE
	defex_file_cache_find(tsk->pid, true);
#endif /* DEFEX_CACHES_ENABLE */
	return 0;
}

int task_defex_user_exec(const char *new_file)
{
#ifdef DEFEX_UMH_RESTRICTION_ENABLE
	int res = DEFEX_ALLOW, is_violation = 1;
	struct file *fp = NULL;
	static unsigned int rules_load_cnt;
	int rules_iter, rules_max, is_system;

	if (is_boot_state_unlocked())
		return DEFEX_ALLOW;

	if (!check_rules_ready()) {
		if (rules_load_cnt++%100 == 0)
			defex_log_warn("Rules not ready");
		goto umh_out;
	}

	if (current == NULL || current->fs == NULL)
		goto umh_out;

	fp = local_fopen(new_file, O_RDONLY, 0);
	if (IS_ERR(fp) || (fp == NULL)) {
		res = DEFEX_DENY;
		goto umh_out;
	} else {
		filp_close(fp, NULL);
	}
	
	is_system = check_path_is_system(new_file);

	FOR_EACH_RULES(rules_iter, rules_max, is_system) {
		if (rules_lookup(new_file, feature_umhbin_path, NULL, NULL, 0,
				 is_system)) {
			is_violation = 0;
			break;
		}
	}

	if (is_violation) {
		defex_log_warn("UMH Exec Denied: %s", new_file);
		res = DEFEX_DENY;
		goto umh_out;
	}

umh_out:
	return res;
#else
	return DEFEX_ALLOW;
#endif /* DEFEX_UMH_RESTRICTION_ENABLE */
}
