// SPDX-License-Identifier: GPL-2.0
/*
 * FIVE State machine
 *
 * Copyright (C) 2017 Samsung Electronics, Inc.
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
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

#if IS_BUILTIN(CONFIG_FIVE)
#include <linux/task_integrity.h>
#else
#include <linux/sched.h>
#include "task_integrity.h"
#endif

#include "five_audit.h"
#include "five_state.h"
#include "five_hooks.h"
#include "five_cache.h"
#include "five_testing.h"

enum task_integrity_state_cause {
	STATE_CAUSE_UNKNOWN,
	STATE_CAUSE_DIGSIG,
	STATE_CAUSE_DMV_PROTECTED,
	STATE_CAUSE_TRUSTED,
	STATE_CAUSE_HMAC,           // deprecated
	STATE_CAUSE_SYSTEM_LABEL,   // deprecated
	STATE_CAUSE_NOCERT,
	STATE_CAUSE_TAMPERED,
	STATE_CAUSE_MISMATCH_LABEL, // deprecated
	STATE_CAUSE_FSV_PROTECTED
};

struct task_verification_result {
	enum task_integrity_value new_tint;
	enum task_integrity_value prev_tint;
	enum task_integrity_state_cause cause;
};

__visible_for_testing
const char *task_integrity_state_str(
		enum task_integrity_state_cause cause)
{
	const char *str = "unknown";

	switch (cause) {
	case STATE_CAUSE_DIGSIG:
		str = "digsig";
		break;
	case STATE_CAUSE_DMV_PROTECTED:
		str = "dmv_protected";
		break;
	case STATE_CAUSE_FSV_PROTECTED:
		str = "fsv_protected";
		break;
	case STATE_CAUSE_TRUSTED:
		str = "trusted";
		break;
	case STATE_CAUSE_HMAC:
		str = "hmac";
		break;
	case STATE_CAUSE_SYSTEM_LABEL:
		str = "system_label";
		break;
	case STATE_CAUSE_NOCERT:
		str = "nocert";
		break;
	case STATE_CAUSE_MISMATCH_LABEL:
		str = "mismatch_label";
		break;
	case STATE_CAUSE_TAMPERED:
		str = "tampered";
		break;
	case STATE_CAUSE_UNKNOWN:
		str = "unknown";
		break;
	}

	return str;
}

__visible_for_testing
enum task_integrity_reset_cause state_to_reason_cause(
		enum task_integrity_state_cause cause)
{
	enum task_integrity_reset_cause reset_cause;

	switch (cause) {
	case STATE_CAUSE_UNKNOWN:
		reset_cause = CAUSE_UNKNOWN;
		break;
	case STATE_CAUSE_TAMPERED:
		reset_cause = CAUSE_TAMPERED;
		break;
	case STATE_CAUSE_NOCERT:
		reset_cause = CAUSE_NO_CERT;
		break;
	case STATE_CAUSE_MISMATCH_LABEL:
		reset_cause = CAUSE_MISMATCH_LABEL;
		break;
	default:
		/* Integrity is not NONE. */
		reset_cause = CAUSE_UNSET;
		break;
	}

	return reset_cause;
}

const char *task_integrity_reset_str(
		enum task_integrity_reset_cause cause)
{
	const char *str = NULL;

	switch (cause) {
	case CAUSE_TAMPERED:
		str = "tampered";
		break;
	case CAUSE_NO_CERT:
		str = "nocert";
		break;
	case CAUSE_MISMATCH_LABEL:
		str = "mismatch_label";
		break;
	case CAUSE_UNSET:
		str = "unset";
		break;
	case CAUSE_BAD_FS:
		str = "bad_fs";
		break;
	case CAUSE_INVALID_HASH_LENGTH:
		str = "invalid_hash_len";
		break;
	case CAUSE_INVALID_HEADER:
		str = "invalid_header";
		break;
	case CAUSE_CALC_HASH_FAILED:
		str = "calc_hash_failed";
		break;
	case CAUSE_INVALID_LABEL_DATA:
		str = "invalid_label_data";
		break;
	case CAUSE_INVALID_SIGNATURE_DATA:
		str = "invalid_sign_data";
		break;
	case CAUSE_INVALID_HASH:
		str = "invalid_hash";
		break;
	case CAUSE_INVALID_CALC_CERT_HASH:
		str = "invalid_calc_cert_hash";
		break;
	case CAUSE_INVALID_UPDATE_LABEL:
		str = "invalid_update_label";
		break;
	case CAUSE_INVALID_SIGNATURE:
		str = "invalid_signature";
		break;
	case CAUSE_UKNOWN_FIVE_DATA:
		str = "unknown_five_data";
		break;
	case CAUSE_PTRACE:
		str = "ptrace";
		break;
	case CAUSE_VMRW:
		str = "vmrw";
		break;
	case CAUSE_EXEC:
		str = "exec";
		break;
	default:
		str = "reset_integrity";
		break;
	}
	return str;
}

#if IS_MODULE(CONFIG_FIVE)
EXPORT_SYMBOL_GPL(task_integrity_reset_str);
#endif

__visible_for_testing
bool set_first_state(struct five_iint_cache *iint,
				struct task_integrity *integrity,
				struct task_verification_result *result)
{
	enum task_integrity_value tint = INTEGRITY_NONE;
	enum five_file_integrity status = five_get_cache_status(iint);
	bool trusted_file = iint->five_flags & FIVE_TRUSTED_FILE;
	enum task_integrity_state_cause cause = STATE_CAUSE_UNKNOWN;

	result->new_tint = result->prev_tint = task_integrity_read(integrity);
	task_integrity_clear(integrity);

	switch (status) {
	case FIVE_FILE_FSVERITY:
	case FIVE_FILE_DMVERITY:
		if (trusted_file) {
			cause = STATE_CAUSE_TRUSTED;
		} else {
			cause = (status == FIVE_FILE_FSVERITY)
				? STATE_CAUSE_FSV_PROTECTED
				: STATE_CAUSE_DMV_PROTECTED;
		}
		tint = INTEGRITY_DMVERITY;
		break;
	case FIVE_FILE_HMAC:
		cause = STATE_CAUSE_HMAC;
		tint = INTEGRITY_MIXED;
		break;
	case FIVE_FILE_FAIL:
		cause = STATE_CAUSE_TAMPERED;
		tint = INTEGRITY_NONE;
		break;
	case FIVE_FILE_UNKNOWN:
		cause = STATE_CAUSE_NOCERT;
		tint = INTEGRITY_NONE;
		break;
	default:
		cause = STATE_CAUSE_NOCERT;
		tint = INTEGRITY_NONE;
		break;
	}

	task_integrity_set(integrity, tint);
	result->new_tint = tint;
	result->cause = cause;

	return true;
}

__visible_for_testing
bool set_next_state(struct five_iint_cache *iint,
			   struct task_integrity *integrity,
			   struct task_verification_result *result)
{
	bool is_newstate = false;
	enum five_file_integrity status = five_get_cache_status(iint);
	bool dmv_protected = (status == FIVE_FILE_DMVERITY);
	bool fsv_protected = (status == FIVE_FILE_FSVERITY);
	bool xv_protected = dmv_protected || fsv_protected;
	enum task_integrity_state_cause cause = STATE_CAUSE_UNKNOWN;
	enum task_integrity_value state_tint = INTEGRITY_NONE;

	result->new_tint = result->prev_tint = task_integrity_read(integrity);

	if (status == FIVE_FILE_UNKNOWN || status == FIVE_FILE_FAIL) {
		spin_lock(&integrity->value_lock);

		if (status == FIVE_FILE_UNKNOWN)
			cause = STATE_CAUSE_NOCERT;
		else
			cause = STATE_CAUSE_TAMPERED;

		state_tint = INTEGRITY_NONE;
		is_newstate = true;
		goto out;
	}

	spin_lock(&integrity->value_lock);
	switch (integrity->value) {
	case INTEGRITY_PRELOAD:
		if (xv_protected) {
			cause = fsv_protected ? STATE_CAUSE_FSV_PROTECTED
						: STATE_CAUSE_DMV_PROTECTED;
			state_tint = INTEGRITY_DMVERITY;
		} else {
			cause = STATE_CAUSE_HMAC;
			state_tint = INTEGRITY_MIXED;
		}
		is_newstate = true;
		break;
	case INTEGRITY_DMVERITY:
		if (!xv_protected) {
			cause = STATE_CAUSE_HMAC;
			state_tint = INTEGRITY_MIXED;
			is_newstate = true;
		}
		break;
	case INTEGRITY_MIXED:
		break;
	case INTEGRITY_NONE:
		break;
	default:
		// Unknown or unused (deprecated) state
		cause = STATE_CAUSE_UNKNOWN;
		state_tint = INTEGRITY_NONE;
		is_newstate = true;
	}

out:

	if (is_newstate) {
		__task_integrity_set(integrity, state_tint);
		result->new_tint = state_tint;
		result->cause = cause;
	}
	spin_unlock(&integrity->value_lock);

	return is_newstate;
}

void five_state_proceed(struct task_integrity *integrity,
			struct file_verification_result *file_result)
{
	struct five_iint_cache *iint = file_result->iint;
	enum five_hooks fn = file_result->fn;
	struct task_struct *task = file_result->task;
	struct file *file = file_result->file;
	bool is_newstate;
	struct task_verification_result task_result = {};

	if (!iint)
		return;

	if (fn == BPRM_CHECK)
		is_newstate = set_first_state(iint, integrity, &task_result);
	else
		is_newstate = set_next_state(iint, integrity, &task_result);

	if (is_newstate) {
		if (task_result.new_tint == INTEGRITY_NONE) {
			task_integrity_set_reset_reason(integrity,
				state_to_reason_cause(task_result.cause), file);
			five_hook_integrity_reset(task, file,
				state_to_reason_cause(task_result.cause));
		}
		five_audit_verbose(task, file, five_get_string_fn(fn),
			task_result.prev_tint, task_result.new_tint,
			task_integrity_state_str(task_result.cause),
			file_result->five_result);
	}
}

#if IS_BUILTIN(CONFIG_FIVE) && defined(CONFIG_SEC_KUNIT)
EXPORT_SYMBOL_GPL(task_integrity_state_str);
EXPORT_SYMBOL_GPL(state_to_reason_cause);
EXPORT_SYMBOL_GPL(set_next_state);
EXPORT_SYMBOL_GPL(set_first_state);
EXPORT_SYMBOL_GPL(five_state_proceed);
#endif
