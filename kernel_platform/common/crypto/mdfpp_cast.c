// SPDX-License-Identifier: GPL-2.0
//
// In Samsung R&D Institute Ukraine, LLC (SRUKR) under a contract between
// Samsung R&D Institute Ukraine, LLC (Kyiv, Ukraine)
// and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
// Copyright: (c) Samsung Electronics Co, Ltd 2026. All rights reserved.
//

#include <linux/kernel.h>
#include <linux/module.h>

#include "aes_gcm_mdfpp_cast.h"

static int __init mdfpp_cast_init(void)
{

	aes_gcm_mdfpp_cast();

	return 0;
}

late_initcall(mdfpp_cast_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MDFPP CAST");
