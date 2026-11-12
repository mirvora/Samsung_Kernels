// SPDX-License-Identifier: GPL-2.0
//
// In Samsung R&D Institute Ukraine, LLC (SRUKR) under a contract between
// Samsung R&D Institute Ukraine, LLC (Kyiv, Ukraine)
// and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
// Copyright: (c) Samsung Electronics Co, Ltd 2026. All rights reserved.
//

#include <crypto/aead.h>

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#define TEST_ENCRYPT 1
#define TEST_DECRYPT 0

#define MAX_SIZE_IV  64

struct aead_testvec {
	const char *key;
	const char *iv;
	const char *ptext;
	const char *a_data;
	const char *ctext;
	unsigned int k_size;
	unsigned int pt_size;
	unsigned int a_size;
	unsigned int ct_size;
};

struct aead_test_suite {
	const struct aead_testvec *vecs;
	size_t tv_count;
};

static const char zeroed_string[MAX_SIZE_IV] = {0};

static const struct aead_testvec aes_gcm_rfc4106_tv_template[] = {
	{
		.key = "\xfe\xff\xe9\x92\x86\x65\x73\x1c"
			  "\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			  "\x00\x00\x00\x00",
		.k_size = 20,
		.iv = zeroed_string,
		.ptext = "\x01\x01\x01\x01\x01\x01\x01\x01"
			  "\x01\x01\x01\x01\x01\x01\x01\x01",
		.pt_size = 16,
		.a_data = zeroed_string,
		.a_size = 16,
		.ctext = "\x4B\xB1\xB5\xE3\x25\x71\x70\xDE"
			  "\x7F\xC9\x9C\xA5\x14\x19\xF2\xAC"
			  "\x0B\x8F\x88\x69\x17\xE6\xB4\x3C"
			  "\xB1\x68\xFD\x14\x52\x64\x61\xB2",
		.ct_size = 32,
	}, {
		.key = "\xFE\xFF\xE9\x92\x86\x65\x73\x1C"
			  "\x6D\x6A\x8F\x94\x67\x30\x83\x08"
			  "\xFE\xFF\xE9\x92\x86\x65\x73\x1C"
			  "\xCA\xFE\xBA\xBE",
		.k_size = 28,
		.iv = "\xFA\xCE\xDB\xAD\xDE\xCA\xF8\x88",
		.ptext = "\x45\x00\x00\x28\xA4\xAD\x40\x00"
			  "\x40\x06\x78\x80\x0A\x01\x03\x8F"
			  "\x0A\x01\x06\x12\x80\x23\x06\xB8"
			  "\xCB\x71\x26\x02\xDD\x6B\xB0\x3E"
			  "\x50\x10\x16\xD0\x75\x68\x00\x01",
		.pt_size = 40,
		.a_data = "\x00\x00\xA5\xF8\x00\x00\x00\x0A"
			  "\xFA\xCE\xDB\xAD\xDE\xCA\xF8\x88",
		.a_size = 16,
		.ctext = "\xA5\xB1\xF8\x06\x60\x29\xAE\xA4"
			  "\x0E\x59\x8B\x81\x22\xDE\x02\x42"
			  "\x09\x38\xB3\xAB\x33\xF8\x28\xE6"
			  "\x87\xB8\x85\x8B\x5B\xFB\xDB\xD0"
			  "\x31\x5B\x27\x45\x21\x44\xCC\x77"
			  "\x95\x45\x7B\x96\x52\x03\x7F\x53"
			  "\x18\x02\x7B\x5B\x4C\xD7\xA6\x36",
		.ct_size = 56,
	}, {
		.key = "\xAB\xBC\xCD\xDE\xF0\x01\x12\x23"
			  "\x34\x45\x56\x67\x78\x89\x9A\xAB"
			  "\xAB\xBC\xCD\xDE\xF0\x01\x12\x23"
			  "\x34\x45\x56\x67\x78\x89\x9A\xAB"
			  "\x11\x22\x33\x44",
		.k_size = 36,
		.iv = "\x01\x02\x03\x04\x05\x06\x07\x08",
		.ptext = "\x45\x00\x00\x30\x69\xA6\x40\x00"
			  "\x80\x06\x26\x90\xC0\xA8\x01\x02"
			  "\x93\x89\x15\x5E\x0A\x9E\x00\x8B"
			  "\x2D\xC5\x7E\xE0\x00\x00\x00\x00"
			  "\x70\x02\x40\x00\x20\xBF\x00\x00"
			  "\x02\x04\x05\xB4\x01\x01\x04\x02"
			  "\x01\x02\x02\x01",
		.pt_size = 52,
		.a_data = "\x4A\x2C\xBF\xE3\x00\x00\x00\x02"
			  "\x01\x02\x03\x04\x05\x06\x07\x08",
		.a_size = 16,
		.ctext = "\xFF\x42\x5C\x9B\x72\x45\x99\xDF"
			  "\x7A\x3B\xCD\x51\x01\x94\xE0\x0D"
			  "\x6A\x78\x10\x7F\x1B\x0B\x1C\xBF"
			  "\x06\xEF\xAE\x9D\x65\xA5\xD7\x63"
			  "\x74\x8A\x63\x79\x85\x77\x1D\x34"
			  "\x7F\x05\x45\x65\x9F\x14\xE9\x9D"
			  "\xEF\x84\x2D\x8E\xB3\x35\xF4\xEE"
			  "\xCF\xDB\xF8\x31\x82\x4B\x4C\x49"
			  "\x15\x95\x6C\x96",
		.ct_size = 68,
	}
};

static const struct aead_testvec aes_gcm_tv_template[] = {
	{
		.key = "\xfe\xff\xe9\x92\x86\x65\x73\x1c"
			  "\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.k_size = 16,
		.iv = "\xca\xfe\xba\xbe\xfa\xce\xdb\xad"
			  "\xde\xca\xf8\x88",
		.ptext = "\xd9\x31\x32\x25\xf8\x84\x06\xe5"
			  "\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
			  "\x86\xa7\xa9\x53\x15\x34\xf7\xda"
			  "\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
			  "\x1c\x3c\x0c\x95\x95\x68\x09\x53"
			  "\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
			  "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57"
			  "\xba\x63\x7b\x39",
		.pt_size = 60,
		.a_data = "\xfe\xed\xfa\xce\xde\xad\xbe\xef"
			  "\xfe\xed\xfa\xce\xde\xad\xbe\xef"
			  "\xab\xad\xda\xd2",
		.a_size = 20,
		.ctext = "\x42\x83\x1e\xc2\x21\x77\x74\x24"
			  "\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
			  "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0"
			  "\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
			  "\x21\xd5\x14\xb2\x54\x66\x93\x1c"
			  "\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
			  "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97"
			  "\x3d\x58\xe0\x91"
			  "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb"
			  "\x94\xfa\xe9\x5a\xe7\x12\x1a\x47",
		.ct_size = 76,
	}, {
		.key = zeroed_string,
		.k_size = 24,
		.ctext = "\xcd\x33\xb2\x8a\xc7\x73\xf7\x4b"
			  "\xa0\x0e\xd1\xf3\x12\x57\x24\x35",
		.ct_size = 16,
	}, {
		.key = zeroed_string,
		.k_size = 32,
		.ptext = zeroed_string,
		.pt_size = 16,
		.ctext = "\xce\xa7\x40\x3d\x4d\x60\x6b\x6e"
			  "\x07\x4e\xc5\xd3\xba\xf3\x9d\x18"
			  "\xd0\xd1\xc8\xa7\x99\x99\x6b\xf0"
			  "\x26\x5b\x98\xb5\xd4\x8a\xb9\x19",
		.ct_size = 32,
	}
};

static const struct aead_test_suite aes_gcm_tv = {
	aes_gcm_tv_template,
	ARRAY_SIZE(aes_gcm_tv_template),
};

static const struct aead_test_suite aes_gcm_rfc4106_tv = {
	aes_gcm_rfc4106_tv_template,
	ARRAY_SIZE(aes_gcm_rfc4106_tv_template),
};

static int __test_aead(struct crypto_aead *tfm,
						uint32_t enc,
						const struct aead_testvec *tv)
{
	int ret = -EINVAL;
	uint8_t iv[MAX_SIZE_IV] = {0};
	uint32_t iv_size = 0;
	uint8_t *buff = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	uint32_t auth_size = 0;
	size_t buff_size = 0;
	const uint8_t *ptext = tv->pt_size ? tv->ptext : zeroed_string;
	const uint8_t *ctext = tv->ct_size ? tv->ctext : zeroed_string;
	const uint8_t *a_data = tv->a_size ? tv->a_data : zeroed_string;

	if (tv->ct_size < tv->pt_size)
		return -EINVAL;
	auth_size = tv->ct_size - tv->pt_size;

	iv_size = crypto_aead_ivsize(tfm);
	if (iv_size > sizeof(iv))
		return -EINVAL;

	if (tv->iv)
		memcpy(iv, tv->iv, iv_size);

	buff_size = tv->a_size + tv->ct_size;
	buff = kmalloc(buff_size, GFP_KERNEL);
	if (!buff)
		goto error_clean;

	memcpy(&buff[0], a_data, tv->a_size);
	memcpy(&buff[tv->a_size],
		enc ? ptext : ctext,
		enc ? tv->pt_size : tv->ct_size);

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto error_clean;

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);

	crypto_aead_clear_flags(tfm, ~0);

	ret = crypto_aead_setkey(tfm, tv->key, tv->k_size);
	if (ret)
		goto error_clean;

	ret = crypto_aead_setauthsize(tfm, auth_size);
	if (ret)
		goto error_clean;

	sg_init_one(&sg, buff, buff_size);

	aead_request_set_crypt(req, &sg, &sg, enc ? tv->pt_size : tv->ct_size, iv);

	aead_request_set_ad(req, tv->a_size);

	ret = enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req);
	ret = crypto_wait_req(ret, &wait);
	if (ret)
		goto error_clean;

	if (memcmp(&buff[tv->a_size],
			enc ? ctext : ptext,
			enc ? tv->ct_size : tv->pt_size)) {
		ret = -EINVAL;
		goto error_clean;
	}

	ret = 0;

error_clean:
	if (req)
		aead_request_free(req);
	if (buff)
		kfree_sensitive(buff);

	return ret;
}

static int test_aead(const struct aead_test_suite *tv,
					const char *alg_name,
					uint32_t type,
					uint32_t mask)
{
	struct crypto_aead *tfm;
	int err = -EINVAL;
	size_t i = 0;

	tfm = crypto_alloc_aead(alg_name, type, mask);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	for (i = 0; i < tv->tv_count; i++) {
		err = __test_aead(tfm, TEST_ENCRYPT, &tv->vecs[i]);
		if (err) {
			pr_err("MDFPP CAST  : %s, test encrypt %zu failed, err=%d.\n", alg_name, i, err);
			goto out;
		}
	}

	for (i = 0; i < tv->tv_count; i++) {
		err = __test_aead(tfm, TEST_DECRYPT, &tv->vecs[i]);
		if (err) {
			pr_err("MDFPP CAST  : %s, test decrypt %zu failed, err=%d.\n", alg_name, i, err);
			goto out;
		}
	}

	pr_info("MDFPP CAST : self-tests for %s passed.\n", alg_name);

out:
	if (tfm)
		crypto_free_aead(tfm);
	return err;
}

void aes_gcm_mdfpp_cast(void)
{
	int ret = 0;

	ret |= test_aead(&aes_gcm_tv, "gcm_base(ctr(aes-generic),ghash-generic)", 0, 0);
	ret |= test_aead(&aes_gcm_tv, "gcm_base(ctr(aes-ce),ghash-generic)", 0, 0);
	ret |= test_aead(&aes_gcm_rfc4106_tv, "rfc4106(gcm_base(ctr(aes-generic),ghash-generic))", 0, 0);
	ret |= test_aead(&aes_gcm_rfc4106_tv, "rfc4106(gcm_base(ctr(aes-ce),ghash-generic))", 0, 0);

	if (ret)
		panic("MDFPP CAST : one or more tests failed.\n");
}
