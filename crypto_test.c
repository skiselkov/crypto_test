/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://opensource.org/licenses/CDDL-1.0
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2014 by Saso Kiselkov. All rights reserved.
 */

#include <sys/modctl.h>
#include <sys/byteorder.h>
#include <sys/cmn_err.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/spi.h>
#include <sys/strsun.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>

#define CHECK

#define	ENCBLKSZ	(128 * 1024)
#define	OUTER_ROUNDS	1024ULL
#define	INNER_ROUNDS	48
#define	CRYPTO_SET_RAW_DATA(obj, d, l)		\
	do {					\
		obj.cd_format = CRYPTO_DATA_RAW;\
		obj.cd_miscdata = NULL;		\
		obj.cd_length = l;		\
		obj.cd_offset = 0;		\
		obj.cd_raw.iov_base = (void *)d;\
		obj.cd_raw.iov_len = l;		\
	} while (0)
#define	CRYPTO_SET_RAW_KEY(obj, k, l)			\
	do {						\
		obj.ck_format = CRYPTO_KEY_RAW;		\
		obj.ck_data = (void *)k;		\
		obj.ck_length = CRYPTO_BYTES2BITS(l);	\
	} while (0)
#define	GCM_PARAM_SET(param, iv, iv_len, AAD, AAD_len, tag_len)		\
	do {								\
		param.pIv = iv;						\
		param.ulIvLen = iv_len;					\
		param.ulIvBits = CRYPTO_BYTES2BITS(iv_len);		\
		param.pAAD = AAD;					\
		param.ulAADLen = AAD_len;				\
		param.ulTagBits = CRYPTO_BYTES2BITS(tag_len);		\
	} while (0)

#define	AES_BLOCK(x) \
	(unsigned long long) ntohll(((uint64_t *)x)[0]), \
	(unsigned long long) ntohll(((uint64_t *)x)[1])

#define	ECB_NCOPIES	16

static struct modlinkage modlinkage = {
	.ml_rev =	MODREV_1,
	.ml_linkage =	{ NULL }
};

static void speed_test(const char *mech_name, boolean_t encrypt);
static void test_ecb_all(void);
static void test_cbc_all(void);
static void test_ctr_all(void);
static void test_gcm_all(void);

/*
 * GCM test vectors from Appendix B of:
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents\
 * /proposedmodes/gcm/gcm-revised-spec.pdf
 */

/* Test Case 1 */
static uint8_t gcm_tc1_K[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t gcm_tc1_IV[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static uint8_t gcm_tc1_T[] = {
	0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
	0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
};

/* Test Case 2 */
static uint8_t gcm_tc2_pt[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t gcm_tc2_ct[] = {
	0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
	0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
};

static uint8_t gcm_tc2_T[] = {
	0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
	0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
};

static uint8_t gcm_tc3_K[] = {
	0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
	0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

/* Test Case 3 */
static uint8_t gcm_tc3_IV[] = {
	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
	0xde, 0xca, 0xf8, 0x88
};

static uint8_t gcm_tc3_pt[] = {
	0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
	0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
	0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
	0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
	0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
	0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
	0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
	0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};

static uint8_t gcm_tc3_ct[] = {
	0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
	0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
	0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
	0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
	0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
	0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
	0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
	0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85
};

static uint8_t gcm_tc3_T[] = {
	0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
	0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4
};

/* Test Case 4 */
static uint8_t gcm_tc4_A[] = {
	0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	0xab, 0xad, 0xda, 0xd2
};

static uint8_t gcm_tc4_T[] = {
	0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
	0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

/* Test Case 5 */
static uint8_t gcm_tc5_IV[] = {
	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad
};

static uint8_t gcm_tc5_ct[] = {
	0x61, 0x35, 0x3b, 0x4c, 0x28, 0x06, 0x93, 0x4a,
	0x77, 0x7f, 0xf5, 0x1f, 0xa2, 0x2a, 0x47, 0x55,
	0x69, 0x9b, 0x2a, 0x71, 0x4f, 0xcd, 0xc6, 0xf8,
	0x37, 0x66, 0xe5, 0xf9, 0x7b, 0x6c, 0x74, 0x23,
	0x73, 0x80, 0x69, 0x00, 0xe4, 0x9f, 0x24, 0xb2,
	0x2b, 0x09, 0x75, 0x44, 0xd4, 0x89, 0x6b, 0x42,
	0x49, 0x89, 0xb5, 0xe1, 0xeb, 0xac, 0x0f, 0x07,
	0xc2, 0x3f, 0x45, 0x98
};

static uint8_t gcm_tc5_T[] = {
	0x36, 0x12, 0xd2, 0xe7, 0x9e, 0x3b, 0x07, 0x85,
	0x56, 0x1b, 0xe1, 0x4a, 0xac, 0xa2, 0xfc, 0xcb
};

/* Test Case 6 */
static uint8_t gcm_tc6_IV[] = {
	0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
	0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
	0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
	0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
	0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
	0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
	0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
	0xa6, 0x37, 0xb3, 0x9b
};

static uint8_t gcm_tc6_ct[] = {
	0x8c, 0xe2, 0x49, 0x98, 0x62, 0x56, 0x15, 0xb6,
	0x03, 0xa0, 0x33, 0xac, 0xa1, 0x3f, 0xb8, 0x94,
	0xbe, 0x91, 0x12, 0xa5, 0xc3, 0xa2, 0x11, 0xa8,
	0xba, 0x26, 0x2a, 0x3c, 0xca, 0x7e, 0x2c, 0xa7,
	0x01, 0xe4, 0xa9, 0xa4, 0xfb, 0xa4, 0x3c, 0x90,
	0xcc, 0xdc, 0xb2, 0x81, 0xd4, 0x8c, 0x7c, 0x6f,
	0xd6, 0x28, 0x75, 0xd2, 0xac, 0xa4, 0x17, 0x03,
	0x4c, 0x34, 0xae, 0xe5
};

static uint8_t gcm_tc6_T[] = {
	0x61, 0x9c, 0xc5, 0xae, 0xff, 0xfe, 0x0b, 0xfa,
	0x46, 0x2a, 0xf4, 0x3c, 0x16, 0x99, 0xd0, 0x50
};

/* Test Case 7 */
static uint8_t gcm_tc7_K[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * ECB KAT vectors from:
 * http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
 */

/* ECBVarTxt128.rsp */
static uint8_t ecb_tc1_K[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t ecb_tc1_pt[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static uint8_t ecb_tc1_ct[] = {
	0x3f, 0x5b, 0x8c, 0xc9, 0xea, 0x85, 0x5a, 0x0a,
	0xfa, 0x73, 0x47, 0xd2, 0x3e, 0x8d, 0x66, 0x4e
};

/*
 * ECBVarKey128.rsp
 */
static uint8_t ecb_tc2_K[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static uint8_t ecb_tc2_pt[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t ecb_tc2_ct[] = {
	0xa1, 0xf6, 0x25, 0x8c, 0x87, 0x7d, 0x5f, 0xcd,
	0x89, 0x64, 0x48, 0x45, 0x38, 0xbf, 0xc9, 0x2c
};

/* ECBVarTxt192.rsp */
static uint8_t ecb_tc3_K[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define	ecb_tc3_pt	ecb_tc1_pt
static uint8_t ecb_tc3_ct[] = {
	0xb1, 0x3d, 0xb4, 0xda, 0x1f, 0x71, 0x8b, 0xc6,
	0x90, 0x47, 0x97, 0xc8, 0x2b, 0xcf, 0x2d, 0x32
};

/* ECBVarKey192.rsp */
static uint8_t ecb_tc4_K[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
#define	ecb_tc4_pt	ecb_tc2_pt
static uint8_t ecb_tc4_ct[] = {
	0xdd, 0x8a, 0x49, 0x35, 0x14, 0x23, 0x1c, 0xbf,
	0x56, 0xec, 0xce, 0xe4, 0xc4, 0x08, 0x89, 0xfb
};

/* ECBVarTxt256.rsp */
static uint8_t ecb_tc5_K[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define ecb_tc5_pt	ecb_tc1_pt
static uint8_t ecb_tc5_ct[] = {
	0xac, 0xda, 0xce, 0x80, 0x78, 0xa3, 0x2b, 0x1a,
	0x18, 0x2b, 0xfa, 0x49, 0x87, 0xca, 0x13, 0x47
};

/* ECBVarKey256.rsp */
static uint8_t ecb_tc6_K[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
#define	ecb_tc6_pt	ecb_tc2_pt
static uint8_t ecb_tc6_ct[] = {
	0x4b, 0xf8, 0x5f, 0x1b, 0x5d, 0x54, 0xad, 0xbc,
	0x30, 0x7b, 0x0a, 0x04, 0x83, 0x89, 0xad, 0xcb
};

/*
 * CBC & CTR KAT vectors from:
 * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 */

/* F.2.1 (pp.27) CBC-AES128 */
static uint8_t cbc_tc1_K[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static uint8_t cbc_tc1_IV[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static uint8_t cbc_tc1_pt[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static uint8_t cbc_tc1_ct[] = {
	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
	0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
	0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
	0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
	0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
	0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
	0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
	0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

/* F.2.3 (pp.28) CBC-AES192 */
static uint8_t cbc_tc2_K[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
	0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};
#define	cbc_tc2_IV	cbc_tc1_IV
#define	cbc_tc2_pt	cbc_tc1_pt
static uint8_t cbc_tc2_ct[] = {
	0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
	0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
	0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
	0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
	0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
	0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
	0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
	0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd
};

/* F.2.5 (pp.28) CBC-AES256 */
static uint8_t cbc_tc3_K[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
#define	cbc_tc3_IV	cbc_tc1_IV
#define	cbc_tc3_pt	cbc_tc1_pt
static uint8_t cbc_tc3_ct[] = {
	0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
	0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
	0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
	0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
	0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
	0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
	0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
	0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};

/* F.5.1 (pp.55) CTR-AES128 */
#define	ctr_tc1_K	cbc_tc1_K
static CK_AES_CTR_PARAMS ctr_tc1_IV = {
	.ulCounterBits = 128,
	.cb = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	}
};
#define	ctr_tc1_pt	cbc_tc1_pt
static uint8_t ctr_tc1_ct[] = {
	0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
	0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
	0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
	0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
	0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
	0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
	0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
	0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
};

/* F.5.3 (pp.56) CTR-AES192 */
#define	ctr_tc2_K	cbc_tc2_K
static CK_AES_CTR_PARAMS ctr_tc2_IV = {
	.ulCounterBits = 128,
	.cb = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	}
};
#define	ctr_tc2_pt	cbc_tc1_pt
static uint8_t ctr_tc2_ct[] = {
	0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2,
	0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b,
	0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef,
	0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94,
	0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70,
	0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7,
	0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58,
	0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50
};

/* F.5.5 (pp.57) CTR-AES256 */
#define	ctr_tc3_K	cbc_tc3_K
static CK_AES_CTR_PARAMS ctr_tc3_IV = {
	.ulCounterBits = 128,
	.cb = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	}
};
#define	ctr_tc3_pt	cbc_tc1_pt
static uint8_t ctr_tc3_ct[] = {
	0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
	0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
	0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
	0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
	0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
	0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
	0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
	0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
};

int
_init(void)
{
#ifdef CHECK
	test_ecb_all();
	test_cbc_all();
	test_ctr_all();
	test_gcm_all();
#else
	speed_test(SUN_CKM_AES_GCM, B_TRUE);
	speed_test(SUN_CKM_AES_CBC, B_TRUE);
	speed_test(SUN_CKM_AES_CTR, B_TRUE);
	speed_test(SUN_CKM_AES_ECB, B_TRUE);
	speed_test(SUN_CKM_AES_GCM, B_FALSE);
	speed_test(SUN_CKM_AES_CBC, B_FALSE);
	speed_test(SUN_CKM_AES_CTR, B_FALSE);
	speed_test(SUN_CKM_AES_ECB, B_FALSE);
#endif

	return (EACCES);
}

static void
speed_test(const char *mech_name, boolean_t encrypt)
{
	int ret;
	uint8_t K[16];
	uint8_t token[16], iv[16];
	crypto_data_t kcf_input, kcf_output, kcf_token;
	CK_AES_GCM_PARAMS gcm_params = { iv, 12, 12 * 8, NULL, 0, 128 };
	CK_AES_CTR_PARAMS ctr_params = {
	    64, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	};
	crypto_key_t kcf_K = {
	    .ck_format = CRYPTO_KEY_RAW,
	    .ck_data = (void *)K,
	    .ck_length = CRYPTO_BYTES2BITS(sizeof (K))
	};
	uint8_t *input = kmem_zalloc(ENCBLKSZ, KM_SLEEP);
	uint8_t *output = kmem_zalloc(INNER_ROUNDS * ENCBLKSZ + 16, KM_SLEEP);
	crypto_mechanism_t mech;
	crypto_context_t ctx;
	clock_t start, end;
	boolean_t first_block = B_TRUE;
	if (strcmp(mech_name, SUN_CKM_AES_GCM) == 0) {
		mech.cm_type = crypto_mech2id(SUN_CKM_AES_GCM);
		mech.cm_param = (void *)&gcm_params;
		mech.cm_param_len = sizeof (gcm_params);
	} else if (strcmp(mech_name, SUN_CKM_AES_CBC) == 0) {
		mech.cm_type = crypto_mech2id(SUN_CKM_AES_CBC);
		mech.cm_param = (void *)iv;
		mech.cm_param_len = sizeof (iv);
	} else if (strcmp(mech_name, SUN_CKM_AES_CTR) == 0) {
		mech.cm_type = crypto_mech2id(SUN_CKM_AES_CTR);
		mech.cm_param = (void *)&ctr_params;
		mech.cm_param_len = sizeof (ctr_params);
	} else {
		mech.cm_type = crypto_mech2id(SUN_CKM_AES_ECB);
		mech.cm_param = NULL;
		mech.cm_param_len = 0;
	}

	bzero(K, sizeof (K));
	bzero(token, sizeof (token));
	bzero(iv, sizeof (iv));

	start = ddi_get_lbolt();
	for (int i = 0; i < OUTER_ROUNDS; i++) {

		if (encrypt)
			ret = crypto_encrypt_init(&mech, &kcf_K, NULL, &ctx,
			    NULL);
		else
			ret = crypto_decrypt_init(&mech, &kcf_K, NULL, &ctx,
			    NULL);
		if (ret != CRYPTO_SUCCESS) {
			cmn_err(CE_NOTE, "Init problem: %x", ret);
			goto out;
		}

		CRYPTO_SET_RAW_DATA(kcf_input, input, ENCBLKSZ);

		for (int j = 0; j < INNER_ROUNDS; j++) {
			CRYPTO_SET_RAW_DATA(kcf_output, output,
			    INNER_ROUNDS * ENCBLKSZ + 16);
			if (encrypt)
				ret = crypto_encrypt_update(ctx, &kcf_input,
				    &kcf_output, NULL);
			else
				ret = crypto_decrypt_update(ctx, &kcf_input,
				    &kcf_output, NULL);
			if (ret != CRYPTO_SUCCESS) {
				cmn_err(CE_NOTE, "Update problem: %x", ret);
				goto out;
			}
		}
		CRYPTO_SET_RAW_DATA(kcf_output, output,
		    INNER_ROUNDS * ENCBLKSZ + 16);

		if (encrypt)
			ret = crypto_encrypt_final(ctx, &kcf_output, NULL);
		else
			ret = crypto_encrypt_final(ctx, &kcf_output, NULL);
		if (ret != CRYPTO_SUCCESS) {
			cmn_err(CE_NOTE, "Final problem: %x", ret);
			goto out;
		}
	}

	end = ddi_get_lbolt();

	if (start == end)
		end = start + 1;

out:
	kmem_free(input, ENCBLKSZ);
	kmem_free(output, INNER_ROUNDS * ENCBLKSZ + 16);
}

static void
test_gcm(int tcN, boolean_t encrypt, void *K, size_t K_len, void *T,
    size_t T_len, void *IV, size_t IV_len, void *AAD, size_t AAD_len,
    void *in, void *out, size_t len)
{
	int rv;
	uint8_t *inbuf = NULL, *outbuf = NULL;
	size_t inbuf_len = 0, outbuf_len = 0;
	CK_AES_GCM_PARAMS gcm_params;

	crypto_context_t ctx;
	crypto_data_t kcf_input, kcf_output;
	crypto_key_t kcf_key;
	crypto_mechanism_t mech = {
	    .cm_type = crypto_mech2id(SUN_CKM_AES_GCM),
	    .cm_param = (void *)&gcm_params,
	    .cm_param_len = sizeof (gcm_params)
	};

	if (encrypt) {
		outbuf = kmem_zalloc(len + T_len, KM_SLEEP);
		outbuf_len = len + T_len;

		CRYPTO_SET_RAW_DATA(kcf_input, in, len);
		CRYPTO_SET_RAW_DATA(kcf_output, outbuf, len + T_len);
	} else {
		inbuf = kmem_zalloc(len + T_len, KM_SLEEP);
		inbuf_len = len + T_len;
		outbuf = kmem_zalloc(len, KM_SLEEP);
		outbuf_len = len;

		bcopy(in, inbuf, len);
		bcopy(T, inbuf + len, T_len);

		CRYPTO_SET_RAW_DATA(kcf_input, inbuf, inbuf_len);
		CRYPTO_SET_RAW_DATA(kcf_output, outbuf, outbuf_len);
	}
	GCM_PARAM_SET(gcm_params, IV, IV_len, AAD, AAD_len, T_len);
	CRYPTO_SET_RAW_KEY(kcf_key, K, K_len);

	if (encrypt)
		rv = crypto_encrypt_init(&mech, &kcf_key, NULL, &ctx, NULL);
	else
		rv = crypto_decrypt_init(&mech, &kcf_key, NULL, &ctx, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "GCM/%d/%s init problem: %x", tcN,
		    encrypt ? "E" : "D", rv);
		goto errout_dealloc;
	}
	if (len > 0 || !encrypt) {
		if (encrypt)
			rv = crypto_encrypt_update(ctx, &kcf_input,
			    &kcf_output, NULL);
		else
			rv = crypto_decrypt_update(ctx, &kcf_input,
			    &kcf_output, NULL);
		if (rv != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "GCM/%d/%s update problem: %x",
			    tcN, encrypt ? "E" : "D", rv);
			goto errout_final;
		}
		kcf_output.cd_offset = (len / 16) * 16;
	}

errout_final:
	if (encrypt)
		rv = crypto_encrypt_final(ctx, &kcf_output, NULL);
	else
		rv = crypto_decrypt_final(ctx, &kcf_output, NULL);
	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "GCM/%d/%s final problem: %x",
		    tcN, encrypt ? "E" : "D", rv);
		goto errout_dealloc;
	}

	if (encrypt) {
		cmn_err(CE_NOTE, "GCM/%d/E: %s", tcN,
		    (bcmp(outbuf, out, len) == 0 &&
		    bcmp(outbuf + len, T, T_len) == 0) ? "OK" : "BAD");
	} else {
		cmn_err(CE_NOTE, "GCM/%d/D: %s", tcN,
		    bcmp(outbuf, out, len) == 0 ? "OK" : "BAD");
	}

errout_dealloc:
	if (inbuf)
		kmem_free(inbuf, inbuf_len);
	if (outbuf)
		kmem_free(outbuf, outbuf_len);
}

static void
test_mode(int tcN, char *mech_name, boolean_t encrypt, void *K,
    size_t K_len, void *param, size_t param_len, void *in, const void *out,
    size_t len, int ncopies)
{
	int rv, i;
	crypto_context_t ctx;
	crypto_data_t kcf_input, kcf_output;
	crypto_key_t kcf_key;
	crypto_mechanism_t mech = {
	    .cm_type = crypto_mech2id(mech_name),
	    .cm_param = param,
	    .cm_param_len = param_len
	};
	uint8_t *inbuf, *outbuf;
	const char *short_name;

	if (strcmp(mech_name, SUN_CKM_AES_ECB) == 0)
		short_name = "ECB";
	else if (strcmp(mech_name, SUN_CKM_AES_CBC) == 0)
		short_name = "CBC";
	else
		short_name = "CTR";

	inbuf = kmem_zalloc(len * ncopies, KM_SLEEP);
	outbuf = kmem_zalloc(len * ncopies, KM_SLEEP);

	for (i = 0; i < ncopies; i++)
		bcopy(in, &inbuf[i * len], len);

	CRYPTO_SET_RAW_DATA(kcf_input, inbuf, ncopies * len);
	CRYPTO_SET_RAW_DATA(kcf_output, outbuf, ncopies * len);
	CRYPTO_SET_RAW_KEY(kcf_key, K, K_len);

	if (encrypt)
		rv = crypto_encrypt_init(&mech, &kcf_key, NULL, &ctx, NULL);
	else
		rv = crypto_decrypt_init(&mech, &kcf_key, NULL, &ctx, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "%s/%d/%s init problem: %x", short_name,
		    tcN, encrypt ? "E" : "D", rv);
		goto errout_dealloc;
	}

	if (len > 0) {
		if (encrypt)
			rv = crypto_encrypt_update(ctx, &kcf_input,
			    &kcf_output, NULL);
		else
			rv = crypto_decrypt_update(ctx, &kcf_input,
			    &kcf_output, NULL);
		if (rv != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "%s/%d/%s update problem: %x",
			    short_name, tcN, encrypt ? "E" : "D", rv);
			goto errout_final;
		}
	}

errout_final:
	if (encrypt)
		rv = crypto_encrypt_final(ctx, &kcf_output, NULL);
	else
		rv = crypto_decrypt_final(ctx, &kcf_output, NULL);
	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "%s/%d/%s final problem: %x", short_name,
		    tcN, encrypt ? "E" : "D", rv);
		goto errout_dealloc;
	}
	for (i = 0; i < ncopies; i++) {
		if (bcmp(&outbuf[i * len], out, len) != 0) {
			cmn_err(CE_NOTE, "%s/%d/%s: BAD at %d: "
			    "expected %016llx%016llx; got %016llx%016llx",
			    short_name, tcN, encrypt ? "E" : "D", (int)len * i,
			    AES_BLOCK(out), AES_BLOCK(&outbuf[i * len]));
			break;
		}
	}
	if (i == ncopies) {
		cmn_err(CE_NOTE, "%s/%d/%s: OK", short_name,
		    tcN, encrypt ? "E" : "D");
	}

errout_dealloc:
	kmem_free(inbuf, len * ncopies);
	kmem_free(outbuf, len * ncopies);
}

static void
test_ecb_all(void)
{
	/* Encryption */
	test_mode(1, SUN_CKM_AES_ECB, B_TRUE, ecb_tc1_K, sizeof (ecb_tc1_K),
	    NULL, 0, ecb_tc1_pt, ecb_tc1_ct, sizeof (ecb_tc1_pt), ECB_NCOPIES);
	test_mode(2, SUN_CKM_AES_ECB, B_TRUE, ecb_tc2_K, sizeof (ecb_tc2_K),
	    NULL, 0, ecb_tc2_pt, ecb_tc2_ct, sizeof (ecb_tc2_pt), ECB_NCOPIES);
	test_mode(3, SUN_CKM_AES_ECB, B_TRUE, ecb_tc3_K, sizeof (ecb_tc3_K),
	    NULL, 0, ecb_tc3_pt, ecb_tc3_ct, sizeof (ecb_tc3_pt), ECB_NCOPIES);
	test_mode(4, SUN_CKM_AES_ECB, B_TRUE, ecb_tc4_K, sizeof (ecb_tc4_K),
	    NULL, 0, ecb_tc4_pt, ecb_tc4_ct, sizeof (ecb_tc4_pt), ECB_NCOPIES);
	test_mode(5, SUN_CKM_AES_ECB, B_TRUE, ecb_tc5_K, sizeof (ecb_tc5_K),
	    NULL, 0, ecb_tc5_pt, ecb_tc5_ct, sizeof (ecb_tc5_pt), ECB_NCOPIES);
	test_mode(6, SUN_CKM_AES_ECB, B_TRUE, ecb_tc6_K, sizeof (ecb_tc6_K),
	    NULL, 0, ecb_tc6_pt, ecb_tc6_ct, sizeof (ecb_tc6_pt), ECB_NCOPIES);

	/* Decryption */
	test_mode(1, SUN_CKM_AES_ECB, B_FALSE, ecb_tc1_K, sizeof (ecb_tc1_K),
	    NULL, 0, ecb_tc1_ct, ecb_tc1_pt, sizeof (ecb_tc1_pt), ECB_NCOPIES);
	test_mode(2, SUN_CKM_AES_ECB, B_FALSE, ecb_tc2_K, sizeof (ecb_tc2_K),
	    NULL, 0, ecb_tc2_ct, ecb_tc2_pt, sizeof (ecb_tc2_pt), ECB_NCOPIES);
	test_mode(3, SUN_CKM_AES_ECB, B_FALSE, ecb_tc3_K, sizeof (ecb_tc3_K),
	    NULL, 0, ecb_tc3_ct, ecb_tc3_pt, sizeof (ecb_tc3_pt), ECB_NCOPIES);
	test_mode(4, SUN_CKM_AES_ECB, B_FALSE, ecb_tc4_K, sizeof (ecb_tc4_K),
	    NULL, 0, ecb_tc4_ct, ecb_tc4_pt, sizeof (ecb_tc4_pt), ECB_NCOPIES);
	test_mode(5, SUN_CKM_AES_ECB, B_FALSE, ecb_tc5_K, sizeof (ecb_tc5_K),
	    NULL, 0, ecb_tc5_ct, ecb_tc5_pt, sizeof (ecb_tc5_pt), ECB_NCOPIES);
	test_mode(6, SUN_CKM_AES_ECB, B_FALSE, ecb_tc6_K, sizeof (ecb_tc6_K),
	    NULL, 0, ecb_tc6_ct, ecb_tc6_pt, sizeof (ecb_tc6_pt), ECB_NCOPIES);
}

static void
test_cbc_all(void)
{
	/* Encryption */
	test_mode(1, SUN_CKM_AES_CBC, B_TRUE, cbc_tc1_K, sizeof (cbc_tc1_K),
	    cbc_tc1_IV, sizeof (cbc_tc1_IV), cbc_tc1_pt, cbc_tc1_ct,
	    sizeof (cbc_tc1_pt), 1);
	test_mode(2, SUN_CKM_AES_CBC, B_TRUE, cbc_tc2_K, sizeof (cbc_tc2_K),
	    cbc_tc2_IV, sizeof (cbc_tc2_IV), cbc_tc2_pt, cbc_tc2_ct,
	    sizeof (cbc_tc2_pt), 1);
	test_mode(3, SUN_CKM_AES_CBC, B_TRUE, cbc_tc3_K, sizeof (cbc_tc3_K),
	    cbc_tc3_IV, sizeof (cbc_tc3_IV), cbc_tc3_pt, cbc_tc3_ct,
	    sizeof (cbc_tc3_pt), 1);

	/* Decryption */
	test_mode(1, SUN_CKM_AES_CBC, B_FALSE, cbc_tc1_K, sizeof (cbc_tc1_K),
	    cbc_tc1_IV, sizeof (cbc_tc1_IV), cbc_tc1_ct, cbc_tc1_pt,
	    sizeof (cbc_tc1_pt), 1);
	test_mode(2, SUN_CKM_AES_CBC, B_FALSE, cbc_tc2_K, sizeof (cbc_tc2_K),
	    cbc_tc2_IV, sizeof (cbc_tc2_IV), cbc_tc2_ct, cbc_tc2_pt,
	    sizeof (cbc_tc2_pt), 1);
	test_mode(3, SUN_CKM_AES_CBC, B_FALSE, cbc_tc3_K, sizeof (cbc_tc3_K),
	    cbc_tc3_IV, sizeof (cbc_tc3_IV), cbc_tc3_ct, cbc_tc3_pt,
	    sizeof (cbc_tc3_pt), 1);
}

static void
test_ctr_all(void)
{
	/* Encryption */
	test_mode(1, SUN_CKM_AES_CTR, B_TRUE, ctr_tc1_K, sizeof (ctr_tc1_K),
	    &ctr_tc1_IV, sizeof (ctr_tc1_IV), ctr_tc1_pt, ctr_tc1_ct,
	    sizeof (ctr_tc1_pt), 1);
	test_mode(2, SUN_CKM_AES_CTR, B_TRUE, ctr_tc2_K, sizeof (ctr_tc2_K),
	    &ctr_tc2_IV, sizeof (ctr_tc2_IV), ctr_tc2_pt, ctr_tc2_ct,
	    sizeof (ctr_tc2_pt), 1);
	test_mode(3, SUN_CKM_AES_CTR, B_TRUE, ctr_tc3_K, sizeof (ctr_tc3_K),
	    &ctr_tc3_IV, sizeof (ctr_tc3_IV), ctr_tc3_pt, ctr_tc3_ct,
	    sizeof (ctr_tc3_pt), 1);

	/* Decryption */
	test_mode(1, SUN_CKM_AES_CTR, B_FALSE, ctr_tc1_K, sizeof (ctr_tc1_K),
	    &ctr_tc1_IV, sizeof (ctr_tc1_IV), ctr_tc1_ct, ctr_tc1_pt,
	    sizeof (ctr_tc1_pt), 1);
	test_mode(2, SUN_CKM_AES_CTR, B_FALSE, ctr_tc2_K, sizeof (ctr_tc2_K),
	    &ctr_tc2_IV, sizeof (ctr_tc2_IV), ctr_tc2_ct, ctr_tc2_pt,
	    sizeof (ctr_tc2_pt), 1);
	test_mode(3, SUN_CKM_AES_CTR, B_FALSE, ctr_tc3_K, sizeof (ctr_tc3_K),
	    &ctr_tc3_IV, sizeof (ctr_tc3_IV), ctr_tc3_ct, ctr_tc3_pt,
	    sizeof (ctr_tc3_pt), 1);
}

static void
test_gcm_all(void)
{
	/* Encryption */
	test_gcm(1, B_TRUE, gcm_tc1_K, sizeof (gcm_tc1_K), gcm_tc1_T,
	    sizeof (gcm_tc1_T), gcm_tc1_IV, sizeof (gcm_tc1_IV), NULL, 0,
	    NULL, NULL, 0);
	test_gcm(2, B_TRUE, gcm_tc1_K, sizeof (gcm_tc1_K), gcm_tc2_T,
	    sizeof (gcm_tc2_T), gcm_tc1_IV, sizeof (gcm_tc1_IV), NULL, 0,
	    gcm_tc2_pt, gcm_tc2_ct, sizeof (gcm_tc2_pt));
	test_gcm(3, B_TRUE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc3_T,
	    sizeof (gcm_tc3_T), gcm_tc3_IV, sizeof (gcm_tc3_IV), NULL, 0,
	    gcm_tc3_pt, gcm_tc3_ct, sizeof (gcm_tc3_pt));
	test_gcm(4, B_TRUE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc4_T,
	    sizeof (gcm_tc4_T), gcm_tc3_IV, sizeof (gcm_tc3_IV), gcm_tc4_A,
	    sizeof (gcm_tc4_A), gcm_tc3_pt, gcm_tc3_ct, 60);
	test_gcm(5, B_TRUE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc5_T,
	    sizeof (gcm_tc5_T), gcm_tc5_IV, sizeof (gcm_tc5_IV),
	    gcm_tc4_A, sizeof (gcm_tc4_A), gcm_tc3_pt, gcm_tc5_ct,
	    sizeof (gcm_tc5_ct));
	test_gcm(6, B_TRUE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc6_T,
	    sizeof (gcm_tc6_T), gcm_tc6_IV, sizeof (gcm_tc6_IV), gcm_tc4_A,
	    sizeof (gcm_tc4_A), gcm_tc3_pt, gcm_tc6_ct, sizeof (gcm_tc6_ct));

	/* Decryption */
	test_gcm(1, B_FALSE, gcm_tc1_K, sizeof (gcm_tc1_K), gcm_tc1_T,
	    sizeof (gcm_tc1_T), gcm_tc1_IV, sizeof (gcm_tc1_IV), NULL, 0,
	    NULL, NULL, 0);
	test_gcm(2, B_FALSE, gcm_tc1_K, sizeof (gcm_tc1_K), gcm_tc2_T,
	    sizeof (gcm_tc2_T), gcm_tc1_IV, sizeof (gcm_tc1_IV), NULL, 0,
	    gcm_tc2_ct, gcm_tc2_pt, sizeof (gcm_tc2_pt));
	test_gcm(3, B_FALSE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc3_T,
	    sizeof (gcm_tc3_T), gcm_tc3_IV, sizeof (gcm_tc3_IV), NULL, 0,
	    gcm_tc3_ct, gcm_tc3_pt, sizeof (gcm_tc3_pt));
	test_gcm(4, B_FALSE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc4_T,
	    sizeof (gcm_tc4_T), gcm_tc3_IV, sizeof (gcm_tc3_IV), gcm_tc4_A,
	    sizeof (gcm_tc4_A), gcm_tc3_ct, gcm_tc3_pt, 60);
	test_gcm(5, B_FALSE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc5_T,
	    sizeof (gcm_tc5_T), gcm_tc5_IV, sizeof (gcm_tc5_IV),
	    gcm_tc4_A, sizeof (gcm_tc4_A), gcm_tc5_ct, gcm_tc3_pt,
	    sizeof (gcm_tc5_ct));
	test_gcm(6, B_FALSE, gcm_tc3_K, sizeof (gcm_tc3_K), gcm_tc6_T,
	    sizeof (gcm_tc6_T), gcm_tc6_IV, sizeof (gcm_tc6_IV), gcm_tc4_A,
	    sizeof (gcm_tc4_A), gcm_tc6_ct, gcm_tc3_pt, sizeof (gcm_tc6_ct));
}

int
_fini(void)
{
	return (EACCES);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
