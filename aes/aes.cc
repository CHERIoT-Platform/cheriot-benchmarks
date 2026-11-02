// Copyright SCI Semiconductor
// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

#include <allocator.h>
#include <cheri.hh>
#include <compartment.h>
#include <debug.hh>
#include <ds/xoroshiro.h>
#include <fail-simulator-on-error.h>
#include <locks.hh>
#include <platform-rdcycle.h>

#include <bearssl_aead.h>
#include <bearssl_block.h>
#include <mbedtls/private/aes.h>
#include <mbedtls/private/gcm.h>
#include <micro_aes.h>

#ifndef DEBUG_AESBENCH
#	define DEBUG_AESBENCH false
#endif

using Debug = ConditionalDebug<DEBUG_AESBENCH, "AES benchmark">;

#ifndef AESBENCH_LOG_DATA
#	define AESBENCH_LOG_DATA 0
#endif

/*
    Benchmark parameters
*/

// Range of plaintext sizes to test
#ifndef AESBENCH_PLAINTEXT_SIZE_MIN
#	define AESBENCH_PLAINTEXT_SIZE_MIN 32
#endif
#ifndef AESBENCH_PLAINTEXT_SIZE_MAX
#	define AESBENCH_PLAINTEXT_SIZE_MAX (32 * 1024)
#endif
const size_t MinimumPlaintextSize = AESBENCH_PLAINTEXT_SIZE_MIN;
const size_t MaximumPlaintextSize = AESBENCH_PLAINTEXT_SIZE_MAX;

// Number of plaintexts to test per size
#ifndef AESBENCH_PLAINTEXT_COUNT
#	define AESBENCH_PLAINTEXT_COUNT 3
#endif
const size_t PlaintextCount = AESBENCH_PLAINTEXT_COUNT;

// Key sizes to test per plaintext
#ifndef AESBENCH_ENABLE_AES128
#	define AESBENCH_ENABLE_AES128 1
#endif
#ifndef AESBENCH_ENABLE_AES192
#	define AESBENCH_ENABLE_AES192 1
#endif
#ifndef AESBENCH_ENABLE_AES256
#	define AESBENCH_ENABLE_AES256 1
#endif
const size_t KeySizes[] = {
#if AESBENCH_ENABLE_AES128 == 1
  128,
#endif
#if AESBENCH_ENABLE_AES192 == 1
  192,
#endif
#if AESBENCH_ENABLE_AES256 == 1
  256,
#endif
};
const size_t MaximumKeySize =
#if AESBENCH_ENABLE_AES256 == 1
  256;
#elif AESBENCH_ENABLE_AES192 == 1
  192;
#elif AESBENCH_ENABLE_AES128 == 1
  128;
#endif

// Cipher modes to test
#ifndef AESBENCH_ENABLE_CBC
#	define AESBENCH_ENABLE_CBC 1
#endif
#ifndef AESBENCH_ENABLE_CTR
#	define AESBENCH_ENABLE_CTR 1
#endif
#ifndef AESBENCH_ENABLE_GCM
#	define AESBENCH_ENABLE_GCM 1
#endif

// Number of keys to test per key size
#ifndef AESBENCH_KEY_COUNT
#	define AESBENCH_KEY_COUNT 3
#endif
const size_t KeyCount = AESBENCH_KEY_COUNT;

// Number of IVs to test per key
#ifndef AESBENCH_IV_COUNT
#	define AESBENCH_IV_COUNT 3
#endif
const size_t IvCount = AESBENCH_IV_COUNT;

// Repetition count for each input combination
#ifndef AESBENCH_REPEAT_COUNT
#	define AESBENCH_REPEAT_COUNT 3
#endif
const size_t RepeatCount = AESBENCH_REPEAT_COUNT;

#ifndef AESBENCH_SEED
#	define AESBENCH_SEED 1
#endif
const uint8_t Seed = AESBENCH_SEED;

/*
    AES implementations
*/

#define AES_CBC_IV_SIZE 16

#define AES_CTR_IV_SIZE 12

// GCM in general supports arbitrary-size IVs, but micro-AES only implements
// this one size, so it is used across all implementations here for consistency
#define AES_GCM_IV_SIZE 12

#define AES_GCM_TAG_SIZE 16

/**
 * Generic AES encryption/decryption interface
 */
class AesImpl
{
	public:
	virtual ~AesImpl() = default;

	/**
	 * Check that a key size is usable for this implementation
	 */
	virtual bool supports_key_size(size_t keySizeBits) = 0;

	/**
	 * Set the active key, required to stay alive for the lifetime of this
	 * class
	 */
	virtual void set_key(const uint8_t *key, size_t keySizeBytes) = 0;

	/**
	 * Encrypt the data from `plaintext` into the `ciphertext` buffer using `iv`
	 * and a key previously set by `set_key`. Returns `true` if successful.
	 *
	 * The contents of `ciphertext` should be initialised equal to `plaintext`
	 * to allow implementations to work in-place (ex. BearSSL). Some
	 * implementations require that `plaintext` and `ciphertext` do not overlap
	 * (ex. micro-AES).
	 *
	 * `plaintextSize` should be the size of the `plaintext` buffer, and the
	 * `ciphertext` buffer should be equal to this plus `AES_GCM_TAG_SIZE` to
	 * accommodate for GCM implementations (this extra space does not need to be
	 * initialised).
	 */
	virtual bool encrypt_bytes(uint8_t       *iv,
	                           size_t         plaintextSize,
	                           const uint8_t *plaintext,
	                           uint8_t       *ciphertext) = 0;

	/**
	 * Decrypt the data from `ciphertext` into the `plaintext` buffer using `iv`
	 * and a key previously set by `set_key`. Returns `true` if successful.
	 *
	 * The contents of `plaintext` should be initialised equal to `ciphertext`
	 * (not including the GCM tag) to allow implementations to work in-place
	 * (ex. BearSSL). Some implementations require that `plaintext` and
	 * `ciphertext` do not overlap (ex. micro-AES).
	 *
	 * `plaintextSize` should be the size of the `plaintext` buffer, and the
	 * `ciphertext` buffer should be equal to this plus `AES_GCM_TAG_SIZE` to
	 * accommodate for GCM implementations.
	 */
	virtual bool decrypt_bytes(uint8_t       *iv,
	                           size_t         plaintextSize,
	                           const uint8_t *ciphertext,
	                           uint8_t       *plaintext) = 0;

	/**
	 * Get the name of the implementation used
	 */
	virtual const char *get_name() = 0;

	/**
	 * Initialise a working copy of the iv.
	 * Even for CTR implementations, these must be buffers big enough for a CBC
	 * IV, as some still use the extra space (ex. mbedtls)
	 */
	virtual void init_working_iv(const uint8_t iv[AES_CBC_IV_SIZE],
	                             uint8_t       workingIv[AES_CBC_IV_SIZE])
	{ memcpy(workingIv, iv, AES_CBC_IV_SIZE); }
};

template<typename EncCtx,
         typename DecCtx,
         void EncInitFunc(EncCtx *ctx, const void *key, size_t len),
         void EncRunFunc(const EncCtx *ctx, void *iv, void *data, size_t len),
         void DecInitFunc(DecCtx *ctx, const void *key, size_t len),
         void DecRunFunc(const DecCtx *ctx, void *iv, void *data, size_t len),
         const char *Name>
class BearSslAesCbcImpl : public AesImpl
{
	EncCtx encCtx;
	DecCtx decCtx;

	bool supports_key_size(size_t keySizeBits) override
	{
		switch (keySizeBits)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{
		EncInitFunc(&encCtx, key, keySizeBytes);
		DecInitFunc(&decCtx, key, keySizeBytes);
	}

	bool encrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		// BearSSL works in-place
		Debug::Assert(
		  [&]() { return memcmp(ciphertext, plaintext, plaintextSize) == 0; },
		  "ciphertext must be initialised equal to plaintext");

		EncRunFunc(&encCtx, iv, ciphertext, plaintextSize);

		return true;
	}

	bool decrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		// BearSSL works in-place
		Debug::Assert(
		  [&]() { return memcmp(ciphertext, plaintext, plaintextSize) == 0; },
		  "plaintext must be initialised equal to ciphertext");

		DecRunFunc(&decCtx, iv, plaintext, plaintextSize);

		return true;
	}

	const char *get_name() override
	{ return Name; }
};

const char BearAesSmallCbcName[] = "BearSSL.aes_small.CBC";
using BearAesSmallCbc            = BearSslAesCbcImpl<br_aes_small_cbcenc_keys,
                                                     br_aes_small_cbcdec_keys,
                                                     br_aes_small_cbcenc_init,
                                                     br_aes_small_cbcenc_run,
                                                     br_aes_small_cbcdec_init,
                                                     br_aes_small_cbcdec_run,
                                                     BearAesSmallCbcName>;

const char BearAesBigCbcName[] = "BearSSL.aes_big.CBC";
using BearAesBigCbc            = BearSslAesCbcImpl<br_aes_big_cbcenc_keys,
                                                   br_aes_big_cbcdec_keys,
                                                   br_aes_big_cbcenc_init,
                                                   br_aes_big_cbcenc_run,
                                                   br_aes_big_cbcdec_init,
                                                   br_aes_big_cbcdec_run,
                                                   BearAesBigCbcName>;

const char BearAesCtCbcName[] = "BearSSL.aes_ct.CBC";
using BearAesCtCbc            = BearSslAesCbcImpl<br_aes_ct_cbcenc_keys,
                                                  br_aes_ct_cbcdec_keys,
                                                  br_aes_ct_cbcenc_init,
                                                  br_aes_ct_cbcenc_run,
                                                  br_aes_ct_cbcdec_init,
                                                  br_aes_ct_cbcdec_run,
                                                  BearAesCtCbcName>;

class MicroAes128CbcImpl : public AesImpl
{
	public:
	bool supports_key_size(size_t keySizeBits) override
	{ return keySizeBits == 128; }

	const uint8_t *key;

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{ this->key = key; }

	bool encrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		char ret =
		  AES_CBC_encrypt(key, iv, plaintext, plaintextSize, ciphertext);
		return ret == M_SUCCESS;
	}

	bool decrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		char ret =
		  AES_CBC_decrypt(key, iv, ciphertext, plaintextSize, plaintext);
		return ret == M_SUCCESS;
	}

	const char *get_name() override
	{ return "micro-AES.128.CBC"; }
};

class MbedtlsAesCbcImpl : public AesImpl
{
	mbedtls_aes_context encCtx;
	mbedtls_aes_context decCtx;

	public:
	MbedtlsAesCbcImpl()
	{
		mbedtls_aes_init(&encCtx);
		mbedtls_aes_init(&decCtx);
	}

	~MbedtlsAesCbcImpl() override
	{
		mbedtls_aes_free(&encCtx);
		mbedtls_aes_free(&decCtx);
	}

	bool supports_key_size(size_t keySizeBits) override
	{
		switch (keySizeBits)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{
		size_t keySizeBits = keySizeBytes * 8;

		int ret;

		ret = mbedtls_aes_setkey_enc(&encCtx, key, keySizeBits);
		Debug::Invariant(ret == 0, "mbedtls_aes_setkey_enc={}", ret);

		ret = mbedtls_aes_setkey_dec(&decCtx, key, keySizeBits);
		Debug::Invariant(ret == 0, "mbedtls_aes_setkey_dec={}", ret);
	}

	bool encrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		int ret = mbedtls_aes_crypt_cbc(&encCtx,
		                                MBEDTLS_AES_ENCRYPT,
		                                plaintextSize,
		                                iv,
		                                plaintext,
		                                ciphertext);
		return ret == 0;
	}

	bool decrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		int ret = mbedtls_aes_crypt_cbc(&decCtx,
		                                MBEDTLS_AES_DECRYPT,
		                                plaintextSize,
		                                iv,
		                                ciphertext,
		                                plaintext);
		return ret == 0;
	}

	const char *get_name() override
	{ return "mbedtls.CBC"; }
};

/**
 * Helper class for implementations using the same function for encryption and
 * decryption
 */
class AesSymmetricImpl : public AesImpl
{
	/**
	 * Encrypt/decrypt inText to outText
	 */
	virtual bool run(uint8_t       *iv,
	                 size_t         plaintextSize,
	                 const uint8_t *inText,
	                 uint8_t       *outText) = 0;

	bool encrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{ return run(iv, plaintextSize, plaintext, ciphertext); }

	bool decrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{ return run(iv, plaintextSize, ciphertext, plaintext); }
};

template<typename Ctx,
         void        InitFunc(Ctx *ctx, const void *key, size_t len),
         uint32_t    RunFunc(const Ctx  *ctx,
                             const void *iv,
                             uint32_t    cc,
                             void       *data,
                             size_t      len),
         const char *Name>
class BearSslAesCtrImpl : public AesSymmetricImpl
{
	Ctx ctx;

	bool supports_key_size(size_t keySizeBits) override
	{
		switch (keySizeBits)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{ InitFunc(&ctx, key, keySizeBytes); }

	bool run(uint8_t       *iv,
	         size_t         plaintextSize,
	         const uint8_t *inText,
	         uint8_t       *outText) override
	{
		// BearSSL works in-place
		Debug::Assert(
		  [&]() { return memcmp(outText, inText, plaintextSize) == 0; },
		  "ciphertext must be initialised equal to plaintext");

		// Use the same counter start value as micro-AES
		uint32_t cc = 1;

		RunFunc(&ctx, iv, cc, outText, plaintextSize);

		return true;
	}

	const char *get_name() override
	{ return Name; }
};

const char BearAesSmallCtrName[] = "BearSSL.aes_small.CTR";
using BearAesSmallCtr            = BearSslAesCtrImpl<br_aes_small_ctr_keys,
                                                     br_aes_small_ctr_init,
                                                     br_aes_small_ctr_run,
                                                     BearAesSmallCtrName>;

const char BearAesBigCtrName[] = "BearSSL.aes_big.CTR";
using BearAesBigCtr            = BearSslAesCtrImpl<br_aes_big_ctr_keys,
                                                   br_aes_big_ctr_init,
                                                   br_aes_big_ctr_run,
                                                   BearAesBigCtrName>;

const char BearAesCtCtrName[] = "BearSSL.aes_ct.CTR";
using BearAesCtCtr            = BearSslAesCtrImpl<br_aes_ct_ctr_keys,
                                                  br_aes_ct_ctr_init,
                                                  br_aes_ct_ctr_run,
                                                  BearAesCtCtrName>;

class MicroAes128CtrImpl : public AesSymmetricImpl
{
	public:
	bool supports_key_size(size_t keySizeBits) override
	{ return keySizeBits == 128; }

	const uint8_t *key;

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{ this->key = key; }

	bool run(uint8_t       *iv,
	         size_t         plaintextSize,
	         const uint8_t *inText,
	         uint8_t       *outText) override
	{
		AES_CTR_encrypt(key, iv, inText, plaintextSize, outText);
		return true;
	}

	const char *get_name() override
	{ return "micro-AES.128.CTR"; }
};

class MbedtlsAesCtrImpl : public AesSymmetricImpl
{
	mbedtls_aes_context encCtx;
	mbedtls_aes_context decCtx;

	// Scratch space required for intermediate values by the library
	uint8_t streamBlock[16];

	public:
	MbedtlsAesCtrImpl()
	{
		mbedtls_aes_init(&encCtx);
		mbedtls_aes_init(&decCtx);
	}

	~MbedtlsAesCtrImpl() override
	{
		mbedtls_aes_free(&encCtx);
		mbedtls_aes_free(&decCtx);
	}

	bool supports_key_size(size_t keySizeBits) override
	{
		switch (keySizeBits)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{
		size_t keySizeBits = keySizeBytes * 8;

		int ret;

		ret = mbedtls_aes_setkey_enc(&encCtx, key, keySizeBits);
		Debug::Invariant(ret == 0, "mbedtls_aes_setkey_enc={}", ret);

		ret = mbedtls_aes_setkey_dec(&decCtx, key, keySizeBits);
		Debug::Invariant(ret == 0, "mbedtls_aes_setkey_dec={}", ret);
	}

	void init_working_iv(const uint8_t *iv, uint8_t *workingIv) override
	{
		memcpy(workingIv, iv, AES_CTR_IV_SIZE);

		// mbedtls stores counter with the iv
		// Initialise to same value as micro-AES
		workingIv[12] = 0;
		workingIv[13] = 0;
		workingIv[14] = 0;
		workingIv[15] = 1;
	}

	bool run(uint8_t       *iv,
	         size_t         plaintextSize,
	         const uint8_t *plaintext,
	         uint8_t       *ciphertext) override
	{
		int ret;

		size_t ncOff = 0;
		ret          = mbedtls_aes_crypt_ctr(&encCtx,
		                                     plaintextSize,
		                                     &ncOff,
		                                     iv,
		                                     streamBlock,
		                                     plaintext,
		                                     ciphertext);
		return ret == 0;
	}

	const char *get_name() override
	{ return "mbedtls.CTR"; }
};

template<const br_ghash            GHash,
         const br_block_ctr_class &Vtable,
         const char               *Name>
class BearSslAesGcmImpl : public AesImpl
{
	br_gcm_context      encCtx;
	br_aes_gen_ctr_keys encCtrCtx;

	br_gcm_context      decCtx;
	br_aes_gen_ctr_keys decCtrCtx;

	public:
	bool supports_key_size(size_t keySizeBits) override
	{
		switch (keySizeBits)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{
		Vtable.init(&encCtrCtx.vtable, key, keySizeBytes);
		br_gcm_init(&encCtx, &encCtrCtx.vtable, GHash);

		Vtable.init(&decCtrCtx.vtable, key, keySizeBytes);
		br_gcm_init(&decCtx, &decCtrCtx.vtable, GHash);
	}

	bool encrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		// BearSSL works in-place
		Debug::Assert(
		  [&]() { return memcmp(ciphertext, plaintext, plaintextSize) == 0; },
		  "ciphertext must be initialised equal to plaintext");

		br_gcm_reset(&encCtx, iv, AES_GCM_IV_SIZE);
		br_gcm_flip(&encCtx);
		br_gcm_run(&encCtx, true, ciphertext, plaintextSize);
		br_gcm_get_tag(&encCtx, ciphertext + plaintextSize);
		return true;
	}

	bool decrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		// BearSSL works in-place
		Debug::Assert(
		  [&]() { return memcmp(plaintext, ciphertext, plaintextSize) == 0; },
		  "ciphertext must be initialised equal to plaintext");

		br_gcm_reset(&decCtx, iv, AES_GCM_IV_SIZE);
		br_gcm_flip(&decCtx);
		br_gcm_run(&decCtx, false, plaintext, plaintextSize);
		return br_gcm_check_tag(&decCtx, ciphertext + plaintextSize) == 1;
	}

	const char *get_name() override
	{ return Name; }
};

const char BearAesSmallGcmCtmulName[] = "BearSSL.aes_small.GCM.ctmul";
using BearAesSmallGcmCtmul = BearSslAesGcmImpl<br_ghash_ctmul,
                                               br_aes_small_ctr_vtable,
                                               BearAesSmallGcmCtmulName>;

const char BearAesSmallGcmCtmul32Name[] = "BearSSL.aes_small.GCM.ctmul32";
using BearAesSmallGcmCtmul32 = BearSslAesGcmImpl<br_ghash_ctmul32,
                                                 br_aes_small_ctr_vtable,
                                                 BearAesSmallGcmCtmul32Name>;

const char BearAesSmallGcmCtmul64Name[] = "BearSSL.aes_small.GCM.ctmul64";
using BearAesSmallGcmCtmul64 = BearSslAesGcmImpl<br_ghash_ctmul64,
                                                 br_aes_small_ctr_vtable,
                                                 BearAesSmallGcmCtmul64Name>;

const char BearAesBigGcmCtmulName[] = "BearSSL.aes_big.GCM.ctmul";
using BearAesBigGcmCtmul            = BearSslAesGcmImpl<br_ghash_ctmul,
                                                        br_aes_big_ctr_vtable,
                                                        BearAesBigGcmCtmulName>;

const char BearAesBigGcmCtmul32Name[] = "BearSSL.aes_big.GCM.ctmul32";
using BearAesBigGcmCtmul32 = BearSslAesGcmImpl<br_ghash_ctmul32,
                                               br_aes_big_ctr_vtable,
                                               BearAesBigGcmCtmul32Name>;

const char BearAesBigGcmCtmul64Name[] = "BearSSL.aes_big.GCM.ctmul64";
using BearAesBigGcmCtmul64 = BearSslAesGcmImpl<br_ghash_ctmul64,
                                               br_aes_big_ctr_vtable,
                                               BearAesBigGcmCtmul64Name>;

const char BearAesCtGcmCtmulName[] = "BearSSL.aes_ct.GCM.ctmul";
using BearAesCtGcmCtmul            = BearSslAesGcmImpl<br_ghash_ctmul,
                                                       br_aes_ct_ctr_vtable,
                                                       BearAesCtGcmCtmulName>;

const char BearAesCtGcmCtmul32Name[] = "BearSSL.aes_ct.GCM.ctmul32";
using BearAesCtGcmCtmul32 = BearSslAesGcmImpl<br_ghash_ctmul32,
                                              br_aes_ct_ctr_vtable,
                                              BearAesCtGcmCtmul32Name>;

const char BearAesCtGcmCtmul64Name[] = "BearSSL.aes_ct.GCM.ctmul64";
using BearAesCtGcmCtmul64 = BearSslAesGcmImpl<br_ghash_ctmul64,
                                              br_aes_ct_ctr_vtable,
                                              BearAesCtGcmCtmul64Name>;

class MicroAes128GcmImpl : public AesImpl
{
	public:
	bool supports_key_size(size_t keySizeBits) override
	{ return keySizeBits == 128; }

	const uint8_t *key;

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{ this->key = key; }

	bool encrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		AES_GCM_encrypt(
		  key, iv, nullptr, 0, plaintext, plaintextSize, ciphertext);
		return true;
	}

	bool decrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		char ret = AES_GCM_decrypt(
		  key, iv, nullptr, 0, ciphertext, plaintextSize, plaintext);
		return ret == M_SUCCESS;
	}

	const char *get_name() override
	{ return "micro-AES.128.GCM"; }
};

class MbedtlsAesGcmImpl : public AesImpl
{
	mbedtls_gcm_context encCtx;
	mbedtls_gcm_context decCtx;

	public:
	MbedtlsAesGcmImpl()
	{
		mbedtls_gcm_init(&encCtx);
		mbedtls_gcm_init(&decCtx);
	}

	~MbedtlsAesGcmImpl() override
	{
		mbedtls_gcm_free(&encCtx);
		mbedtls_gcm_free(&decCtx);
	}

	bool supports_key_size(size_t keySizeBits) override
	{
		switch (keySizeBits)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySizeBytes) override
	{
		size_t keySizeBits = keySizeBytes * 8;

		int ret;

		ret =
		  mbedtls_gcm_setkey(&encCtx, MBEDTLS_CIPHER_ID_AES, key, keySizeBits);
		Debug::Invariant(ret == 0, "mbedtls_gcm_setkey={}", ret);

		ret =
		  mbedtls_gcm_setkey(&decCtx, MBEDTLS_CIPHER_ID_AES, key, keySizeBits);
		Debug::Invariant(ret == 0, "mbedtls_gcm_setkey={}", ret);
	}

	bool encrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		int ret = mbedtls_gcm_crypt_and_tag(&encCtx,
		                                    MBEDTLS_GCM_ENCRYPT,
		                                    plaintextSize,
		                                    iv,
		                                    AES_GCM_IV_SIZE,
		                                    nullptr,
		                                    0,
		                                    plaintext,
		                                    ciphertext,
		                                    AES_GCM_TAG_SIZE,
		                                    ciphertext + plaintextSize);
		return ret == 0;
	}

	bool decrypt_bytes(uint8_t       *iv,
	                   size_t         plaintextSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		int ret = mbedtls_gcm_auth_decrypt(&decCtx,
		                                   plaintextSize,
		                                   iv,
		                                   AES_GCM_IV_SIZE,
		                                   nullptr,
		                                   0,
		                                   ciphertext + plaintextSize,
		                                   AES_GCM_TAG_SIZE,
		                                   ciphertext,
		                                   plaintext);
		return ret == 0;
	}

	const char *get_name() override
	{ return "mbedtls.GCM"; }
};

/*
    Benchmarking code
*/

// Maximum plaintext size + 1 block for GCM tag
static constexpr size_t MaximumCiphertextSize =
  MaximumPlaintextSize + AES_GCM_TAG_SIZE;

static uint8_t ciphertextBuffer[MaximumCiphertextSize];
static uint8_t decryptedPlaintextBuffer[MaximumPlaintextSize];

/**
 * Measures the time taken, in CPU cycles, to encrypt and decrypt `plaintext`
 * using `impl` with `key` and `startIv`.
 *
 * Returns an std::pair of the encryption time and decryption time
 */
static std::pair<int, int> test(AesImpl       &impl,
                                const uint8_t *plaintext,
                                size_t         plaintextSize,
                                const uint8_t *key,
                                size_t         keySizeBytes,
                                const uint8_t *startIv)
{
	// Space for a GCM tag is provided at the end of the ciphertext buffer
	size_t            ciphertextBufferSize = plaintextSize + AES_GCM_TAG_SIZE;
	CHERI::Capability ciphertext{ciphertextBuffer};
	ciphertext.bounds().set_inexact(ciphertextBufferSize);

	CHERI::Capability decryptedPlaintext{decryptedPlaintextBuffer};
	decryptedPlaintext.bounds().set_inexact(plaintextSize);

	impl.set_key(key, keySizeBytes);

	uint8_t workingIv[AES_CBC_IV_SIZE];

	// Encrypt buffer
	memcpy(ciphertext, plaintext, plaintextSize);
	impl.init_working_iv(startIv, workingIv);
	auto encStart = rdcycle();
	bool encRet =
	  impl.encrypt_bytes(workingIv, plaintextSize, plaintext, ciphertext);
	auto encEnd = rdcycle();
	asm volatile("" : : : "memory");
	Debug::Invariant(encRet, "Encryption failed for {}", impl.get_name());

#if AESBENCH_LOG_DATA == 1
	fprintf(stderr, "%s Ciphertext: ", impl.get_name());
	for (size_t i = 0; i < plaintextSize; i++)
		fprintf(stderr, "%02x ", ciphertext[i]);
	fprintf(stderr, "\n");
#endif

	// Decrypt buffer
	memcpy(decryptedPlaintext, ciphertext, plaintextSize);
	impl.init_working_iv(startIv, workingIv);
	auto decStart = rdcycle();
	bool decRet   = impl.decrypt_bytes(
	  workingIv, plaintextSize, ciphertext, decryptedPlaintext);
	auto decEnd = rdcycle();
	asm volatile("" : : : "memory");
	Debug::Invariant(decRet, "Decryption failed for {}", impl.get_name());

#if AESBENCH_LOG_DATA == 1
	fprintf(stderr, "%s Decrypted Plaintext: ", impl.get_name());
	for (size_t i = 0; i < plaintextSize; i++)
		fprintf(stderr, "%02x ", decryptedPlaintext[i]);
	fprintf(stderr, "\n");
#endif

	// Check the output matches the original plaintext
	for (int i = 0; i < plaintextSize; i++)
	{
		Debug::Invariant(plaintext[i] == decryptedPlaintext[i],
		                 "{} byte {} was not a round trip",
		                 impl.get_name(),
		                 i);
	}

	return {
	  encEnd - encStart,
	  decEnd - decStart,
	};
}

/*
 * Initialises an arbitrary mbedtls AES context to trigger the one-time table
 * generation now rather than during an actual benchmark
 */
static void warmup_mbedtls()
{
	constexpr size_t KeySizeBits  = 128;
	constexpr size_t KeySizeBytes = KeySizeBits / 8;

	mbedtls_aes_context ctx;
	uint8_t             key[KeySizeBytes];
	mbedtls_aes_setkey_enc(&ctx, key, KeySizeBits);
}

static void fill_random_bytes(uint8_t seed, uint8_t *buffer, size_t length)
{
	ds::xoroshiro::P16R8 rand(seed);

	for (size_t i = 0; i < length; i++)
		buffer[i] = rand.next();
}

static uint8_t keyBuffer[MaximumKeySize];
static uint8_t plaintextBuffer[MaximumPlaintextSize];

int __cheri_compartment("aesbench") run()
{
	const std::unique_ptr<AesImpl> Implementations[]{
#if AESBENCH_ENABLE_CBC == 1
	  std::make_unique<BearAesSmallCbc>(),
	  std::make_unique<BearAesBigCbc>(),
	  std::make_unique<BearAesCtCbc>(),
	  std::make_unique<MicroAes128CbcImpl>(),
	  std::make_unique<MbedtlsAesCbcImpl>(),
#endif
#if AESBENCH_ENABLE_CTR == 1
	  std::make_unique<BearAesSmallCtr>(),
	  std::make_unique<BearAesBigCtr>(),
	  std::make_unique<BearAesCtCtr>(),
	  std::make_unique<MicroAes128CtrImpl>(),
	  std::make_unique<MbedtlsAesCtrImpl>(),
#endif
#if AESBENCH_ENABLE_GCM == 1
	  std::make_unique<BearAesSmallGcmCtmul>(),
	  std::make_unique<BearAesSmallGcmCtmul32>(),
	  std::make_unique<BearAesSmallGcmCtmul64>(),
	  std::make_unique<BearAesBigGcmCtmul>(),
	  std::make_unique<BearAesBigGcmCtmul32>(),
	  std::make_unique<BearAesBigGcmCtmul64>(),
	  std::make_unique<BearAesCtGcmCtmul>(),
	  std::make_unique<BearAesCtGcmCtmul32>(),
	  std::make_unique<BearAesCtGcmCtmul64>(),
	  std::make_unique<MicroAes128GcmImpl>(),
	  std::make_unique<MbedtlsAesGcmImpl>(),
#endif
	};

	warmup_mbedtls();

	printf("#board\t"
	       "plaintextSize\t"
	       "plaintextId\t"
	       "keySize\t"
	       "keyId\t"
	       "ivId\t"
	       "repetition\t"
	       "implementation\t"
	       "encryptionTime\t"
	       "decryptionTime\n");

	for (size_t plaintextSize = MinimumPlaintextSize;
	     plaintextSize <= MaximumPlaintextSize;
	     plaintextSize <<= 1)
	{
		CHERI::Capability plaintext{plaintextBuffer};
		plaintext.bounds() = plaintextSize;

		for (size_t plaintextId = 0; plaintextId < PlaintextCount;
		     plaintextId++)
		{
			fill_random_bytes(Seed + plaintextId, plaintext, plaintextSize);

#if AESBENCH_LOG_DATA == 1
			fprintf(stderr, "Plaintext: ");
			for (size_t i = 0; i < plaintextSize; i++)
				fprintf(stderr, "%02x ", plaintext[i]);
			fprintf(stderr, "\n");
#endif

			for (size_t keySizeBits : KeySizes)
			{
				size_t keySizeBytes = keySizeBits / 8;

				CHERI::Capability key{keyBuffer};
				key.bounds() = keySizeBytes;

				for (size_t keyId = 0; keyId < KeyCount; keyId++)
				{
					fill_random_bytes(Seed + keyId, key, keySizeBytes);

					for (size_t ivId = 0; ivId < IvCount; ivId++)
					{
						uint8_t startIv[AES_CBC_IV_SIZE];
						fill_random_bytes(Seed + ivId, startIv, sizeof startIv);

						// CTR/GCM IVs are only 12 bytes, so it's fine to just
						// use a subsection of this array for those
						static_assert(AES_CTR_IV_SIZE < AES_CBC_IV_SIZE);
						static_assert(AES_GCM_IV_SIZE < AES_CBC_IV_SIZE);

						for (const std::unique_ptr<AesImpl> &impl :
						     Implementations)
						{
							if (!impl->supports_key_size(keySizeBits))
								continue;

							for (size_t repetition = 0;
							     repetition < RepeatCount;
							     repetition++)
							{
								auto [encRuntime, decRuntime] =
								  test(*impl,
								       plaintext,
								       plaintextSize,
								       key,
								       keySizeBytes,
								       startIv);
								printf("%s\t%zu\t%zu\t%zu\t%zu\t%zu\t%zu\t%"
								       "s\t%d\t%d\n",
								       __XSTRING(BOARD),
								       plaintextSize,
								       plaintextId,
								       keySizeBits,
								       keyId,
								       ivId,
								       repetition,
								       impl->get_name(),
								       encRuntime,
								       decRuntime);
							}
						}
					}
				}
			}
		}
	}

	return 0;
}
