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

#include <bearssl_block.h>
#include <mbedtls/private/aes.h>
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
const size_t MinimumSize = AESBENCH_PLAINTEXT_SIZE_MIN;
const size_t MaximumSize = AESBENCH_PLAINTEXT_SIZE_MAX;

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
	 * Encrypt plaintext
	 *
	 * @param iv         The initial iv value to use. Some implementations may
	 *                   update this in-place.
	 * @param bufferSize The size of plaintext and ciphertext
	 * @param plaintext  The data to encrypt
	 * @param ciphertext The destination to write the encrypted data. Should be
	 *                   initialised equal to plaintext to allow some
	 *                   implementations to work in-place (ex. BearSSL)
	 *
	 * Some implementations require that plaintext and ciphertext do not
	 * overlap (ex. micro-AES)
	 */
	virtual void encrypt_bytes(uint8_t       *iv,
	                           size_t         bufferSize,
	                           const uint8_t *plaintext,
	                           uint8_t       *ciphertext) = 0;

	/**
	 * Decrypt ciphertext
	 *
	 * @param iv         The initial iv value to use. Some implementations may
	 *                   update this in-place.
	 * @param bufferSize The size of plaintext and ciphertext
	 * @param ciphertext The data to decrypt
	 * @param plaintext  The destination to write the decrypted data. Should be
	 *                   initialised equal to ciphertext to allow some
	 *                   implementations to work in-place (ex. BearSSL)
	 *
	 * Some implementations require that plaintext and ciphertext do not
	 * overlap (ex. micro-AES)
	 */
	virtual void decrypt_bytes(uint8_t       *iv,
	                           size_t         bufferSize,
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

	void encrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		// BearSSL works in-place
		Debug::Assert(memcmp(ciphertext, plaintext, bufferSize) == 0,
		              "ciphertext must be initialised equal to plaintext");

		EncRunFunc(&encCtx, iv, ciphertext, bufferSize);
	}

	void decrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		// BearSSL works in-place
		Debug::Assert(memcmp(plaintext, ciphertext, bufferSize) == 0,
		              "plaintext must be initialised equal to ciphertext");

		DecRunFunc(&decCtx, iv, plaintext, bufferSize);
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

	void encrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{ AES_CBC_encrypt(key, iv, plaintext, bufferSize, ciphertext); }

	void decrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{ AES_CBC_decrypt(key, iv, ciphertext, bufferSize, plaintext); }

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
		Debug::Assert(ret == 0, "mbedtls_aes_setkey_enc={}", ret);

		ret = mbedtls_aes_setkey_dec(&decCtx, key, keySizeBits);
		Debug::Assert(ret == 0, "mbedtls_aes_setkey_dec={}", ret);
	}

	void encrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{
		int ret = mbedtls_aes_crypt_cbc(
		  &encCtx, MBEDTLS_AES_ENCRYPT, bufferSize, iv, plaintext, ciphertext);
		Debug::Assert(ret == 0, "mbedtls_aes_crypt_cbc={}", ret);
	}

	void decrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{
		int ret = mbedtls_aes_crypt_cbc(
		  &decCtx, MBEDTLS_AES_DECRYPT, bufferSize, iv, ciphertext, plaintext);
		Debug::Assert(ret == 0, "mbedtls_aes_crypt_cbc={}", ret);
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
	virtual void run(uint8_t       *iv,
	                 size_t         bufferSize,
	                 const uint8_t *inText,
	                 uint8_t       *outText) = 0;

	void encrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *plaintext,
	                   uint8_t       *ciphertext) override
	{ run(iv, bufferSize, plaintext, ciphertext); }

	void decrypt_bytes(uint8_t       *iv,
	                   size_t         bufferSize,
	                   const uint8_t *ciphertext,
	                   uint8_t       *plaintext) override
	{ run(iv, bufferSize, ciphertext, plaintext); }
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

	void run(uint8_t       *iv,
	         size_t         bufferSize,
	         const uint8_t *inText,
	         uint8_t       *outText) override
	{
		// BearSSL works in-place
		Debug::Assert(memcmp(outText, inText, bufferSize) == 0,
		              "ciphertext must be initialised equal to plaintext");

		// Use the same counter start value as micro-AES
		uint32_t cc = 1;

		RunFunc(&ctx, iv, cc, outText, bufferSize);
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

	void run(uint8_t       *iv,
	         size_t         bufferSize,
	         const uint8_t *inText,
	         uint8_t       *outText) override
	{ AES_CTR_encrypt(key, iv, inText, bufferSize, outText); }

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

	void run(uint8_t       *iv,
	         size_t         bufferSize,
	         const uint8_t *plaintext,
	         uint8_t       *ciphertext) override
	{
		int ret;

		size_t ncOff = 0;
		ret          = mbedtls_aes_crypt_ctr(
		  &encCtx, bufferSize, &ncOff, iv, streamBlock, plaintext, ciphertext);
		Debug::Invariant(ret == 0, "mbedtls_aes_crypt_ctr={}", ret);
	}

	const char *get_name() override
	{ return "mbedtls.CTR"; }
};

/*
    Benchmarking code
*/

static uint8_t ciphertextBuffer[MaximumSize];
static uint8_t decryptedPlaintextBuffer[MaximumSize];

/**
 * Time the encryption and decryption of an AES implementation
 * @param impl the implementation to test
 * @param plaintext data to encrypt
 * @param plaintextSize length of plaintext buffer
 * @param key key to encrypt with
 * @param keySizeBytes length of key buffer in bytes
 * @param startIv initial iv value
 */
static std::pair<int, int> test(AesImpl       &impl,
                                const uint8_t *plaintext,
                                size_t         plaintextSize,
                                const uint8_t *key,
                                size_t         keySizeBytes,
                                const uint8_t *startIv)
{
	size_t            bufferSize = plaintextSize;
	CHERI::Capability ciphertext{ciphertextBuffer};
	ciphertext.bounds() = bufferSize;
	CHERI::Capability decryptedPlaintext{decryptedPlaintextBuffer};
	ciphertext.bounds() = bufferSize;

	impl.set_key(key, keySizeBytes);

	uint8_t workingIv[AES_CBC_IV_SIZE];

	// Encrypt buffer
	memcpy(ciphertext, plaintext, bufferSize);
	impl.init_working_iv(startIv, workingIv);
	auto encStart = rdcycle();
	impl.encrypt_bytes(workingIv, bufferSize, plaintext, ciphertext);
	auto encEnd = rdcycle();
	asm volatile("" : : : "memory");

#if AESBENCH_LOG_DATA == 1
	fprintf(stderr, "%s Ciphertext: ", impl.get_name());
	for (size_t i = 0; i < bufferSize; i++)
		fprintf(stderr, "%02x ", ciphertext[i]);
	fprintf(stderr, "\n");
#endif

	// Decrypt buffer
	memcpy(decryptedPlaintext, ciphertext, bufferSize);
	impl.init_working_iv(startIv, workingIv);
	auto decStart = rdcycle();
	impl.decrypt_bytes(workingIv, bufferSize, ciphertext, decryptedPlaintext);
	auto decEnd = rdcycle();
	asm volatile("" : : : "memory");

#if AESBENCH_LOG_DATA == 1
	fprintf(stderr, "%s Decrypted Plaintext: ", impl.get_name());
	for (size_t i = 0; i < bufferSize; i++)
		fprintf(stderr, "%02x ", decryptedPlaintext[i]);
	fprintf(stderr, "\n");
#endif

	// Check the output matches the original plaintext
	for (int i = 0; i < bufferSize; i++)
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

static void
fill_random_bytes(ds::xoroshiro::P16R8 &rand, uint8_t *buffer, size_t length)
{
	for (size_t i = 0; i < length; i++)
		buffer[i] = rand.next();
}

static uint8_t keyBuffer[MaximumKeySize];
static uint8_t plaintextBuffer[MaximumSize];

int __cheri_compartment("aesbench") run()
{
	ds::xoroshiro::P16R8  rand8(Seed);
	ds::xoroshiro::P64R32 rand32(Seed);

	const std::unique_ptr<AesImpl> Implementations[]{
	  // optimised for code size, non-constant time
	  std::make_unique<BearAesSmallCbc>(),
	  std::make_unique<BearAesSmallCtr>(),

	  // table based, fast, non-constant time
	  std::make_unique<BearAesBigCbc>(),
	  std::make_unique<BearAesBigCtr>(),

	  // constant-time, but slower than big
	  std::make_unique<BearAesCtCbc>(),
	  std::make_unique<BearAesCtCtr>(),

	  std::make_unique<MicroAes128CbcImpl>(),
	  std::make_unique<MicroAes128CtrImpl>(),

	  std::make_unique<MbedtlsAesCbcImpl>(),
	  std::make_unique<MbedtlsAesCtrImpl>(),
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

	for (size_t plaintextSize = MinimumSize; plaintextSize <= MaximumSize;
	     plaintextSize <<= 1)
	{
		CHERI::Capability plaintext{plaintextBuffer};
		plaintext.bounds() = plaintextSize;

		for (size_t plaintextId = 0; plaintextId < PlaintextCount;
		     plaintextId++)
		{
			fill_random_bytes(rand8, plaintext, plaintextSize);

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
					fill_random_bytes(rand8, key, keySizeBytes);

					for (size_t ivId = 0; ivId < IvCount; ivId++)
					{
						uint8_t startIv[AES_CBC_IV_SIZE];
						fill_random_bytes(rand8, startIv, sizeof startIv);

						// CTR's IV is only 12 bytes, so it's fine to just use
						// a subsection of this array for that
						static_assert(AES_CTR_IV_SIZE < AES_CBC_IV_SIZE);

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
