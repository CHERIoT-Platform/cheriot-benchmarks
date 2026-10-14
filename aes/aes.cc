// Copyright SCI Semiconductor
// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

#include <allocator.h>
#include <compartment.h>
#include <debug.hh>
#include <ds/xoroshiro.h>
#include <fail-simulator-on-error.h>
#include <locks.hh>
#include <platform-rdcycle.h>

#include <bearssl_block.h>
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
    Generic AES encryption/decryption interface
*/

#define AES_CBC_IV_SIZE 16
#define AES_CTR_IV_SIZE 12

class AesImpl
{
	public:
	/*
	    Check that a key size is usable for this implementation
	*/
	virtual bool supports_key_size(size_t keySize) = 0;

	/*
	    Set the active key, required to stay alive for the lifetime of this
	    class
	*/
	virtual void set_key(const uint8_t *key, size_t keySize) = 0;

	/*
	    Encrypt plaintext
	    Implementations may require that plaintext and ciphertext do not overlap
	    (ex. micro-AES)
	*/
	virtual void encrypt_bytes(const uint8_t *iv,
	                           const uint8_t *plaintext,
	                           size_t         plainTextSize,
	                           uint8_t       *ciphertext) = 0;

	/*
	    Implementations may require that plaintext and ciphertext do not overlap
	    (ex. micro-AES)
	*/
	virtual void decrypt_bytes(const uint8_t *iv,
	                           const uint8_t *ciphertext,
	                           size_t         ciphertextSize,
	                           uint8_t       *plaintext) = 0;

	/*
	    Get the name of the implementation used
	*/
	virtual const char *get_name() = 0;
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

	bool supports_key_size(size_t keySize) override
	{
		switch (keySize)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySize) override
	{
		EncInitFunc(&encCtx, key, keySize);
		DecInitFunc(&decCtx, key, keySize);
	}

	void encrypt_bytes(const uint8_t *iv,
	                   const uint8_t *plaintext,
	                   size_t         plainTextSize,
	                   uint8_t       *ciphertext) override
	{
		// BearSSL works in-place
		memcpy(ciphertext, plaintext, plainTextSize);
		uint8_t workingIv[AES_CBC_IV_SIZE];
		memcpy(workingIv, iv, AES_CBC_IV_SIZE);

		EncRunFunc(&encCtx, workingIv, ciphertext, plainTextSize);
	}

	void decrypt_bytes(const uint8_t *iv,
	                   const uint8_t *ciphertext,
	                   size_t         ciphertextSize,
	                   uint8_t       *plaintext) override
	{
		// BearSSL works in-place
		memcpy(plaintext, ciphertext, ciphertextSize);
		uint8_t workingIv[AES_CBC_IV_SIZE];
		memcpy(workingIv, iv, AES_CBC_IV_SIZE);

		DecRunFunc(&decCtx, workingIv, plaintext, ciphertextSize);
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
	bool supports_key_size(size_t keySize) override
	{ return keySize == 128; }

	const uint8_t *key;

	void set_key(const uint8_t *key, size_t keySize) override
	{ this->key = key; }

	void encrypt_bytes(const uint8_t *iv,
	                   const uint8_t *plaintext,
	                   size_t         plainTextSize,
	                   uint8_t       *ciphertext) override
	{ AES_CBC_encrypt(key, iv, plaintext, plainTextSize, ciphertext); }

	void decrypt_bytes(const uint8_t *iv,
	                   const uint8_t *ciphertext,
	                   size_t         ciphertextSize,
	                   uint8_t       *plaintext) override
	{ AES_CBC_decrypt(key, iv, ciphertext, ciphertextSize, plaintext); }

	const char *get_name() override
	{ return "micro-AES.128.CBC"; }
};

/*
    Helper class for implementations using the same function for encryption and
    decryption
*/
class AesSymmetricImpl : public AesImpl
{
	/*
	    Encrypt/decrypt inText to outText
	*/
	virtual void run(const uint8_t *iv,
	                 const uint8_t *inText,
	                 size_t         inTextSize,
	                 uint8_t       *outText) = 0;

	void encrypt_bytes(const uint8_t *iv,
	                   const uint8_t *plaintext,
	                   size_t         plainTextSize,
	                   uint8_t       *ciphertext) override
	{ run(iv, plaintext, plainTextSize, ciphertext); }

	void decrypt_bytes(const uint8_t *iv,
	                   const uint8_t *ciphertext,
	                   size_t         ciphertextSize,
	                   uint8_t       *plaintext) override
	{ run(iv, ciphertext, ciphertextSize, plaintext); }
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

	bool supports_key_size(size_t keySize) override
	{
		switch (keySize)
		{
			case 128:
			case 192:
			case 256:
				return true;
			default:
				return false;
		}
	}

	void set_key(const uint8_t *key, size_t keySize) override
	{ InitFunc(&ctx, key, keySize); }

	void run(const uint8_t *iv,
	         const uint8_t *inText,
	         size_t         inTextSize,
	         uint8_t       *outText) override
	{
		// BearSSL works in-place
		memcpy(outText, inText, inTextSize);

		// Use the same counter start value as micro-AES
		uint32_t cc = 1;

		RunFunc(&ctx, iv, cc, outText, inTextSize);
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
	bool supports_key_size(size_t keySize) override
	{ return keySize == 128; }

	const uint8_t *key;

	void set_key(const uint8_t *key, size_t keySize) override
	{ this->key = key; }

	void run(const uint8_t *iv,
	         const uint8_t *inText,
	         size_t         inTextSize,
	         uint8_t       *outText) override
	{ AES_CTR_encrypt(key, iv, inText, inTextSize, outText); }

	const char *get_name() override
	{ return "micro-AES.128.CTR"; }
};

static std::pair<int, int> test(AesImpl       &impl,
                                const uint8_t *plaintext,
                                size_t         plaintextSize,
                                const uint8_t *key,
                                size_t         keySizeBytes,
                                const uint8_t *startIv)
{
	impl.set_key(key, keySizeBytes);

	auto ciphertext = std::make_unique<uint8_t[]>(plaintextSize);
	Debug::Assert(ciphertext != nullptr, "Couldn't allocate ciphertext");

	auto decryptedPlaintext = std::make_unique<uint8_t[]>(plaintextSize);
	Debug::Assert(decryptedPlaintext != nullptr,
	              "Couldn't allocate decryptedPlaintext");

	// Encrypt buffer
	auto encStart = rdcycle();
	impl.encrypt_bytes(startIv, plaintext, plaintextSize, ciphertext.get());
	auto encEnd = rdcycle();
	asm volatile("" : : : "memory");

#if AESBENCH_LOG_DATA == 1
	fprintf(stderr, "%s Ciphertext: ", impl.get_name());
	for (size_t i = 0; i < plaintextSize; i++)
		fprintf(stderr, "%02x ", ciphertext[i]);
	fprintf(stderr, "\n");
#endif

	// Decrypt buffer
	auto decStart = rdcycle();
	impl.decrypt_bytes(
	  startIv, ciphertext.get(), plaintextSize, decryptedPlaintext.get());
	auto decEnd = rdcycle();
	asm volatile("" : : : "memory");

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

static void
fill_random_bytes(ds::xoroshiro::P16R8 &rand, uint8_t *buffer, size_t length)
{
	for (size_t i = 0; i < length; i++)
		buffer[i] = rand.next();
}

int __cheri_compartment("aesbench") run()
{
	ds::xoroshiro::P16R8  rand8(Seed);
	ds::xoroshiro::P64R32 rand32(Seed);

	AesImpl *const Implementations[]{
	  // optimised for code size, non-constant time
	  new BearAesSmallCbc(),
	  new BearAesSmallCtr(),

	  // table based, fast, non-constant time
	  new BearAesBigCbc(),
	  new BearAesBigCtr(),

	  // constant-time, but slower than big
	  new BearAesCtCbc(),
	  new BearAesCtCtr(),

	  new MicroAes128CbcImpl(),
	  new MicroAes128CtrImpl(),
	};

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
		auto plaintext = std::make_unique<uint8_t[]>(plaintextSize);
		Debug::Assert(plaintext != nullptr, "Couldn't allocate plaintext");

		for (size_t plaintextId = 0; plaintextId < PlaintextCount;
		     plaintextId++)
		{
			fill_random_bytes(rand8, plaintext.get(), plaintextSize);

#if AESBENCH_LOG_DATA == 1
			fprintf(stderr, "Plaintext: ");
			for (size_t i = 0; i < plaintextSize; i++)
				fprintf(stderr, "%02x ", plaintext[i]);
			fprintf(stderr, "\n");
#endif

			for (size_t keySize : KeySizes)
			{
				size_t keySizeBytes = keySize / 8;
				auto   key          = std::make_unique<uint8_t[]>(keySizeBytes);
				Debug::Assert(key != nullptr, "Couldn't allocate key");

				for (size_t keyId = 0; keyId < KeyCount; keyId++)
				{
					fill_random_bytes(rand8, key.get(), keySizeBytes);

					for (size_t ivId = 0; ivId < IvCount; ivId++)
					{
						uint8_t startIv[AES_CBC_IV_SIZE];
						fill_random_bytes(rand8, startIv, sizeof startIv);

						// CTR's IV is only 12 bytes, so it's fine to just use
						// a subsection of this array for that
						static_assert(AES_CTR_IV_SIZE < AES_CBC_IV_SIZE);

						for (AesImpl *impl : Implementations)
						{
							if (!impl->supports_key_size(keySize))
								continue;

							for (size_t repetition = 0;
							     repetition < RepeatCount;
							     repetition++)
							{
								auto [encRuntime, decRuntime] =
								  test(*impl,
								       plaintext.get(),
								       plaintextSize,
								       key.get(),
								       keySizeBytes,
								       startIv);
								printf("%s\t%zu\t%zu\t%zu\t%zu\t%zu\t%zu\t%"
								       "s\t%d\t%d\n",
								       __XSTRING(BOARD),
								       plaintextSize,
								       plaintextId,
								       keySize,
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
