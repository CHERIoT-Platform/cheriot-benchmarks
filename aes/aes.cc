// Copyright SCI Semiconductor
// SPDX-License-Identifier: MIT

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

#ifndef DEBUG_AESBENCH
#	define DEBUG_AESBENCH false
#endif

using Debug = ConditionalDebug<DEBUG_AESBENCH, "AES benchmark">;

#define AES_IV_SIZE 16

class AesImpl
{
	public:
	/*
	    Set the active key, required to stay alive for the lifetime of this
	    class
	*/
	virtual void set_key(const uint8_t *key, size_t keySize) = 0;

	/*
	    Encrypt plaintext, updating iv and plaintext in-place
	*/
	virtual void
	encrypt_bytes(uint8_t *iv, uint8_t *plaintext, size_t plainTextSize) = 0;

	/*
	    Decrypt ciphertext, updating iv and ciphertext in-place
	*/
	virtual void
	decrypt_bytes(uint8_t *iv, uint8_t *ciphertext, size_t ciphertextSize) = 0;

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
class BearSslAesImpl : public AesImpl
{
	EncCtx encCtx;
	DecCtx decCtx;

	void set_key(const uint8_t *key, size_t keySize) override
	{
		EncInitFunc(&encCtx, key, keySize);
		DecInitFunc(&decCtx, key, keySize);
	}

	void encrypt_bytes(uint8_t *iv,
	                   uint8_t *plaintext,
	                   size_t   plainTextSize) override
	{ EncRunFunc(&encCtx, iv, plaintext, plainTextSize); }

	void decrypt_bytes(uint8_t *iv,
	                   uint8_t *ciphertext,
	                   size_t   ciphertextSize) override
	{ DecRunFunc(&decCtx, iv, ciphertext, ciphertextSize); }

	const char *get_name() override
	{ return Name; }
};

const char BearAesSmallName[] = "BearSSL.aes_small";
using BearAesSmall            = BearSslAesImpl<br_aes_small_cbcenc_keys,
                                               br_aes_small_cbcdec_keys,
                                               br_aes_small_cbcenc_init,
                                               br_aes_small_cbcenc_run,
                                               br_aes_small_cbcdec_init,
                                               br_aes_small_cbcdec_run,
                                               BearAesSmallName>;

const char BearAesBigName[] = "BearSSL.aes_big";
using BearAesBig            = BearSslAesImpl<br_aes_big_cbcenc_keys,
                                             br_aes_big_cbcdec_keys,
                                             br_aes_big_cbcenc_init,
                                             br_aes_big_cbcenc_run,
                                             br_aes_big_cbcdec_init,
                                             br_aes_big_cbcdec_run,
                                             BearAesBigName>;

const char BearAesCtName[] = "BearSSL.aes_ct";
using BearAesCt            = BearSslAesImpl<br_aes_ct_cbcenc_keys,
                                            br_aes_ct_cbcdec_keys,
                                            br_aes_ct_cbcenc_init,
                                            br_aes_ct_cbcenc_run,
                                            br_aes_ct_cbcdec_init,
                                            br_aes_ct_cbcdec_run,
                                            BearAesCtName>;

static std::pair<int, int> test(AesImpl       &impl,
                                const uint8_t *plaintext,
                                size_t         plaintextSize,
                                const uint8_t *key,
                                size_t         keySizeBytes,
                                const uint8_t *startIv)
{
	impl.set_key(key, keySizeBytes);

	// Duplicate plaintext to allow modifying in-place
	auto workingText = std::make_unique<uint8_t[]>(plaintextSize);
	Debug::Assert(workingText != nullptr, "Couldn't allocate workingText");
	memcpy(workingText.get(), plaintext, plaintextSize);

	// Duplicate IV to allow modifying in-place
	uint8_t workingIv[AES_IV_SIZE];
	memcpy(workingIv, startIv, sizeof workingIv);

	// Encrypt buffer
	auto encStart = rdcycle();
	impl.encrypt_bytes(workingIv, workingText.get(), plaintextSize);
	auto encEnd = rdcycle();
	asm volatile("" : : : "memory");

	// Decrypt buffer
	memcpy(workingIv, startIv, sizeof workingIv);
	auto decStart = rdcycle();
	impl.decrypt_bytes(workingIv, workingText.get(), plaintextSize);
	auto decEnd = rdcycle();
	asm volatile("" : : : "memory");

	// Check the output matches the original plaintext
	for (int i = 0; i < plaintextSize; i++)
	{
		Debug::Invariant(plaintext[i] == workingText[i],
		                 "{} byte {} was not a round trip",
		                 impl.get_name(),
		                 i);
	}

	return {
	  encEnd - encStart,
	  decEnd - decStart,
	};
}

// Range of plaintext sizes to test
const size_t MinimumSize = 32;
const size_t MaximumSize = 32 * 1024; // TODO: a good size

// Number of plaintexts to test per size
const size_t PlaintextCount = 3;

// Number of key sizes to test per plaintext
const size_t KeySizes[] = {128 /*, 256 */};

// Number of keys to test per key size
const size_t KeyCount = 3;

// Number of IVs to test per key
const size_t IvCount = 3;

// Repetition count for each input combination
const size_t RepeatCount = 3;

const uint8_t Seed = 1;

static void
fill_random_bytes(ds::xoroshiro::P16R8 &rand, uint8_t *buffer, size_t length)
{
	for (size_t i = 0; i < length; i++)
		buffer[i] = rand.next();
}

int __cheri_compartment("aesbench") run()
{
	ds::xoroshiro::P16R8 rand(Seed);

	AesImpl *const Implementations[]{
	  // optimised for code size, non-constant time
	  new BearAesSmall(),

	  // table based, fast, non-constant time
	  new BearAesBig(),

	  // constant-time, but slower than big
	  new BearAesCt(),
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
			fill_random_bytes(rand, plaintext.get(), plaintextSize);

			for (size_t keySize : KeySizes)
			{
				size_t keySizeBytes = keySize / 8;
				auto   key          = std::make_unique<uint8_t[]>(keySizeBytes);
				Debug::Assert(key != nullptr, "Couldn't allocate key");

				for (size_t keyId = 0; keyId < KeyCount; keyId++)
				{
					fill_random_bytes(rand, key.get(), keySizeBytes);

					for (size_t ivId = 0; ivId < IvCount; ivId++)
					{
						uint8_t startIv[AES_IV_SIZE];
						fill_random_bytes(rand, startIv, sizeof startIv);

						for (AesImpl *impl : Implementations)
						{
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
								printf("%s\t%zu\t%zu\t%zu\t%zu\t%zu\t%zu\t%s\t%"
								       "d\t%d\n",
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
