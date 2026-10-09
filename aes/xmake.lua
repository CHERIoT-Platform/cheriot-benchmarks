-- Copyright Microsoft and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

set_project("CHERIoT AES benchmark benchmark");
sdkdir = "../cheriot-rtos/sdk"
includes(sdkdir)
set_toolchains("cheriot-clang")

option("board")
    set_default("sail")

bearssl = "../network-stack/third_party/BearSSL"

debugOption("aesbench");
compartment("aesbench")
    add_deps("crt", "cxxrt", "freestanding", "atomic", "stdio", "debug")

    -- Allow allocating an effectively unbounded amount of memory (more than exists)
    add_rules("cheriot.component-debug")
	add_deps("unwind_error_handler")
    add_defines("MALLOC_QUOTA=1000000")
    add_defines("BOARD=" .. tostring(get_config("board")))

    add_files("aes.cc")

    -- BearSSL Configuration
    add_defines("BR_INT128=0", "BR_UMUL128=0", "BR_USE_UNIX_TIME=1")
    -- BearSSL sources:
    -- These must be split up because Lua has a limit to the number of arguments
    -- to a function.
    -- TODO: many not needed
    add_includedirs(
        bearssl .. "/src",
        bearssl .. "/inc"
    )
    add_files(bearssl .. "/src/settings.c")
    add_files(
        bearssl .. "/src/aead/ccm.c",
        bearssl .. "/src/aead/eax.c",
        bearssl .. "/src/aead/gcm.c")
    add_files(
        bearssl .. "/src/codec/ccopy.c",
        bearssl .. "/src/codec/dec16be.c",
        bearssl .. "/src/codec/dec16le.c",
        bearssl .. "/src/codec/dec32be.c",
        bearssl .. "/src/codec/dec32le.c",
        bearssl .. "/src/codec/dec64be.c",
        bearssl .. "/src/codec/dec64le.c",
        bearssl .. "/src/codec/enc16be.c",
        bearssl .. "/src/codec/enc16le.c",
        bearssl .. "/src/codec/enc32be.c",
        bearssl .. "/src/codec/enc32le.c",
        bearssl .. "/src/codec/enc64be.c",
        bearssl .. "/src/codec/enc64le.c",
        bearssl .. "/src/codec/pemdec.c",
        bearssl .. "/src/codec/pemenc.c")
    add_files(
        bearssl .. "/src/ec/ec_all_m15.c",
        bearssl .. "/src/ec/ec_all_m31.c",
        bearssl .. "/src/ec/ec_c25519_i15.c",
        bearssl .. "/src/ec/ec_c25519_i31.c",
        bearssl .. "/src/ec/ec_c25519_m15.c",
        bearssl .. "/src/ec/ec_c25519_m31.c",
        bearssl .. "/src/ec/ec_c25519_m62.c",
        bearssl .. "/src/ec/ec_c25519_m64.c",
        bearssl .. "/src/ec/ec_curve25519.c",
        bearssl .. "/src/ec/ec_default.c",
        bearssl .. "/src/ec/ec_keygen.c",
        bearssl .. "/src/ec/ec_p256_m15.c",
        bearssl .. "/src/ec/ec_p256_m31.c",
        bearssl .. "/src/ec/ec_p256_m62.c",
        bearssl .. "/src/ec/ec_p256_m64.c",
        bearssl .. "/src/ec/ec_prime_i15.c",
        bearssl .. "/src/ec/ec_prime_i31.c",
        bearssl .. "/src/ec/ec_pubkey.c",
        bearssl .. "/src/ec/ec_secp256r1.c",
        bearssl .. "/src/ec/ec_secp384r1.c",
        bearssl .. "/src/ec/ec_secp521r1.c",
        bearssl .. "/src/ec/ecdsa_atr.c",
        bearssl .. "/src/ec/ecdsa_default_sign_asn1.c",
        bearssl .. "/src/ec/ecdsa_default_sign_raw.c",
        bearssl .. "/src/ec/ecdsa_default_vrfy_asn1.c",
        bearssl .. "/src/ec/ecdsa_default_vrfy_raw.c",
        bearssl .. "/src/ec/ecdsa_i15_bits.c",
        bearssl .. "/src/ec/ecdsa_i15_sign_asn1.c",
        bearssl .. "/src/ec/ecdsa_i15_sign_raw.c",
        bearssl .. "/src/ec/ecdsa_i15_vrfy_asn1.c",
        bearssl .. "/src/ec/ecdsa_i15_vrfy_raw.c",
        bearssl .. "/src/ec/ecdsa_i31_bits.c",
        bearssl .. "/src/ec/ecdsa_i31_sign_asn1.c",
        bearssl .. "/src/ec/ecdsa_i31_sign_raw.c",
        bearssl .. "/src/ec/ecdsa_i31_vrfy_asn1.c",
        bearssl .. "/src/ec/ecdsa_i31_vrfy_raw.c",
        bearssl .. "/src/ec/ecdsa_rta.c")
    add_files(
        bearssl .. "/src/hash/dig_oid.c",
        bearssl .. "/src/hash/dig_size.c",
        bearssl .. "/src/hash/ghash_ctmul.c",
        bearssl .. "/src/hash/ghash_ctmul32.c",
        bearssl .. "/src/hash/ghash_ctmul64.c",
        bearssl .. "/src/hash/ghash_pclmul.c",
        bearssl .. "/src/hash/ghash_pwr8.c",
        bearssl .. "/src/hash/md5.c",
        bearssl .. "/src/hash/md5sha1.c",
        bearssl .. "/src/hash/mgf1.c",
        bearssl .. "/src/hash/multihash.c",
        bearssl .. "/src/hash/sha1.c",
        bearssl .. "/src/hash/sha2big.c",
        bearssl .. "/src/hash/sha2small.c")
    add_files(
        bearssl .. "/src/int/i15_add.c",
        bearssl .. "/src/int/i15_bitlen.c",
        bearssl .. "/src/int/i15_decmod.c",
        bearssl .. "/src/int/i15_decode.c",
        bearssl .. "/src/int/i15_decred.c",
        bearssl .. "/src/int/i15_encode.c",
        bearssl .. "/src/int/i15_fmont.c",
        bearssl .. "/src/int/i15_iszero.c",
        bearssl .. "/src/int/i15_moddiv.c",
        bearssl .. "/src/int/i15_modpow.c",
        bearssl .. "/src/int/i15_modpow2.c",
        bearssl .. "/src/int/i15_montmul.c",
        bearssl .. "/src/int/i15_mulacc.c",
        bearssl .. "/src/int/i15_muladd.c",
        bearssl .. "/src/int/i15_ninv15.c",
        bearssl .. "/src/int/i15_reduce.c",
        bearssl .. "/src/int/i15_rshift.c",
        bearssl .. "/src/int/i15_sub.c",
        bearssl .. "/src/int/i15_tmont.c",
        bearssl .. "/src/int/i31_add.c",
        bearssl .. "/src/int/i31_bitlen.c",
        bearssl .. "/src/int/i31_decmod.c",
        bearssl .. "/src/int/i31_decode.c",
        bearssl .. "/src/int/i31_decred.c",
        bearssl .. "/src/int/i31_encode.c",
        bearssl .. "/src/int/i31_fmont.c",
        bearssl .. "/src/int/i31_iszero.c",
        bearssl .. "/src/int/i31_moddiv.c",
        bearssl .. "/src/int/i31_modpow.c",
        bearssl .. "/src/int/i31_modpow2.c",
        bearssl .. "/src/int/i31_montmul.c",
        bearssl .. "/src/int/i31_mulacc.c",
        bearssl .. "/src/int/i31_muladd.c",
        bearssl .. "/src/int/i31_ninv31.c",
        bearssl .. "/src/int/i31_reduce.c",
        bearssl .. "/src/int/i31_rshift.c",
        bearssl .. "/src/int/i31_sub.c",
        bearssl .. "/src/int/i31_tmont.c",
        bearssl .. "/src/int/i32_add.c",
        bearssl .. "/src/int/i32_bitlen.c",
        bearssl .. "/src/int/i32_decmod.c",
        bearssl .. "/src/int/i32_decode.c",
        bearssl .. "/src/int/i32_decred.c",
        bearssl .. "/src/int/i32_div32.c",
        bearssl .. "/src/int/i32_encode.c",
        bearssl .. "/src/int/i32_fmont.c",
        bearssl .. "/src/int/i32_iszero.c",
        bearssl .. "/src/int/i32_modpow.c",
        bearssl .. "/src/int/i32_montmul.c",
        bearssl .. "/src/int/i32_mulacc.c",
        bearssl .. "/src/int/i32_muladd.c",
        bearssl .. "/src/int/i32_ninv32.c",
        bearssl .. "/src/int/i32_reduce.c",
        bearssl .. "/src/int/i32_sub.c",
        bearssl .. "/src/int/i32_tmont.c",
        bearssl .. "/src/int/i62_modpow2.c")
    add_files(
        bearssl .. "/src/kdf/hkdf.c",
        bearssl .. "/src/kdf/shake.c")
    add_files(
        bearssl .. "/src/mac/hmac.c",
        bearssl .. "/src/mac/hmac_ct.c")
    add_files(
        bearssl .. "/src/rand/aesctr_drbg.c",
        bearssl .. "/src/rand/hmac_drbg.c",
        bearssl .. "/src/rand/sysrng.c")
    add_files(
        bearssl .. "/src/rsa/rsa_default_keygen.c",
        bearssl .. "/src/rsa/rsa_default_modulus.c",
        bearssl .. "/src/rsa/rsa_default_oaep_decrypt.c",
        bearssl .. "/src/rsa/rsa_default_oaep_encrypt.c",
        bearssl .. "/src/rsa/rsa_default_pkcs1_sign.c",
        bearssl .. "/src/rsa/rsa_default_pkcs1_vrfy.c",
        bearssl .. "/src/rsa/rsa_default_priv.c",
        bearssl .. "/src/rsa/rsa_default_privexp.c",
        bearssl .. "/src/rsa/rsa_default_pss_sign.c",
        bearssl .. "/src/rsa/rsa_default_pss_vrfy.c",
        bearssl .. "/src/rsa/rsa_default_pub.c",
        bearssl .. "/src/rsa/rsa_default_pubexp.c",
        bearssl .. "/src/rsa/rsa_i15_keygen.c",
        bearssl .. "/src/rsa/rsa_i15_modulus.c",
        bearssl .. "/src/rsa/rsa_i15_oaep_decrypt.c",
        bearssl .. "/src/rsa/rsa_i15_oaep_encrypt.c",
        bearssl .. "/src/rsa/rsa_i15_pkcs1_sign.c",
        bearssl .. "/src/rsa/rsa_i15_pkcs1_vrfy.c",
        bearssl .. "/src/rsa/rsa_i15_priv.c",
        bearssl .. "/src/rsa/rsa_i15_privexp.c",
        bearssl .. "/src/rsa/rsa_i15_pss_sign.c",
        bearssl .. "/src/rsa/rsa_i15_pss_vrfy.c",
        bearssl .. "/src/rsa/rsa_i15_pub.c",
        bearssl .. "/src/rsa/rsa_i15_pubexp.c",
        bearssl .. "/src/rsa/rsa_i31_keygen.c",
        bearssl .. "/src/rsa/rsa_i31_keygen_inner.c",
        bearssl .. "/src/rsa/rsa_i31_modulus.c",
        bearssl .. "/src/rsa/rsa_i31_oaep_decrypt.c",
        bearssl .. "/src/rsa/rsa_i31_oaep_encrypt.c",
        bearssl .. "/src/rsa/rsa_i31_pkcs1_sign.c",
        bearssl .. "/src/rsa/rsa_i31_pkcs1_vrfy.c",
        bearssl .. "/src/rsa/rsa_i31_priv.c",
        bearssl .. "/src/rsa/rsa_i31_privexp.c",
        bearssl .. "/src/rsa/rsa_i31_pss_sign.c",
        bearssl .. "/src/rsa/rsa_i31_pss_vrfy.c",
        bearssl .. "/src/rsa/rsa_i31_pub.c",
        bearssl .. "/src/rsa/rsa_i31_pubexp.c",
        bearssl .. "/src/rsa/rsa_i32_oaep_decrypt.c",
        bearssl .. "/src/rsa/rsa_i32_oaep_encrypt.c",
        bearssl .. "/src/rsa/rsa_i32_pkcs1_sign.c",
        bearssl .. "/src/rsa/rsa_i32_pkcs1_vrfy.c",
        bearssl .. "/src/rsa/rsa_i32_priv.c",
        bearssl .. "/src/rsa/rsa_i32_pss_sign.c",
        bearssl .. "/src/rsa/rsa_i32_pss_vrfy.c",
        bearssl .. "/src/rsa/rsa_i32_pub.c",
        bearssl .. "/src/rsa/rsa_i62_keygen.c",
        bearssl .. "/src/rsa/rsa_i62_oaep_decrypt.c",
        bearssl .. "/src/rsa/rsa_i62_oaep_encrypt.c",
        bearssl .. "/src/rsa/rsa_i62_pkcs1_sign.c",
        bearssl .. "/src/rsa/rsa_i62_pkcs1_vrfy.c",
        bearssl .. "/src/rsa/rsa_i62_priv.c",
        bearssl .. "/src/rsa/rsa_i62_pss_sign.c",
        bearssl .. "/src/rsa/rsa_i62_pss_vrfy.c",
        bearssl .. "/src/rsa/rsa_i62_pub.c",
        bearssl .. "/src/rsa/rsa_oaep_pad.c",
        bearssl .. "/src/rsa/rsa_oaep_unpad.c",
        bearssl .. "/src/rsa/rsa_pkcs1_sig_pad.c",
        bearssl .. "/src/rsa/rsa_pkcs1_sig_unpad.c",
        bearssl .. "/src/rsa/rsa_pss_sig_pad.c",
        bearssl .. "/src/rsa/rsa_pss_sig_unpad.c",
        bearssl .. "/src/rsa/rsa_ssl_decrypt.c")
    add_files(
        bearssl .. "/src/ssl/prf.c",
        bearssl .. "/src/ssl/prf_md5sha1.c",
        bearssl .. "/src/ssl/prf_sha256.c",
        bearssl .. "/src/ssl/prf_sha384.c",
        bearssl .. "/src/ssl/ssl_ccert_single_ec.c",
        bearssl .. "/src/ssl/ssl_ccert_single_rsa.c",
        bearssl .. "/src/ssl/ssl_client.c",
        bearssl .. "/src/ssl/ssl_client_default_rsapub.c",
        bearssl .. "/src/ssl/ssl_client_full.c",
        bearssl .. "/src/ssl/ssl_engine.c",
        bearssl .. "/src/ssl/ssl_engine_default_aescbc.c",
        bearssl .. "/src/ssl/ssl_engine_default_aesccm.c",
        bearssl .. "/src/ssl/ssl_engine_default_aesgcm.c",
        bearssl .. "/src/ssl/ssl_engine_default_chapol.c",
        bearssl .. "/src/ssl/ssl_engine_default_descbc.c",
        bearssl .. "/src/ssl/ssl_engine_default_ec.c",
        bearssl .. "/src/ssl/ssl_engine_default_ecdsa.c",
        bearssl .. "/src/ssl/ssl_engine_default_rsavrfy.c",
        bearssl .. "/src/ssl/ssl_hashes.c",
        bearssl .. "/src/ssl/ssl_hs_client.c",
        bearssl .. "/src/ssl/ssl_hs_server.c",
        bearssl .. "/src/ssl/ssl_io.c",
        bearssl .. "/src/ssl/ssl_keyexport.c",
        bearssl .. "/src/ssl/ssl_lru.c",
        bearssl .. "/src/ssl/ssl_rec_cbc.c",
        bearssl .. "/src/ssl/ssl_rec_ccm.c",
        bearssl .. "/src/ssl/ssl_rec_chapol.c",
        bearssl .. "/src/ssl/ssl_rec_gcm.c",
        bearssl .. "/src/ssl/ssl_scert_single_ec.c",
        bearssl .. "/src/ssl/ssl_scert_single_rsa.c",
        bearssl .. "/src/ssl/ssl_server.c",
        bearssl .. "/src/ssl/ssl_server_full_ec.c",
        bearssl .. "/src/ssl/ssl_server_full_rsa.c",
        bearssl .. "/src/ssl/ssl_server_mine2c.c",
        bearssl .. "/src/ssl/ssl_server_mine2g.c",
        bearssl .. "/src/ssl/ssl_server_minf2c.c",
        bearssl .. "/src/ssl/ssl_server_minf2g.c",
        bearssl .. "/src/ssl/ssl_server_minr2g.c",
        bearssl .. "/src/ssl/ssl_server_minu2g.c",
        bearssl .. "/src/ssl/ssl_server_minv2g.c")
    add_files(
        bearssl .. "/src/symcipher/aes_big_cbcdec.c",
        bearssl .. "/src/symcipher/aes_big_cbcenc.c",
        bearssl .. "/src/symcipher/aes_big_ctr.c",
        bearssl .. "/src/symcipher/aes_big_ctrcbc.c",
        bearssl .. "/src/symcipher/aes_big_dec.c",
        bearssl .. "/src/symcipher/aes_big_enc.c",
        bearssl .. "/src/symcipher/aes_common.c",
        bearssl .. "/src/symcipher/aes_ct.c",
        bearssl .. "/src/symcipher/aes_ct64.c",
        bearssl .. "/src/symcipher/aes_ct64_cbcdec.c",
        bearssl .. "/src/symcipher/aes_ct64_cbcenc.c",
        bearssl .. "/src/symcipher/aes_ct64_ctr.c",
        bearssl .. "/src/symcipher/aes_ct64_ctrcbc.c",
        bearssl .. "/src/symcipher/aes_ct64_dec.c",
        bearssl .. "/src/symcipher/aes_ct64_enc.c",
        bearssl .. "/src/symcipher/aes_ct_cbcdec.c",
        bearssl .. "/src/symcipher/aes_ct_cbcenc.c",
        bearssl .. "/src/symcipher/aes_ct_ctr.c",
        bearssl .. "/src/symcipher/aes_ct_ctrcbc.c",
        bearssl .. "/src/symcipher/aes_ct_dec.c",
        bearssl .. "/src/symcipher/aes_ct_enc.c",
        bearssl .. "/src/symcipher/aes_pwr8.c",
        bearssl .. "/src/symcipher/aes_pwr8_cbcdec.c",
        bearssl .. "/src/symcipher/aes_pwr8_cbcenc.c",
        bearssl .. "/src/symcipher/aes_pwr8_ctr.c",
        bearssl .. "/src/symcipher/aes_pwr8_ctrcbc.c",
        bearssl .. "/src/symcipher/aes_small_cbcdec.c",
        bearssl .. "/src/symcipher/aes_small_cbcenc.c",
        bearssl .. "/src/symcipher/aes_small_ctr.c",
        bearssl .. "/src/symcipher/aes_small_ctrcbc.c",
        bearssl .. "/src/symcipher/aes_small_dec.c",
        bearssl .. "/src/symcipher/aes_small_enc.c",
        bearssl .. "/src/symcipher/aes_x86ni.c",
        bearssl .. "/src/symcipher/aes_x86ni_cbcdec.c",
        bearssl .. "/src/symcipher/aes_x86ni_cbcenc.c",
        bearssl .. "/src/symcipher/aes_x86ni_ctr.c",
        bearssl .. "/src/symcipher/aes_x86ni_ctrcbc.c",
        bearssl .. "/src/symcipher/chacha20_ct.c",
        bearssl .. "/src/symcipher/chacha20_sse2.c",
        bearssl .. "/src/symcipher/des_ct.c",
        bearssl .. "/src/symcipher/des_ct_cbcdec.c",
        bearssl .. "/src/symcipher/des_ct_cbcenc.c",
        bearssl .. "/src/symcipher/des_support.c",
        bearssl .. "/src/symcipher/des_tab.c",
        bearssl .. "/src/symcipher/des_tab_cbcdec.c",
        bearssl .. "/src/symcipher/des_tab_cbcenc.c",
        bearssl .. "/src/symcipher/poly1305_ctmul.c",
        bearssl .. "/src/symcipher/poly1305_ctmul32.c",
        bearssl .. "/src/symcipher/poly1305_ctmulq.c",
        bearssl .. "/src/symcipher/poly1305_i15.c")
    add_files(
        bearssl .. "/src/x509/asn1enc.c",
        bearssl .. "/src/x509/encode_ec_pk8der.c",
        bearssl .. "/src/x509/encode_ec_rawder.c",
        bearssl .. "/src/x509/encode_rsa_pk8der.c",
        bearssl .. "/src/x509/encode_rsa_rawder.c",
        bearssl .. "/src/x509/skey_decoder.c")
    add_files(
        bearssl .. "/src/x509/x509_decoder.c",
        bearssl .. "/src/x509/x509_knownkey.c",
        --bearssl .. "/src/x509/x509_minimal.c",
        bearssl .. "/src/x509/x509_minimal_full.c")


-- Firmware image for the example.
firmware("aes-benchmark")
    add_deps("aesbench")

    on_load(function(target)
        target:values_set("threads", {
            {
                compartment = "aesbench",
                priority = 1,
                entry_point = "run",
                stack_size = 0x800,
                trusted_stack_frames = 4
            },
        }, {expand = false})
    end)
