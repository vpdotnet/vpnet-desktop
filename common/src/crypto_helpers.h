// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include "common.h"
#line HEADER_FILE("crypto_helpers.h")

#ifndef CRYPTO_HELPERS_H
#define CRYPTO_HELPERS_H

#include <cstddef>
#include "openssl.h" // Include OpenSSL headers for the required types

// Forward declarations for OpenSSL types
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct engine_st ENGINE;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

#ifdef __cplusplus
extern "C" {
#endif

// X25519 key exchange function
COMMON_EXPORT bool curve25519(unsigned char *out, const unsigned char *private_key, const unsigned char *public_key);

// OpenSSL function pointers are internal to crypto_helpers.cpp

// Constants
#ifndef EVP_PKEY_X25519
#define EVP_PKEY_X25519 1034 // NID_X25519
#endif
#ifndef EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#endif
#ifndef EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_AEAD_SET_TAG 0x11
#endif

// ChaCha20-Poly1305 AEAD decryption
COMMON_EXPORT bool decrypt_chacha20poly1305(
    unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *key, size_t key_len);

#ifdef __cplusplus
}
#endif

// WireGuard encrypted IP decryption using X25519 key exchange and ChaCha20-Poly1305
// This function is not part of the C API because it returns a QString
COMMON_EXPORT QString decrypt_wireguard_ip(
    const QByteArray &encryptedData,
    const unsigned char *privateKey,
    const unsigned char *serverPubkey);


#endif // CRYPTO_HELPERS_H