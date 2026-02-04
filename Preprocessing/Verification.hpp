
#ifndef ECDSA_PREPROCESSING_HPP_
#define ECDSA_PREPROCESSING_HPP_

#include "P256Element.h"
#include "EcdsaOptions.h"
#include "Processor/Data_Files.h"
#include "Protocols/ReplicatedPrep.h"
#include "Protocols/MaliciousShamirShare.h"
#include "Protocols/Rep3Share.h"
#include "GC/TinierSecret.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/TinyMC.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

#include "GC/TinierSharePrep.hpp"
#include "GC/CcdSecret.h"

template<template<class U> class T>
class EcTuple
{
public:
    T<P256Element::Scalar> a;
    T<P256Element::Scalar> b;
    P256Element::Scalar c;
    T<P256Element> secret_R; // k
    P256Element R;
};

// RSA implementation
EVP_PKEY* generate_rsa_keypair(int bits = 2048) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw runtime_error("Failed to create key context");
    }

    EVP_PKEY* pkey = nullptr;
    try {
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            throw runtime_error("Failed to initialize key generation");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
            throw runtime_error("Failed to set key length");
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            throw runtime_error("Failed to generate key");
        }
    }
    catch (...) {
        EVP_PKEY_CTX_free(ctx);
        throw;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

vector<unsigned char> rsa_sign(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len) {
    if (!pkey || !msg) {
        throw runtime_error("Invalid input parameters for RSA signing");
    }

    // Create the Message Digest Context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw runtime_error("Failed to create message digest context");
    }

    vector<unsigned char> signature;
    size_t sig_len = 0;

    try {
        // Initialize signing operation
        if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
            throw runtime_error("Failed to initialize signing operation");
        }

        // Calculate signature length
        if (EVP_DigestSign(md_ctx, nullptr, &sig_len, msg, msg_len) <= 0) {
            throw runtime_error("Failed to calculate signature length");
        }

        // Allocate memory for signature
        signature.resize(sig_len);

        // Generate signature
        if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, msg, msg_len) <= 0) {
            throw runtime_error("Failed to generate signature");
        }

        signature.resize(sig_len);
    }
    catch (...) {
        EVP_MD_CTX_free(md_ctx);
        throw;
    }

    EVP_MD_CTX_free(md_ctx);
    return signature;
}

bool rsa_verify(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                const vector<unsigned char>& signature) {
    if (!pkey || !msg) {
        throw runtime_error("Invalid input parameters for RSA verification");
    }

    // Create the Message Digest Context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw runtime_error("Failed to create message digest context");
    }

    bool result = false;
    try {
        // Initialize verification operation
        if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
            throw runtime_error("Failed to initialize verification operation");
        }

        // Verify the signature
        int verify_result = EVP_DigestVerify(md_ctx, signature.data(), signature.size(),
                                           msg, msg_len);
        result = (verify_result == 1);
    }
    catch (...) {
        EVP_MD_CTX_free(md_ctx);
        throw;
    }

    EVP_MD_CTX_free(md_ctx);
    return result;
}

// Structure to hold encryption results
struct EncryptionResult {
    vector<unsigned char> ciphertext;
    vector<unsigned char> tag;
    vector<unsigned char> iv;
};

// Print OpenSSL errors
void print_openssl_errors() {
    char err_buf[256];
    unsigned long err;

    while ((err = ERR_get_error())) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        cerr << "OpenSSL Error: " << err_buf << endl;
    }
}

// Generate a random AES-256 key
vector<unsigned char> generate_aes_key() {
    vector<unsigned char> key(32);
    if (RAND_bytes(key.data(), key.size()) != 1) {
        throw runtime_error("Failed to generate random AES key");
    }
    return key;
}

// Generate a random IV for AES-GCM
vector<unsigned char> generate_iv() {
    vector<unsigned char> iv(12);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw runtime_error("Failed to generate random IV");
    }
    return iv;
}

// Generate a random message of specified size
vector<unsigned char> generate_random_message(size_t size) {
    vector<unsigned char> message(size);
    if (RAND_bytes(message.data(), message.size()) != 1) {
        throw runtime_error("Failed to generate random message");
    }
    return message;
}

// Encrypt data using AES-256-GCM
EncryptionResult aes_gcm_encrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& iv,
    const vector<unsigned char>& plaintext) {

    EncryptionResult result;
    result.iv = iv;
    result.ciphertext.resize(plaintext.size());
    result.tag.resize(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_errors();
        throw runtime_error("Failed to create new EVP_CIPHER_CTX");
    }

    try {
        // Initialize the encryption operation
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to initialize encryption");
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to set IV length");
        }

        // Initialize key and IV
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to set key and IV");
        }

        int len;
        // Provide the message to be encrypted
        if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed in EVP_EncryptUpdate");
        }

        int ciphertext_len = len;

        // Finalize the encryption
        if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed in EVP_EncryptFinal_ex");
        }

        ciphertext_len += len;
        result.ciphertext.resize(ciphertext_len);

        // Get the tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, result.tag.size(), result.tag.data()) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to get the tag");
        }

        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

// Decrypt data using AES-256-GCM
vector<unsigned char> aes_gcm_decrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& iv,
    const vector<unsigned char>& ciphertext,
    const vector<unsigned char>& tag) {

    vector<unsigned char> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_errors();
        throw runtime_error("Failed to create new EVP_CIPHER_CTX");
    }

    try {
        // Initialize the decryption operation
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to initialize decryption");
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to set IV length");
        }

        // Initialize key and IV
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to set key and IV");
        }

        int len;
        // Provide the ciphertext to be decrypted, and get the output
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed in EVP_DecryptUpdate");
        }

        int plaintext_len = len;

        // Set the expected tag value
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char*>(tag.data())) != 1) {
            print_openssl_errors();
            throw runtime_error("Failed to set expected tag value");
        }

        // Finalize the decryption
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

        // Check if the decryption was successful
        if (ret <= 0) {
            print_openssl_errors();
            throw runtime_error("Authentication failed or decrypt error");
        }

        plaintext_len += len;
        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }
    catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}
// schnorr verify
template<template<class U> class T>
void schnorr_verify(int buffer_size,
        vector<T<P256Element::Scalar>>& s,
        vector<T<P256Element>>& Pk,
        vector<T<P256Element>>& Ra,
        vector<P256Element::Scalar>& e_opened,
        SubProcessor<T<P256Element::Scalar>>& proc)
{
    Timer timer;
    timer.start();
    Player& P = proc.P;
//    auto& prep = proc.DataF;
    size_t start = P.total_comm().sent;
    auto stats = P.total_comm();
    auto& extra_player = P;

    auto& MCp = proc.MC;
    typedef T<typename P256Element::Scalar> pShare;
    typedef T<P256Element> cShare;

    typename cShare::Direct_MC MCc(MCp.get_alphai());

//    P256Element right_side_opened, left_side_opened;

    P256Element right_side,left_side;

    // Batch verification
    string seed = "BatchVerificationSeed";
    cShare R_batch, Pk_e_mul_batch, S_batch;
    pShare s_batch;
//    P256Element temp;
    vector<P256Element::Scalar> a;
    for (int i = 1; i < buffer_size; ++i){
      a.push_back(P256Element::generate_ai(seed, i));
    }
    for (int i = 1; i < buffer_size; ++i) {
      R_batch+=Ra[i] * a[i];
      Pk_e_mul_batch+= (Pk[i] * e_opened[i] * a[i]);
      s_batch+= s[i] * a[i] ;
    }

    left_side = MCc.open(R_batch + Pk_e_mul_batch, extra_player);
    right_side = MCc.open(s_batch, extra_player);
    cout << "Bacth verififcation is " << (left_side == right_side? "valid": "wrong") << endl;

    timer.stop();
    cout << "Verified " << buffer_size << " identification proofs "<< endl;
    cout << "MPC total verification time: " << timer.elapsed()
            << " seconds, throughput " << buffer_size / timer.elapsed() << ", "
            << 1e-3 * (P.total_comm().sent - start) / buffer_size
            << " kbytes per tuple" << endl;
    (P.total_comm() - stats).print(true);
}



#endif /* ECDSA_PREPROCESSING_HPP_ */
