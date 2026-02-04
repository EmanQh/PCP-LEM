
#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Protocols/Replicated.h"
#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/ReplicatedInput.h"
#include "Protocols/AtlasShare.h"
#include "Protocols/Rep4Share.h"
#include "Protocols/ProtocolSet.h"
#include "Math/gfp.h"
#include "ECDSA/P256Element.h"
#include "Tools/Bundle.h"
#include "GC/TinyMC.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/CcdSecret.h"
#include "GC/VectorInput.h"

#include "ECDSA/Verification.hpp"
#include "ECDSA/sign.hpp"
#include "Protocols/MaliciousRepMC.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MaliciousRepPrep.hpp"
#include "Processor/Input.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"
#include "GC/Secret.hpp"
#include "Machines/Shamir.hpp"
#include "Machines/MalRep.hpp"
#include "Machines/Rep.hpp"

#include <assert.h>
void RSA_test()
{
  try {
      // Default number of signatures if not specified
      int RSA_n_tuples = 15000;
      int message_size = 64; //512, 4096

      cout << "=== Testing RSA Signature and Verification Performance with " << RSA_n_tuples << " signatures ===" << endl;

      ERR_load_crypto_strings();

      // Generate RSA keypair
      EVP_PKEY* pkey = generate_rsa_keypair(2048);

      Timer signature_start;
      signature_start.start();

      // Pre-generate all messages and signatures
      // Generate test messages and signatures
      cout << "\nGenerating and signing messages for testing..." << endl;
      Timer signature_timer;
      signature_timer.start();
      vector<vector<unsigned char>> messages;
      vector<vector<unsigned char>> signatures;
      for (int i = 0; i < RSA_n_tuples; i++) {
          // Generate random message
          vector<unsigned char> message = generate_random_message(message_size);
          messages.push_back(message);

          // Sign the message
          signatures.push_back(rsa_sign(pkey,
              message.data(),
              message.size()));

          if ((i + 1) % 100 == 0 || i == RSA_n_tuples - 1) {
              cout << "Signed " << (i + 1) << " messages\r" << flush;
          }
      }
      cout << "\n\nDSO total signature time: " << (signature_start.elapsed() * 1e3) << " ms, throughput " << RSA_n_tuples /signature_start.elapsed()<< ", average single signature time: "<<(signature_start.elapsed() * 1e3)/RSA_n_tuples <<" ms" << endl;

      cout << "\nPerforming verification tests..." << endl;

      // Start timing verification
      Timer verify_start;
      verify_start.start();
      // Perform verifications
      for (int i = 0; i < RSA_n_tuples; i++) {
          bool verified = rsa_verify(pkey,
              messages[i].data(),
              messages[i].size(),
              signatures[i]);
          if (!verified) {
              cerr << "Verification failed for message " << i << endl;
              EVP_PKEY_free(pkey);
              exit(1);
          }
          if ((i + 1) % 100 == 0 || i == RSA_n_tuples - 1) {
              cout << "Verified " << (i + 1) << " signatures\r" << flush;
          }
       }
      cout << "\n\nMPC total verification time per server: " << (verify_start.elapsed() * 1e3) << " ms, throughput " << RSA_n_tuples /verify_start.elapsed()<< ", average single verification time: "<<(verify_start.elapsed() * 1e3)/RSA_n_tuples <<" ms" << endl;
//        cout << "Verifications per second: " << (n_tuples / seconds) << endl;

      EVP_PKEY_free(pkey);
      ERR_free_strings();
  }
  catch (const exception& e) {
      cerr << "Test failed with error: " << e.what() << endl;
      exit(1);
  }
  catch (...) {
      cerr << "Test failed with unknown error" << endl;
      exit(1);
  }

}
void test_aes_gcm_performance() {
    try {
        int message_size = 64; //512, 4096
        int num_messages = 15000;
        cout << "=== Testing AES-256-GCM Performance with " << num_messages
             << " messages of size " << message_size << " bytes ===" << endl;

        ERR_load_crypto_strings();

        // Generate AES key
        vector<unsigned char> key = generate_aes_key();

        // Vectors to store generated data
        vector<vector<unsigned char>> plaintext_messages;
        vector<EncryptionResult> encrypted_messages;

        // Generate test messages and encrypt them
        cout << "\nGenerating and encrypting messages for testing..." << endl;
        Timer encryption_timer;
        encryption_timer.start();

        for (int i = 0; i < num_messages; i++) {
            // Generate random message
            vector<unsigned char> message = generate_random_message(message_size);
            plaintext_messages.push_back(message);

            // Generate IV and encrypt message
            vector<unsigned char> iv = generate_iv();
            encrypted_messages.push_back(aes_gcm_encrypt(key, iv, message));

            if ((i + 1) % 100 == 0 || i == num_messages - 1) {
                cout << "Encrypted " << (i + 1) << " messages\r" << flush;
            }
        }

        cout << "\nEncryption completed. Starting decryption..." << endl;

        // Test decryption performance
        Timer decryption_timer;
        decryption_timer.start();

        for (int i = 0; i < num_messages; i++) {
            vector<unsigned char> decrypted = aes_gcm_decrypt(
                key,
                encrypted_messages[i].iv,
                encrypted_messages[i].ciphertext,
                encrypted_messages[i].tag
            );

            // Verify decryption correctness
            if (decrypted != plaintext_messages[i]) {
                cerr << "Decryption verification failed for message " << i << endl;
                ERR_free_strings();
                exit(1);
            }

            if ((i + 1) % 100 == 0 || i == num_messages - 1) {
                cout << "Decrypted " << (i + 1) << " messages\r" << flush;
            }
        }

        // Calculate and display performance metrics
        double encryption_time_ms = encryption_timer.elapsed() * 1e3;
        double decryption_time_ms = decryption_timer.elapsed() * 1e3;
        double encryption_throughput = num_messages / encryption_timer.elapsed();
        double decryption_throughput = num_messages / decryption_timer.elapsed();
        double avg_encryption_time = encryption_time_ms / num_messages;
        double avg_decryption_time = decryption_time_ms / num_messages;
        //
        cout << "\n\nPerformance Results for " << message_size << " byte messages:" << endl;
        cout << "DSO Encryption: " << endl;
        cout << "  Total time: " << encryption_time_ms << " ms" << endl;
        cout << "  Throughput: " << encryption_throughput << " messages/sec" << endl;
        cout << "  Average time per message: " << avg_encryption_time << " ms" << endl;

        cout << "\nMPC per Server Decryption: " << endl;
        cout << "  Total time: " << decryption_time_ms << " ms" << endl;
        cout << "  Throughput: " << decryption_throughput << " messages/sec" << endl;
        cout << "  Average time per message: " << avg_decryption_time << " ms" << endl;

        // Clean up
        ERR_free_strings();
    }
    catch (const exception& e) {
        cerr << "Test failed with error: " << e.what() << endl;
        ERR_free_strings();
        exit(1);
    }
    catch (...) {
        cerr << "Test failed with unknown error" << endl;
        ERR_free_strings();
        exit(1);
    }
}


template<template<class U> class T>
void run(int argc, const char** argv)
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Test small messages 
    test_aes_gcm_performance();
    cout << "\n\n";

    // Clean up OpenSSL
    EVP_cleanup();

    RSA_test();
    bigint::init_thread();
    ez::ezOptionParser opt;
//    EcdsaOptions opts(opt, argc, argv);
//    opts.R_after_msg |= is_same<T<P256Element>, AtlasShare<P256Element>>::value;
    Names N(opt, argc, argv,
            3 + is_same<T<P256Element>, Rep4Share<P256Element>>::value);
    int n_tuples = 15000; // test the average time of n tuples
    if (not opt.lastArgs.empty())
        n_tuples = atoi(opt.lastArgs[0]->c_str());
    cout << "\n\n=== Testing Schnorr Identification Protocol with " << n_tuples << " tuples ===" << endl;
    CryptoPlayer P(N, "ecdsa");

    P256Element::init();
    typedef T<P256Element::Scalar> pShare;
    typedef T<P256Element> cShare;

    OnlineOptions::singleton.batch_size = 1;
    // synchronize
    Bundle<octetStream> bundle(P);
    P.unchecked_broadcast(bundle);

    typename pShare::mac_key_type mac_key;
    pShare::read_or_generate_mac_key("", P, mac_key);

    ProtocolSet<typename T<P256Element::Scalar>::Honest> set(P, mac_key);
//    pShare sk = set.protocol.get_random();

    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * n_tuples;
    DataPositions usage;
    typename pShare::TriplePrep prep(0, usage);
    typename pShare::MAC_Check MCp(mac_key);
    ArithmeticProcessor _({}, 0);
    SubProcessor<pShare> proc(_, MCp, prep, P);
    typename cShare::Direct_MC MCc(MCp.get_alphai());

    double total_keys_gen_time = 0.0;
    double total_Ra_gen_time = 0.0;
    double total_s_gen_time = 0.0;
//    double total_share_gen_time  = 0.0 ;

    vector<P256Element::Scalar> s,d,k,e;
    vector<P256Element> Ra, Pk;
    cout << "\nGenerating proofs of identification..." << endl;
    for (int i = 0; i < n_tuples; ++i) {
        Timer timer;
        timer.start();

        // private key generation
        d.push_back(Ra[0].rand());
//        cout << "Private key is: " << d << endl;

        // public key generation
        Pk.push_back(d[i]);
//        cout << "Public key is: " << Pk[0] << endl;
//        cout << "Keys Generation in: " << timer.elapsed() * 1e3 << " ms" << endl;
        total_keys_gen_time += timer.elapsed();

        Timer timer2;
        timer2.start();
        // secret random number generation
        k.push_back(Ra[0].rand());
//        cout << "Secret random number is: " << k << endl;

        // generate the commitment
        Ra.push_back(k[i]);
//        cout << "Commitment is: " << Ra << endl;
//        cout << "Random key geberation for one session: " << timer2.elapsed() * 1e3 << " ms" << endl;
        total_Ra_gen_time += timer2.elapsed();

        // e selected by verifier
        e.push_back(Ra[0].rand());
//        cout << "Challenge selected by verifier for Schnorr: " << e << endl;

        Timer timer3;
        timer3.start();
        // s computed by prover
        s.push_back((k[i] + e[i] * d[i]));
        total_s_gen_time += timer3.elapsed();
    }
    cout << "Average Keys generation time: " <<  (total_keys_gen_time * 1e3) / n_tuples << " ms" <<endl; // To be donce once in the setup
    cout << "Average Commitment generation time: " <<  (total_Ra_gen_time * 1e3) / n_tuples << " ms" <<endl; // by users for every session
    cout << "Average Responce generation time: " <<  (total_s_gen_time * 1e3) / n_tuples << " ms" << endl; // by users

    vector<pShare> s_share(n_tuples);
    vector<pShare> d_share(n_tuples);
    vector<pShare> k_share(n_tuples);
    vector<pShare> e_share(n_tuples);
    vector<cShare> R_share(n_tuples);
    vector<cShare> Pk_share(n_tuples);
    vector<cShare> Pk2_share(n_tuples);

    auto stats = P.total_comm();
    cout << "\nSending shares..." << endl;
    // Party zero share all clients data for Schnorr just for testing
    auto& input = set.input;
    input.reset_all(P);
    input.add_from_all(s[0]);
    input.add_from_all(d[0]);
    input.add_from_all(k[0]);
    input.add_from_all(e[0]);
    input.exchange();
    s_share[0] = input.finalize(1);
    d_share[0] = input.finalize(1);
    k_share[0] = input.finalize(1);
    e_share[0] = input.finalize(1);

    (P.total_comm() - stats).print(true);

    Pk_share[0] = d_share[0];
    R_share[0] = k_share[0];
    e[0] = MCp.open(e_share[0],P);

    input.reset_all(P);
    for (int i = 1; i < n_tuples; ++i) {
      input.add_from_all(s[i]);
      input.add_from_all(d[i]);
      input.add_from_all(k[i]);
      input.add_from_all(e[i]); //just to have fixed output in the other parties, for testing
    }
    input.exchange();
    for (int i = 1; i < n_tuples; ++i) {
      s_share[i] = input.finalize(1);
      d_share[i] = input.finalize(1);
      k_share[i] = input.finalize(1);
      e_share[i] = input.finalize(1);
      Pk_share[i] = d_share[i];
      R_share[i] = k_share[i];
      e[i] = MCp.open(e_share[i],P); //just to have fixed output in the other parties, for testing
    }

    cout << "\nPerforming verification tests..." << endl;
    schnorr_verify<T>(n_tuples, s_share, Pk_share, R_share, e , proc);

    P256Element::finish();

}
