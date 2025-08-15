#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "esp_system.h"
#include "esp_random.h"
#include "oqs/oqs.h"
#include "oqs/rand.h"

// ---- RNG bridge: use ESP32 hardware RNG for liboqs ----
static void esp_randombytes(uint8_t *out, size_t out_len) {
    // esp_fill_random is available in ESP-IDF; it pulls from HWRNG.
    esp_fill_random(out, out_len);
}

void KEM_evaluation(const char *kem_alg, int trial_count) {
    clock_t start_time, end_time;

    double trial_kem_keygen_time;
    double trial_kem_encaps_time;
    double trial_kem_decaps_time;

    double kem_keygen_times[trial_count];
    double kem_encaps_times[trial_count];
    double kem_decaps_times[trial_count];

    double average_kem_keygen_time = 0.0;
    double average_kem_encaps_time = 0.0;
    double average_kem_decaps_time = 0.0;

    double stddeviation_kem_keygen_time = 0.0;
    double stddeviation_kem_encaps_time = 0.0;
    double stddeviation_kem_decaps_time = 0.0;

    printf("Evaluating KEM: %s with %d trials\n", kem_alg, trial_count);

    OQS_KEM *kem = OQS_KEM_new(kem_alg);
        if (kem == NULL) {
            printf("Failed to init KEM %s\n", kem_alg);
            return;
        }

        uint8_t *kem_pk = malloc(kem->length_public_key);
        uint8_t *kem_sk = malloc(kem->length_secret_key);
        uint8_t *kem_ct = malloc(kem->length_ciphertext);
        uint8_t *ss_enc  = malloc(kem->length_shared_secret);
        uint8_t *ss_dec  = malloc(kem->length_shared_secret);

        if (!kem_pk || !kem_sk || !kem_ct || !ss_enc || !ss_dec) {
            printf("Malloc failed\n");
            OQS_KEM_free(kem);
            return;
        }

    for (int current_trial = 0; current_trial < trial_count; current_trial++) {
        
        start_time = clock();
        if (OQS_KEM_keypair(kem, kem_pk, kem_sk) != OQS_SUCCESS) {
            printf("KEM keypair failed\n");
            break;
        }
        end_time = clock();
        trial_kem_keygen_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        kem_keygen_times[current_trial] = trial_kem_keygen_time;
        average_kem_keygen_time += trial_kem_keygen_time;

        start_time = clock();
        if (OQS_KEM_encaps(kem, kem_ct, ss_enc, kem_pk) != OQS_SUCCESS) {
            printf("KEM encaps failed\n");
            break;
        }
        end_time = clock();
        trial_kem_encaps_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        kem_encaps_times[current_trial] = trial_kem_encaps_time;
        average_kem_encaps_time += trial_kem_encaps_time;

        start_time = clock();
        if (OQS_KEM_decaps(kem, ss_dec, kem_ct, kem_sk) != OQS_SUCCESS) {
            printf("KEM decaps failed\n");
            break;
        }
        end_time = clock();
        trial_kem_decaps_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        kem_decaps_times[current_trial] = trial_kem_decaps_time;
        average_kem_decaps_time += trial_kem_decaps_time;

        // if (memcmp(ss_enc, ss_dec, kem->length_shared_secret) != 0) {
        //     printf("KEM shared secret mismatch during trial number %d\n", trial_count+1);
        //     break;
        // }
        // printf("Trial %d:\n", current_trial + 1);
    }

    average_kem_keygen_time /= trial_count;
    average_kem_encaps_time /= trial_count;
    average_kem_decaps_time /= trial_count;

    for (int i = 0; i < trial_count; i++) {
        stddeviation_kem_keygen_time += pow(kem_keygen_times[i] - average_kem_keygen_time, 2);
        stddeviation_kem_encaps_time += pow(kem_encaps_times[i] - average_kem_encaps_time, 2);
        stddeviation_kem_decaps_time += pow(kem_decaps_times[i] - average_kem_decaps_time, 2);
    }

    stddeviation_kem_keygen_time = sqrt(stddeviation_kem_keygen_time / trial_count);
    stddeviation_kem_encaps_time = sqrt(stddeviation_kem_encaps_time / trial_count);
    stddeviation_kem_decaps_time = sqrt(stddeviation_kem_decaps_time / trial_count);

    printf("KEM %s evaluation results:\n", kem_alg);
    printf("  Average key generation time: %.6f seconds             Standard deviation for key generation time: %.6f seconds\n", average_kem_keygen_time, stddeviation_kem_keygen_time);
    printf("  Average encapsulation time: %.6f seconds              Standard deviation for encapsulation time: %.6f seconds\n", average_kem_encaps_time, stddeviation_kem_encaps_time);
    printf("  Average decapsulation time: %.6f seconds              Standard deviation for decapsulation time: %.6f seconds\n", average_kem_decaps_time, stddeviation_kem_decaps_time);

    
    // cleanup
    OQS_KEM_free(kem);
    free(kem_pk); free(kem_sk); free(kem_ct); free(ss_enc); free(ss_dec);

}

void SIG_evaluation(const char *sig_alg, int trial_count) {
    clock_t start_time, end_time;

    double trial_sig_keygen_time;
    double trial_sig_sign_time;
    double trial_sig_verify_time;

    double sig_keygen_times[trial_count];
    double sig_sign_times[trial_count];
    double sig_verify_times[trial_count];

    double average_sig_keygen_time = 0.0;
    double average_sig_sign_time = 0.0;
    double average_sig_verify_time = 0.0;

    double stddeviation_sig_keygen_time = 0.0;
    double stddeviation_sig_sign_time = 0.0;
    double stddeviation_sig_verify_time = 0.0;

    printf("Evaluating SIG: %s with %d trials\n", sig_alg, trial_count);

    OQS_SIG *sig = OQS_SIG_new(sig_alg);
    if (sig == NULL) {
        printf("Failed to init SIG %s\n", sig_alg);
        return;
    }

    uint8_t *sig_pk = malloc(sig->length_public_key);
    uint8_t *sig_sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    if (!sig_pk || !sig_sk || !signature) {
        printf("Malloc failed\n");
        OQS_SIG_free(sig);
        return;
    }

    for (int current_trial = 0; current_trial < trial_count; current_trial++) {
        
        start_time = clock();
        if (OQS_SIG_keypair(sig, sig_pk, sig_sk) != OQS_SUCCESS) {
            printf("SIG keypair failed\n");
            break;
        }
        end_time = clock();
        trial_sig_keygen_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        sig_keygen_times[current_trial] = trial_sig_keygen_time;
        average_sig_keygen_time += trial_sig_keygen_time;

        const uint8_t message[] = "hello from ESP32 x liboqs";
        size_t msg_len = sizeof(message) - 1;

        size_t sig_len = 0;

        start_time = clock();
        if (OQS_SIG_sign(sig, signature, &sig_len, message, msg_len, sig_sk) != OQS_SUCCESS) {
            printf("SIG sign failed\n");
            break;
        }
        end_time = clock();
        trial_sig_sign_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        sig_sign_times[current_trial] = trial_sig_sign_time;
        average_sig_sign_time += trial_sig_sign_time;

        start_time = clock();
        OQS_STATUS v = OQS_SIG_verify(sig, message, msg_len, signature, sig_len, sig_pk);
        end_time = clock();
        trial_sig_verify_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        sig_verify_times[current_trial] = trial_sig_verify_time;
        average_sig_verify_time += trial_sig_verify_time;
    }

    average_sig_keygen_time /= trial_count;
    average_sig_sign_time /= trial_count;
    average_sig_verify_time /= trial_count;

    for (int i = 0; i < trial_count; i++) {
        stddeviation_sig_keygen_time += pow(sig_keygen_times[i] - average_sig_keygen_time, 2);
        stddeviation_sig_sign_time += pow(sig_sign_times[i] - average_sig_sign_time, 2);
        stddeviation_sig_verify_time += pow(sig_verify_times[i] - average_sig_verify_time, 2);
    }

    stddeviation_sig_keygen_time = sqrt(stddeviation_sig_keygen_time / trial_count);
    stddeviation_sig_sign_time = sqrt(stddeviation_sig_sign_time / trial_count);
    stddeviation_sig_verify_time = sqrt(stddeviation_sig_verify_time / trial_count);

    printf("SIG %s evaluation results:\n", sig_alg);
    printf("  Average key generation time: %.6f seconds              Standard deviation for key generation time: %.6f seconds\n", average_sig_keygen_time, stddeviation_sig_keygen_time);
    printf("  Average sign time: %.6f seconds                        Standard deviation for sign time: %.6f seconds\n", average_sig_sign_time, stddeviation_sig_sign_time);
    printf("  Average verify time: %.6f seconds                      Standard deviation for verify time: %.6f seconds\n", average_sig_verify_time, stddeviation_sig_verify_time);

    
    // cleanup
    OQS_SIG_free(sig);
    free(sig_pk); free(sig_sk); free(signature);
}



void app_main(void) {
    int trial_count = 1000;

    // printf("liboqs version: %s\n", OQS_VERSION_TEXT);

    // printf("Enabled KEMs:\n");
    // for (size_t i = 0; i < OQS_KEM_alg_count(); i++) {
    //     const char *id = OQS_KEM_alg_identifier(i);
    //     printf("  %s  (enabled=%d)\n", id, OQS_KEM_alg_is_enabled(id));
    // }

    // printf("Enabled SIGs:\n");
    // for (size_t i = 0; i < OQS_SIG_alg_count(); i++) {
    //     const char *id = OQS_SIG_alg_identifier(i);
    //     printf("  %s  (enabled=%d)\n", id, OQS_SIG_alg_is_enabled(id));
    // }
    
    printf("liboqs on ESP32 demo (ML-KEM + ML-DSA)\n");

    // 1) Seed/liboqs RNG
    // Use the "custom" RNG route so everything pulls from ESP32 HWRNG.
    OQS_randombytes_custom_algorithm(esp_randombytes);

    // =======================
    // 2) ML-KEM (Kyber) demo
    // =======================

    KEM_evaluation(OQS_KEM_alg_kyber_512, trial_count);
    KEM_evaluation(OQS_KEM_alg_kyber_768, trial_count);
    KEM_evaluation(OQS_KEM_alg_kyber_1024, trial_count);
    KEM_evaluation(OQS_KEM_alg_ml_kem_512, trial_count);
    KEM_evaluation(OQS_KEM_alg_ml_kem_768, trial_count);
    KEM_evaluation(OQS_KEM_alg_ml_kem_1024, trial_count);
    KEM_evaluation(OQS_KEM_alg_ntruprime_sntrup761, trial_count);

    
    // =======================
    // 3) ML-DSA (Dilithium) demo
    // =======================
    SIG_evaluation(OQS_SIG_alg_dilithium_2, trial_count);
    SIG_evaluation(OQS_SIG_alg_dilithium_3, trial_count);
    SIG_evaluation(OQS_SIG_alg_dilithium_5, trial_count);
    SIG_evaluation(OQS_SIG_alg_falcon_512, trial_count);
    SIG_evaluation(OQS_SIG_alg_falcon_1024, trial_count);

    printf("Done.\n");
}
