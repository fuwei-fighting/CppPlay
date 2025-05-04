//
// Created by fuwei on 25-3-10.
//

#include "tests_tpm2.h"

#include "../kyss_tpm2.h"

#include <setjmp.h>
#include <cmocka.h>

int test_tpm2_app_init() {
    CK_RS rs = CKR_GENERAL_ERROR;
    tpm_ctx* t_ctx = NULL;
    rs = kyss_tpm_ctx_new(NULL, &t_ctx);
    assert_int_equal(rs, CKR_OK);

    rs = kyss_tpm_app_init(t_ctx, DEFAULT_SRK_HANDLE,"qwe123!@#");
    assert_int_equal(rs, CKR_OK);

    ESYS_TR primaryHandle = ESYS_TR_NONE;    // 存储主密钥句柄
    const char* primary_blob = NULL;
    rs = kyss_tpm_get_app_primary(t_ctx, DEFAULT_SRK_HANDLE,  &primaryHandle, &primary_blob);
    assert_int_equal(rs, CKR_OK);

    return 0;
}


int test_tpm2_create_sub_key() {
    CK_RS rs = CKR_GENERAL_ERROR;
    tpm_ctx* t_ctx = NULL;
    rs = kyss_tpm_ctx_new(NULL, &t_ctx);
    assert_int_equal(rs, CKR_OK);

    ESYS_TR primaryHandle = ESYS_TR_NONE;    // 存储主密钥句柄
    const char* primary_blob = NULL;
    rs = kyss_tpm_get_app_primary(t_ctx,DEFAULT_SRK_HANDLE, &primaryHandle, &primary_blob);
    assert_int_equal(rs, CKR_OK);

    rs = tpm_session_start(t_ctx, "qwe123!@#", primaryHandle);
    assert_int_equal(rs, CKR_OK);

    ESYS_TR out_handle;
    TPM2B_PUBLIC* out_pub;
    TPM2B_PRIVATE *out_priv;
    const char* password = "qwe123!@#";
    rs = kyss_tpm_generate_key_by_password(t_ctx, primaryHandle, password,
                                            &out_handle, &out_pub, &out_priv);

    assert_int_equal(rs, CKR_OK);

    tpm_flushcontext(t_ctx,out_handle);
    tpm_session_stop(t_ctx);

    return 0;
}

int test_tpm2_encrypt_decrypt() {
    CK_RS rs = CKR_GENERAL_ERROR;
    tpm_ctx* t_ctx = NULL;
    rs = kyss_tpm_ctx_new(NULL, &t_ctx);
    assert_int_equal(rs, CKR_OK);

    ESYS_TR primaryHandle = ESYS_TR_NONE;    // 存储主密钥句柄
    const char* primary_blob = NULL;
    rs = kyss_tpm_get_app_primary(t_ctx,DEFAULT_SRK_HANDLE, &primaryHandle, &primary_blob);
    assert_int_equal(rs, CKR_OK);

    rs = tpm_session_start(t_ctx, "qwe123!@#", primaryHandle);
    assert_int_equal(rs, CKR_OK);

    ESYS_TR out_handle;
    TPM2B_PUBLIC* out_pub;
    TPM2B_PRIVATE *out_priv;
    const char* password = "qwe123!@#";
    rs = kyss_tpm_generate_key_by_password(t_ctx, primaryHandle, password,
                                            &out_handle, &out_pub, &out_priv);

    assert_int_equal(rs, CKR_OK);
    const char* cipher_text = "hello this is message.!@#$4";
    char encrypt_msg[1024] = {0};
    unsigned int encrypt_len;
    rs = kyss_tpm_encrypt_rsa(t_ctx, out_handle, "qwe123!@#", cipher_text, strlen(cipher_text), encrypt_msg, &encrypt_len);
    assert_int_equal(rs, CKR_OK);

    char decrypt_msg[1024] = {0};
    unsigned int decrypt_len;
    rs = kyss_tpm_decrypt_rsa(t_ctx, out_handle, "qwe123!@#", encrypt_msg, encrypt_len, decrypt_msg, &decrypt_len);

    assert_int_equal(rs, CKR_OK);

    tpm_flushcontext(t_ctx,out_handle);
    tpm_session_stop(t_ctx);
    return 0;
}

int test_tpm2_policy() {
    CK_RS rs = CKR_GENERAL_ERROR;
    tpm_ctx* t_ctx = NULL;
    rs = kyss_tpm_ctx_new(NULL, &t_ctx);
    assert_int_equal(rs, CKR_OK);

    ESYS_TR primaryHandle = ESYS_TR_NONE;    // 存储主密钥句柄
    TPM2B_PUBLIC* out_pub;
    TPM2B_PRIVATE *out_priv;
    rs = kyss_tpm_generate_primary_by_policy_pcr(t_ctx, &out_pub, &out_priv);
    assert_int_equal(rs, CKR_OK);

//

//    rs = kyss_tpm_generate_key_by_primary(t_ctx, primaryHandle, &out_pub, &out_priv);
//    assert_int_equal(rs, CKR_OK);
//    const char* password = "qwe123!@#";
//    rs = kyss_tpm_generate_key_by_password(t_ctx, primaryHandle, password,
//                                           &out_handle, &out_pub, &out_priv);
//    assert_int_equal(rs, CKR_OK);
//
//    tpm_flushcontext(t_ctx,primaryHandle);

    return 0;
}

int test_tpm2_sym_endecrypt() {
    CK_RS rs = CKR_GENERAL_ERROR;
    tpm_ctx* t_ctx = NULL;
    rs = kyss_tpm_ctx_new(NULL, &t_ctx);
    assert_int_equal(rs, CKR_OK);

    rs = test_esys_encrypt_decrypt_sym(t_ctx->esys_ctx);
    assert_int_equal(rs, CKR_OK);

    return 0;
}