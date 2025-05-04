//
// Created by fuwei on 25-3-18.
//
#include "kyss_common.h"

#include "log.h"
#include <assert.h>

bool set_esys_auth(ESYS_CONTEXT* esys_ctx, ESYS_TR handle, const char* auth) {
    TPM2B_AUTH tpm_auth = TPM2B_EMPTY_INIT;

    if (auth) {
        size_t auth_len = strlen(auth);
        if (auth_len > sizeof(tpm_auth.buffer)) {
            LOGE("Auth value too large, got %zu expected < %zu",
                 auth_len, sizeof(tpm_auth.buffer));
            return false;
        }

        tpm_auth.size = auth_len;
        memcpy(tpm_auth.buffer, auth, auth_len);
    }

    TSS2_RC rval = Esys_TR_SetAuth(esys_ctx, handle, &tpm_auth);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_SetAuth: 0x%x:", rval);
        return false;
    }
    return true;
}

CK_RS tpm_session_start(tpm_ctx* ctx, const char* auth, uint32_t handle) {
    assert(!ctx->h_session);

    bool res = set_esys_auth(ctx->esys_ctx, handle, auth);
    if (!res) {
        return CKR_GENERAL_ERROR;
    }

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}};

    TPMA_SESSION session_attrs =
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT;

    ESYS_TR session = ESYS_TR_NONE;
    TSS2_RC rc = Esys_StartAuthSession(ctx->esys_ctx,
                                       handle,  //tpmkey
                                       handle,  //bind
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       NULL,
                                       TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                                       &session);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_StartAuthSession: %s", Tss2_RC_Decode(rc));
        Esys_FlushContext(ctx->esys_ctx, session);
        return CKR_GENERAL_ERROR;
    }

    //    rc = Esys_TRSess_SetAttributes(ctx->esys_ctx, session, session_attrs,
    //                                   0xff);
    //    if (rc != TSS2_RC_SUCCESS) {
    //        LOGE("Esys_TRSess_SetAttributes: %s", Tss2_RC_Decode(rc));
    //        rc = Esys_FlushContext(ctx->esys_ctx,
    //                               session);
    //        if (rc != TSS2_RC_SUCCESS) {
    //            LOGW("Esys_FlushContext: %s", Tss2_RC_Decode(rc));
    //        }
    //        return CKR_GENERAL_ERROR;
    //    }

    //    ctx->original_flags = session_attrs;

    ctx->h_session = session;

    return CKR_OK;
}

CK_RS tpm_session_stop(tpm_ctx* ctx) {
    TSS2_RC rc = Esys_FlushContext(ctx->esys_ctx,
                                   ctx->h_session);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_FlushContext: %s", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    ctx->h_session = 0;

    return CKR_OK;
}

bool tpm_flushcontext(tpm_ctx* ctx, uint32_t handle) {
    TSS2_RC rval = Esys_FlushContext(
        ctx->esys_ctx,
        handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_FlushContext: %s", Tss2_RC_Decode(rval));
        return false;
    }

    return true;
}

CK_RS tpm_load_handle(tpm_ctx* ctx,
                      uint32_t primary,
                      TPM2B_PUBLIC* in_pub,
                      TPM2B_PRIVATE* in_priv,
                      ESYS_TR* outHandle) {
    CK_RS rc = CKR_GENERAL_ERROR;

    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;  // 需要加载的子密钥句柄
    rc = Esys_Load(ctx->esys_ctx,
                   primary,
                   ESYS_TR_PASSWORD,
                   ESYS_TR_NONE,
                   ESYS_TR_NONE, in_priv, in_pub, &loadedKeyHandle);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error esys load:%s", Tss2_RC_Decode(rc));
        tpm_flushcontext(ctx, loadedKeyHandle);
        return rc;
    }

    *outHandle = loadedKeyHandle;

    return rc;
}