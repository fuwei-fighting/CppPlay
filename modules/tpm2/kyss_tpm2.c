//
// Created by fuwei on 25-3-7.
//
#include "kyss_tpm2.h"

struct tpm_ctx {
    TSS2_TCTI_CONTEXT* tcti_ctx;
    ESYS_CONTEXT* esys_ctx;
};

CK_RS kyss_tpm_ctx_new(const char* config, tpm_ctx** tctx) {
    TSS2_TCTI_CONTEXT* tcti_context = NULL;

    /* no specific config, try environment */
    if (!config) {
        config = getenv(TPM2_PKCS11_TCTI);
    }
    LOGV("tcti=%s", config ? config : "(null)");

    TSS2_RC rc = Tss2_TctiLdr_Initialize(config, &tcti_context);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Tss2_TctiLdr_Initialize error.");
        return CKR_GENERAL_ERROR;
    }
    return kyss_tpm_ctx_new_fromtcti(tcti_context, tctx);
}

CK_RS kyss_tpm_ctx_new_fromtcti(void* tcti_context, tpm_ctx** tctx) {
    ESYS_CONTEXT* esys_context = NULL;

    tpm_ctx* t_context = calloc(1, sizeof(*t_context));
    if (!t_context) {
        return CKR_HOST_MEMORY;
    }
    TSS2_RC rval = Esys_Initialize(&esys_context, tcti_context, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOGE("Esys_InitializeL 0x%x", rval);
        goto error;
    }
    t_context->esys_ctx = esys_context;
    t_context->tcti_ctx = tcti_context;

    /* assign back (return via pointer) */
    *tctx = t_context;

    return CKR_OK;

error:
    free(t_context);
    return CKR_GENERAL_ERROR;
}