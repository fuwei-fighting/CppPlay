//
// Created by fuwei on 25-3-7.
//
#include <assert.h>
#include "kyss_tpm2.h"

#define TPM2B_INIT(xsize) \
    { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

static inline UINT16 tpm2_error_get(TSS2_RC rc) {
    return ((rc & TPM2_ERROR_TSS2_RC_ERROR_MASK));
}

struct tpm_ctx {
    TSS2_TCTI_CONTEXT* tcti_ctx;
    ESYS_CONTEXT* esys_ctx;

    ESYS_TR h_session;
};

struct tpm_op_data {
    tpm_ctx* ctx;

    tobject* tobj;

    CK_KEY_TYPE op_type;

    union {
        struct {
            TPMT_SIG_SCHEME sig;
            TPMT_RSA_DECRYPT raw;
            TPM2B_DATA label;
        } rsa;
        struct {
            TPMI_ALG_SYM_MODE mode;
            TPM2B_IV iv;
            //            struct {
            //                BIGNUM *counter;
            //            } ctr;
            struct {
                CK_ULONG len;
                CK_BYTE data[16];
            } prev;
        } sym;
        struct {
            TPMT_SIG_SCHEME sig;
        } ecc;
    };
};

struct tobject {
    uint32_t tpm_handle;

    const char* unsealed_auth;

    const char* pub;     /** public tpm data */
    const char* priv;    /** private tpm data */
    const char* objauth; /** wrapped object auth value */
};

static const TPM2B_PUBLIC rsa_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes =
            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT,
        .authPolicy = {
            .size = 0,
        },
        .parameters.rsaDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_NULL,
            },
            .scheme = {.scheme = TPM2_ALG_NULL},
            .keyBits = 2048,
            .exponent = 0,
        },
        .unique.rsa = {
            .size = 0,
        },
    },
};

static const TPM2B_PUBLIC ecc_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes =
            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT,
        .authPolicy = {
            .size = 0,
        },
        .parameters.eccDetail = {.symmetric = {
                                     .algorithm = TPM2_ALG_NULL,
                                     .keyBits.aes = 0,
                                     .mode.aes = 0,
                                 },
                                 .scheme = {.scheme = TPM2_ALG_NULL, .details = {
                                                                         // {.hashAlg = TPM2_ALG_SHA1}
                                                                     }},
                                 .curveID = TPM2_ECC_NIST_P256,
                                 .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}},
        .unique.ecc = {.x = {.size = 0, .buffer = {}}, .y = {.size = 0, .buffer = {}}},
    },
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
    printf("create tpm context from tcti success.\n");

    return CKR_OK;

error:
    free(t_context);
    return CKR_GENERAL_ERROR;
}

CK_RS kyss_tpm_encrypt_rsa(tpm_op_data* tpm_enc_data, CK_BYTE_PTR ctext, CK_ULONG ctextlen,
                           CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {
    LOGV("Performing TPM RSA Decrypt");

    CK_RS rv = CKR_GENERAL_ERROR;

    tpm_ctx* ctx = tpm_enc_data->ctx;
    TPMT_RSA_DECRYPT* scheme = &tpm_enc_data->rsa.raw;
    TPM2B_DATA* label = &tpm_enc_data->rsa.label;
    /*
 * Validate that the data to perform the operation on, typically
 * ciphertext on RSA decrypt, fits in the buffer for the TPM and
 * populate it.
 */
    TPM2B_PUBLIC_KEY_RSA tpm_ctext = {.size = ctextlen};
    if (ctextlen > sizeof(tpm_ctext.buffer)) {
        return CKR_ARGUMENTS_BAD;
    }
    memcpy(tpm_ctext.buffer, ctext, ctextlen);
    const char* auth = tpm_enc_data->tobj->unsealed_auth;
    ESYS_TR handle = tpm_enc_data->tobj->tpm_handle;
    bool result = set_esys_auth(ctx->esys_ctx, handle, auth);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_PUBLIC_KEY_RSA* tpm_ptext;
    TSS2_RC rc = Esys_RSA_Decrypt(
        ctx->esys_ctx,
        handle,
        ctx->h_session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &tpm_ctext,
        scheme,
        label,
        &tpm_ptext);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_RSA_Decrypt: %s", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }
    if (!ptext) {
        *ptextlen = tpm_ctext.size;
        rv = CKR_OK;
        goto out;
    }

    if (*ptextlen < tpm_ctext.size) {
        *ptextlen = tpm_ctext.size;
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    *ptextlen = tpm_ptext->size;
    memcpy(ptext, tpm_ptext->buffer, tpm_ptext->size);

    rv = CKR_OK;

out:
    free(tpm_ptext);

    return rv;
}

CK_RS kyss_tpm_app_init(tpm_ctx* t_ctx, TPMI_DH_PERSISTENT evict_handle, const char* password) {
    TSS2_RC rc;
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 1,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0}},
        }};

    /* TODO use proper template ? */
    // https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_Platform_TPM_Profile_PTP_2.0_r1.03_v22.pdf
    TPM2B_PUBLIC pub_template = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.eccDetail = {.symmetric = {
                                         .algorithm = TPM2_ALG_AES,
                                         .keyBits.aes = 128,
                                         .mode.aes = TPM2_ALG_CFB,
                                     },
                                     .scheme = {
                                         .scheme = TPM2_ALG_NULL,
                                     },
                                     .curveID = TPM2_ECC_NIST_P256,
                                     .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}},
            .unique.ecc = {
                .x = {.size = 0, .buffer = {}},
                .y = {.size = 0, .buffer = {}},
            },
        },
    };
    ESYS_TR hierarchy = ESYS_TR_RH_OWNER;

    TPM2B_AUTH hieararchy_auth = {0};
    hieararchy_auth.size = strlen(password);
    memcpy(hieararchy_auth.buffer, password, hieararchy_auth.size);
    inSensitive.sensitive.userAuth = hieararchy_auth;

    TPM2B_PUBLIC* outPublic = NULL;  // 公钥部分

    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION pcrs = {0};
    TPM2B_CREATION_DATA* data = NULL;
    TPM2B_DIGEST* hash = NULL;
    TPMT_TK_CREATION* ticket = NULL;

    ESYS_TR primary_handle = ESYS_TR_NONE;
    rc = Esys_CreatePrimary(t_ctx->esys_ctx,
                            hierarchy,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &inSensitive,
                            &pub_template,
                            &outside_info,  // 外部信息
                            &pcrs,          // PCR 选择
                            &primary_handle,
                            &outPublic,
                            &data,     // 创建数据
                            &hash,     // 创建哈希
                            &ticket);  // 创建票据
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_CreatePrimary: %s:", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    Esys_Free(data);
    Esys_Free(hash);
    Esys_Free(ticket);
    Esys_Free(outPublic);

    ESYS_TR new_handle = ESYS_TR_NONE;
    rc = Esys_EvictControl(t_ctx->esys_ctx,
                           hierarchy,
                           primary_handle,
                           ESYS_TR_PASSWORD,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           evict_handle,
                           &new_handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_EvictControl: %s:", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    //        rc = Esys_TR_SetAuth(t_ctx->esys_ctx, hierarchy, &hieararchy_auth);
    //        if (rc != TSS2_RC_SUCCESS) {
    //            LOGE("Esys_TR_SetAuth: %s:", Tss2_RC_Decode(rc));
    //            tpm_session_stop(t_ctx);
    //            return CKR_GENERAL_ERROR;
    //        }

    return CKR_OK;
}

CK_RS kyss_tpm_get_app_primary(tpm_ctx* t_ctx, uint32_t default_handle, uint32_t* primary_handle, const char** primary_blob) {
    ESYS_TR handle = ESYS_TR_NONE;
    TPMI_YES_NO more_data = TPM2_NO;
    TPMS_CAPABILITY_DATA* capdata = NULL;

    /* Check for the handle here to avoid causing TPM2_ReadPublic to fail loudly */
    TSS2_RC rval = Esys_GetCapability(
        t_ctx->esys_ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_HANDLES,
        TPM2_PERSISTENT_FIRST,
        TPM2_MAX_CAP_HANDLES,
        &more_data,
        &capdata);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_GetCapability: %s:", Tss2_RC_Decode(rval));
        return -1;
    }
    TPM2_HANDLE find_handle = default_handle;

    bool found = false;
    UINT32 i;
    TPM2_HANDLE* found_handles = capdata->data.handles.handle;
    for (i = 0; i < capdata->data.handles.count; i++) {
        if (find_handle == found_handles[i]) {
            found = true;
            break;
        }
    }

    Esys_Free(capdata);

    if (!found) {
        *primary_handle = 0;
        LOGE("No Provisioning Guide Spec Key Handle");
        return -1;
    }
    rval = Esys_TR_FromTPMPublic(
        t_ctx->esys_ctx,
        find_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_FromTPMPublic: %s:", Tss2_RC_Decode(rval));
        tpm_flushcontext(t_ctx, find_handle);
        return -1;
    }
    uint8_t* buffer = NULL;
    size_t size = 0;
    rval = Esys_TR_Serialize(t_ctx->esys_ctx,
                             handle,
                             &buffer, &size);
    if (rval != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_Serialize: %s:", Tss2_RC_Decode(rval));
        tpm_flushcontext(t_ctx, handle);
        return -1;
    }

    *primary_handle = handle;

    return TSS2_RC_SUCCESS;
}

CK_RS kyss_tpm_generate_key_from_primary(tpm_ctx* tcx,
                                         uint32_t parent,
                                         const char* password,
                                         ESYS_TR* out_handle,
                                         TPM2B_PUBLIC** out_pub,
                                         TPM2B_PRIVATE** out_priv) {
    CK_RS rc = CKR_GENERAL_ERROR;

    TPM2B_PUBLIC in_pub = rsa_template;

    TPM2B_SENSITIVE_CREATE in_priv = {0};
    TPM2B_AUTH passwordAuth = {};
    passwordAuth.size = strlen(password);
    memcpy(passwordAuth.buffer, password, passwordAuth.size);

    in_priv.sensitive.userAuth = passwordAuth;

    TPM2B_DATA outside_info = TPM2B_EMPTY_INIT;

    unsigned int pcr_index = CRYPTFS_TPM2_PCR_INDEX;
    TPML_PCR_SELECTION creation_pcr = {
        .count = 1,
        .pcrSelections = {
            {
                .hash = TPM2_ALG_SHA256,
                .sizeofSelect = 3,
                .pcrSelect = {ESYS_TR_PCR7, ESYS_TR_PCR0, ESYS_TR_PCR0}  // 选择 PCR 0-7
            }}};

    TPM2B_CREATION_DATA* creation_data = NULL;
    TPM2B_DIGEST* creation_hash = NULL;
    TPMT_TK_CREATION* creation_ticket = NULL;

    ESYS_TR parentHandle = parent;

    rc = Esys_Create(tcx->esys_ctx,
                     parentHandle,
                     tcx->h_session, ESYS_TR_NONE, ESYS_TR_NONE,
                     &in_priv,
                     &in_pub,
                     &outside_info,
                     &creation_pcr,
                     out_priv, out_pub,
                     &creation_data,
                     &creation_hash,
                     &creation_ticket);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_Create: %s", Tss2_RC_Decode(rc));
        tpm_session_stop(tcx);
        return rc;
    }

    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;  // 需要加载的子密钥句柄
    rc = Esys_Load(tcx->esys_ctx,
                   parent,
                   ESYS_TR_PASSWORD,
                   ESYS_TR_NONE,
                   ESYS_TR_NONE, *out_priv, *out_pub, &loadedKeyHandle);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error esys load:%s", Tss2_RC_Decode(rc));
        tpm_flushcontext(tcx, loadedKeyHandle);
        return rc;
    }

    rc = Esys_TR_SetAuth(tcx->esys_ctx, loadedKeyHandle, &passwordAuth);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_TR_SetAuth: %s:", Tss2_RC_Decode(rc));
        tpm_flushcontext(tcx, loadedKeyHandle);
        return CKR_GENERAL_ERROR;
    }

    *out_handle = loadedKeyHandle;

    return TSS2_RC_SUCCESS;
}

static bool set_esys_auth(ESYS_CONTEXT* esys_ctx, ESYS_TR handle, const char* auth) {
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

//////////////////////////////////////////  create app handle  //////////////////////////////////////////////////////
#define MAX_APPS 10

typedef struct {
    char app_name[64];
    TPMI_DH_PERSISTENT handle;
} AppHandleMap;

AppHandleMap app_map[MAX_APPS];
int app_count = 0;

TPMI_DH_PERSISTENT get_or_create_handle(const char* app_name) {
    for (int i = 0; i < app_count; i++) {
        if (strcmp(app_map[i].app_name, app_name) == 0) {
            return app_map[i].handle;
        }
    }

    if (app_count >= MAX_APPS) {
        fprintf(stderr, "Maximum number of applications reached\n");
        exit(1);
    }

    app_map[app_count].handle = DEFAULT_SRK_HANDLE + app_count;
    //    app_map[app_count].handle = DEFAULT_SRK_HANDLE;
    strncpy(app_map[app_count].app_name, app_name, sizeof(app_map[app_count].app_name) - 1);
    app_count++;
    return app_map[app_count - 1].handle;
}