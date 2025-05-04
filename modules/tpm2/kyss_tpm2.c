//
// Created by fuwei on 25-3-7.
//
#include <assert.h>
#include "kyss_tpm2.h"

#define DEFAULT_PCRS (0b000000000000000000010101)
#define DEFAULT_BANKS (0b11)

#define TPM2TOTP_BANK_SHA1 (1 << 0)
#define TPM2TOTP_BANK_SHA256 (1 << 1)
#define TPM2TOTP_BANK_SHA384 (1 << 2)

#define TPM2B_PUBLIC_PRIMARY_TEMPLATE                               \
    {                                                               \
        .size = 0,                                                  \
        .publicArea = {                                             \
            .type = TPM2_ALG_ECC,                                   \
            .nameAlg = TPM2_ALG_SHA256,                             \
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |         \
                                 TPMA_OBJECT_RESTRICTED |           \
                                 TPMA_OBJECT_DECRYPT |              \
                                 TPMA_OBJECT_NODA |                 \
                                 TPMA_OBJECT_FIXEDTPM |             \
                                 TPMA_OBJECT_FIXEDPARENT |          \
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),  \
            .authPolicy = {                                         \
                .size = 0,                                          \
            },                                                      \
            .parameters.eccDetail = {                               \
                .symmetric = {                                      \
                    .algorithm = TPM2_ALG_AES,                      \
                    .keyBits.aes = 128,                             \
                    .mode.aes = TPM2_ALG_CFB,                       \
                },                                                  \
                .scheme = {.scheme = TPM2_ALG_NULL, .details = {}}, \
                .curveID = TPM2_ECC_NIST_P256,                      \
                .kdf = {.scheme = TPM2_ALG_NULL, .details = {}},    \
            },                                                      \
            .unique.ecc = {.x.size = 0, .y.size = 0}                \
        }                                                           \
    }

#define TPM2B_SENSITIVE_CREATE_TEMPLATE {.size = 0,                                  \
                                         .sensitive = {                              \
                                             .userAuth = {.size = 0, .buffer = {0}}, \
                                             .data = {.size = 0, .buffer = {0}},     \
                                         }};

static const TPM2B_PUBLIC rsa_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,  // 计算key自身摘要，防止key被非法替换
        .objectAttributes =
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_DECRYPT |
            TPMA_OBJECT_SIGN_ENCRYPT,
        .authPolicy = {
            .size = 0,  // 授权信息
        },
        .parameters.rsaDetail = {
            // 使用的算法参数
            .symmetric = {
                .algorithm = TPM2_ALG_NULL,
            },
            .scheme = {.scheme = TPM2_ALG_NULL},
            .keyBits = 2048,
            .exponent = 0,
        },
        .unique.rsa = {
            // 非对称密钥的公钥部分 && 其他密钥key自身的摘要
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

static const TPM2B_PUBLIC hmac_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_KEYEDHASH,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_SIGN_ENCRYPT),
        .authPolicy = {
            .size = 0,
            .buffer = {0}},
        .parameters.keyedHashDetail.scheme = {.scheme = TPM2_ALG_HMAC, .details = {.hmac = {.hashAlg = TPM2_ALG_SHA1}}},
        .unique.keyedHash = {
            .size = 0,
            .buffer = {0},
        },
    }};

TPM2B_DATA allOutsideInfo = {
    .size = 0,
};
TPML_PCR_SELECTION allCreationPCR = {.count = 0};

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

CK_RS kyss_tpm_encrypt_rsa(tpm_ctx* tcx, uint32_t handle, const char* password, const char* ctext, unsigned int ctextlen,
                           char* ptext, unsigned int* ptextlen) {
    LOGV("Performing TPM RSA encrypt");

    CK_RS rv = CKR_GENERAL_ERROR;

    bool result = set_esys_auth(tcx->esys_ctx, handle, password);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_PUBLIC_KEY_RSA cipher_text = {.size = ctextlen};
    if (ctextlen > sizeof(cipher_text.buffer)) {
        return CKR_ARGUMENTS_BAD;
    }
    memcpy(cipher_text.buffer, ctext, ctextlen);

    TPMT_RSA_DECRYPT in_scheme = {.scheme = TPM2_ALG_RSAES};  // 解密方案
    TPM2B_PUBLIC_KEY_RSA* decrypted_text = NULL;              // 解密后的明文

    /***** 加密数据  encrypt ****/
    rv = Esys_RSA_Encrypt(tcx->esys_ctx,
                          handle,
                          ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher_text,
                          &in_scheme,
                          NULL,  // label
                          &decrypted_text);
    if (rv != TSS2_RC_SUCCESS) {
        LOGE("Esys_RSA_Encrypt: %s", Tss2_RC_Decode(rv));
        tpm_flushcontext(tcx, handle);
        return CKR_GENERAL_ERROR;
    }

    *ptextlen = decrypted_text->size;
    memcpy(ptext, decrypted_text->buffer, decrypted_text->size);

    rv = CKR_OK;

    printf("rsa key encryped: indata = %.*s, outData = %.*s\n", cipher_text.size, cipher_text.buffer, *ptextlen, ptext);
    free(decrypted_text);
    return rv;
}

CK_RS kyss_tpm_decrypt_rsa(tpm_ctx* tcx, uint32_t handle, const char* password, const char* ptext, unsigned int ptextlen,
                           char* ctext, unsigned int* ctextlen) {
    LOGV("Performing TPM RSA Decrypt");

    CK_RS rv = CKR_GENERAL_ERROR;

    ESYS_TR keyHandle = handle;

    bool result = set_esys_auth(tcx->esys_ctx, keyHandle, password);
    if (!result) {
        return CKR_GENERAL_ERROR;
    }

    TPM2B_PUBLIC_KEY_RSA decrypted_text = {.size = ptextlen};
    if (ptextlen > sizeof(decrypted_text.buffer)) {
        return CKR_ARGUMENTS_BAD;
    }
    memcpy(decrypted_text.buffer, ptext, ptextlen);

    TPMT_RSA_DECRYPT in_scheme = {.scheme = TPM2_ALG_RSAES};  // 解密方案
    TPM2B_PUBLIC_KEY_RSA* encrypted_text = NULL;

    rv = Esys_RSA_Decrypt(tcx->esys_ctx,
                          handle,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &decrypted_text,
                          &in_scheme,
                          NULL,
                          &encrypted_text);
    if (rv != TSS2_RC_SUCCESS) {
        LOGE("Esys_RSA_Decrypt: %s", Tss2_RC_Decode(rv));
        tpm_flushcontext(tcx, handle);
        return CKR_GENERAL_ERROR;
    }

    *ctextlen = encrypted_text->size;
    memcpy(ctext, encrypted_text->buffer, encrypted_text->size);

    printf("rsa key decryped: indata = %.*s, outData = %.*s\n", decrypted_text.size, decrypted_text.buffer, *ctextlen, ctext);
    return CKR_OK;
}

CK_RS kyss_tpm_app_init(tpm_ctx* t_ctx, TPMI_DH_PERSISTENT evict_handle, const char* password) {
    TSS2_RC rc;
    TPM2B_SENSITIVE_CREATE inSensitive = {// 敏感数据
                                          .size = 1,
                                          .sensitive = {
                                              .userAuth = {// 存储密码，用于password授权
                                                           .size = 0,
                                                           .buffer = {0}},
                                          }};

    /* TODO use proper template ? */
    // https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_Platform_TPM_Profile_PTP_2.0_r1.03_v22.pdf
    TPM2B_PUBLIC inPub_rsa = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {.algorithm = TPM2_ALG_NULL},
                .scheme = {.scheme = TPM2_ALG_RSAES},
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {},
            },
        },
    };

    TPM2B_PUBLIC pub_template = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,  // 计算key自身的摘要
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

CK_RS kyss_tpm_generate_key_by_password(tpm_ctx* tcx,
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
    *out_handle = loadedKeyHandle;

    return TSS2_RC_SUCCESS;
}

CK_RS kyss_tpm_generate_primary_by_policy_pcr(tpm_ctx* tcx,
                                              TPM2B_PUBLIC** out_pub,
                                              TPM2B_PRIVATE** out_priv) {
    CK_RS rc = CKR_GENERAL_ERROR;
    ESYS_TR primary_handle;
    TPM2B_PUBLIC primaryPublic = TPM2B_PUBLIC_PRIMARY_TEMPLATE;
    TPM2B_SENSITIVE_CREATE primarySensitive = TPM2B_SENSITIVE_CREATE_TEMPLATE;
#if 0
    TPML_PCR_SELECTION *pcrcheck, pcrsel = {.count = 0};
    uint32_t pcrs = DEFAULT_PCRS;
    uint32_t banks = DEFAULT_BANKS;

    if ((banks & TPM2TOTP_BANK_SHA1)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA1;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA256)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA256;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA384)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA384;
        pcrsel.count++;
    }

    for (size_t i = 0; i < pcrsel.count; i++) {
        pcrsel.pcrSelections[i].sizeofSelect = 3;
        pcrsel.pcrSelections[i].pcrSelect[0] = pcrs & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[1] = pcrs >> 8 & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[2] = pcrs >> 16 & 0xff;
    }

    size_t secret_size = 0;
    uint8_t* secret;
    TPM2B_DIGEST* tDigest;
    secret = malloc(20);
    if (!secret) {
        LOGE("secret create failed.");
        return -1;
    }
    while (secret_size < 20) {
        rc = Esys_GetRandom(tcx->esys_ctx,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            20 - secret_size, &tDigest);
        if (rc != TSS2_RC_SUCCESS) {
            LOGE("Error Esys_GetRandom:%s", Tss2_RC_Decode(rc));
            return rc;
        }

        memcpy(&(secret)[secret_size], &tDigest->buffer[0], tDigest->size);
        secret_size += tDigest->size;
        free(tDigest);
    }
        rc = Esys_PCR_Read(tcx->esys_ctx,
                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       &pcrsel, NULL, &pcrcheck, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error esys load:%s", Tss2_RC_Decode(rc));
        return rc;
    }
    if (pcrcheck->count == 0) {
        LOGE("No active banks selected", Tss2_RC_Decode(rc));
        return -1;
    }
#endif
    rc = Esys_CreatePrimary(tcx->esys_ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &primarySensitive, &primaryPublic,
                            &allOutsideInfo, &allCreationPCR,
                            &primary_handle, NULL, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_CreatePrimary: %s:", Tss2_RC_Decode(rc));
        return CKR_GENERAL_ERROR;
    }

    ESYS_TR session;
    TPMT_SYM_DEF sym = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}};

    rc = Esys_StartAuthSession(tcx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                               &session);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error Esys_StartAuthSession:%s", Tss2_RC_Decode(rc));
        return rc;
    }

    TPML_PCR_SELECTION creation_pcr = {
        .count = 1,
        .pcrSelections = {
            {
                .hash = TPM2_ALG_SHA256,
                .sizeofSelect = 3,
                .pcrSelect = {ESYS_TR_PCR7, ESYS_TR_PCR0, ESYS_TR_PCR0}  // 选择 PCR 0-7
            }}};

    rc = Esys_PolicyPCR(tcx->esys_ctx, session,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &creation_pcr);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error Esys_PolicyPCR:%s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        return rc;
    }
    TPM2B_DIGEST* policyDigest = NULL;
    rc = Esys_PolicyGetDigest(tcx->esys_ctx, session,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &policyDigest);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error Esys_PolicyGetDigest:%s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        return rc;
    }

    TPM2B_PUBLIC keyInPublicHmac = rsa_template;
    TPM2B_SENSITIVE_CREATE keySensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {.size = 0, .buffer = {0}},
            .data = {.size = 0, .buffer = {0}},
        }};
    keyInPublicHmac.publicArea.authPolicy = *policyDigest;

    //    keySensitive.sensitive.data.size = creation_pcr.count;
    //    memcpy(&keySensitive.sensitive.data.buffer, creation_pcr.pcrSelections->pcrSelect, creation_pcr.count);

    rc = Esys_Create(tcx->esys_ctx,
                     primary_handle,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &keySensitive,
                     &keyInPublicHmac,
                     NULL,
                     &creation_pcr,
                     out_priv, out_pub,
                     NULL,
                     NULL,
                     NULL);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_Create: %s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        tpm_flushcontext(tcx, primary_handle);
        return rc;
    }

    ESYS_TR loadHandlePub;

    //    rc = Esys_LoadExternal(tcx->esys_ctx, ESYS_TR_NONE,
    //                           ESYS_TR_NONE,
    //                           ESYS_TR_NONE,
    //                           NULL, *out_pub, TPM2_RH_OWNER, &loadHandlePub);
    //    if (rc != TPM2_RC_SUCCESS) {
    //        LOGE("Esys_LoadExternal: %s", Tss2_RC_Decode(rc));
    //        Esys_FlushContext(tcx->esys_ctx, session);
    //        tpm_flushcontext(tcx, primary_handle);
    //        return rc;
    //    }

    rc = tpm_load_handle(tcx, primary_handle, *out_pub, *out_priv, &loadHandlePub);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("tpm_load_handle: %s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        tpm_flushcontext(tcx, primary_handle);
        return rc;
    }

    const char* ctext = "password 1234 Q!@#$%";
    TPM2B_PUBLIC_KEY_RSA cipher_text = {.size = strlen(ctext)};
    memcpy(cipher_text.buffer, ctext, strlen(ctext));
    TPMT_RSA_DECRYPT in_scheme = {.scheme = TPM2_ALG_RSAES};  // 解密方案
    TPM2B_PUBLIC_KEY_RSA* encrypted_text = NULL;              // 解密后的明文

    /***** 加密数据  encrypt ****/
    rc = Esys_RSA_Encrypt(tcx->esys_ctx,
                          loadHandlePub,
                          ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher_text,
                          &in_scheme,
                          NULL,  // label
                          &encrypted_text);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_RSA_Encrypt: %s", Tss2_RC_Decode(rc));
        tpm_flushcontext(tcx, loadHandlePub);
        return CKR_GENERAL_ERROR;
    }

    ESYS_TR loadHandlePri;

    rc = Esys_LoadExternal(tcx->esys_ctx, ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           NULL, *out_pub, TPM2_RH_OWNER, &loadHandlePri);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_LoadExternal: %s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        tpm_flushcontext(tcx, primary_handle);
        return rc;
    }

    //    rc = tpm_load_handle(tcx, primary_handle, *out_pub, *out_priv, &loadHandlePri);
    //    if (rc != TPM2_RC_SUCCESS) {
    //        LOGE("tpm_load_handle: %s", Tss2_RC_Decode(rc));
    //        Esys_FlushContext(tcx->esys_ctx, session);
    //        tpm_flushcontext(tcx, primary_handle);
    //        return rc;
    //    }

    TPM2B_PUBLIC_KEY_RSA* decrypted_text = NULL;
    rc = Esys_RSA_Decrypt(tcx->esys_ctx,
                          loadHandlePri,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          encrypted_text,
                          &in_scheme,
                          NULL,
                          &decrypted_text);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Esys_RSA_Decrypt: %s", Tss2_RC_Decode(rc));
        tpm_flushcontext(tcx, loadHandlePri);
        return CKR_GENERAL_ERROR;
    }
    printf("rsa key decryped: indata = %.*s, outData = %.*s\n", encrypted_text->size, encrypted_text->buffer, decrypted_text->size, decrypted_text->buffer);

    Esys_FlushContext(tcx->esys_ctx, session);
    tpm_flushcontext(tcx, primary_handle);
    return TPM2_RC_SUCCESS;
}

CK_RS kyss_tpm_generate_key_by_primary(tpm_ctx* tcx,
                                       ESYS_TR primary_handle,
                                       TPM2B_PUBLIC** out_pub,
                                       TPM2B_PRIVATE** out_priv) {
    CK_RS rc = CKR_GENERAL_ERROR;

    TPM2B_PUBLIC in_pub = rsa_template;

    TPM2B_SENSITIVE_CREATE in_priv = {0};

    TPML_PCR_SELECTION primary_pcr = {
        .count = 1,
        .pcrSelections = {
            {
                .hash = TPM2_ALG_SHA256,
                .sizeofSelect = 3,
                .pcrSelect = {ESYS_TR_PCR7, ESYS_TR_PCR0, ESYS_TR_PCR0}  // 选择 PCR 0-7
            }}};

    TPMT_SYM_DEF sym = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}};

    ESYS_TR session;
    rc = Esys_StartAuthSession(tcx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                               &session);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error Esys_StartAuthSession:%s", Tss2_RC_Decode(rc));
        return rc;
    }
    TPM2B_DIGEST* policyDigest;
    rc = Esys_PolicyGetDigest(tcx->esys_ctx, session,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &policyDigest);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error Esys_PolicyGetDigest:%s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        return rc;
    }

    rc = Esys_PolicyPCR(tcx->esys_ctx, session,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &primary_pcr);
    if (rc != TSS2_RC_SUCCESS) {
        LOGE("Error Esys_PolicyPCR:%s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        return rc;
    }

    in_pub.publicArea.authPolicy = *policyDigest;
    free(policyDigest);

    TPML_PCR_SELECTION creation_pcr = {.count = 0};
    rc = Esys_Create(tcx->esys_ctx,
                     primary_handle,
                     session, ESYS_TR_NONE, ESYS_TR_NONE,
                     &in_priv,
                     &in_pub,
                     NULL,
                     &creation_pcr,
                     out_priv, out_pub,
                     NULL,
                     NULL,
                     NULL);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("Esys_Create: %s", Tss2_RC_Decode(rc));
        Esys_FlushContext(tcx->esys_ctx, session);
        tpm_flushcontext(tcx, primary_handle);
        return rc;
    }

    return TPM2_RC_SUCCESS;
}

CK_RS kyss_tpm_encrypt_rsa_pcr_policy(tpm_ctx* tcx, uint32_t handle, const char* ctext, unsigned int ctextlen,
                                      char* ptext, unsigned int* ptextlen) {
    LOGV("Performing TPM RSA encrypt");

    CK_RS rv = CKR_GENERAL_ERROR;
}

/**
 *
 * @param esys_context
 * @return
 * TODO: 1. 需要把加解密的流程拆开
 *       2. TPM2B_PUBLIC TPM2B_AUTH这几个结构体的作用，如何填？
 *       3.
 */
int test_esys_encrypt_decrypt_sym(ESYS_CONTEXT* esys_context) {
    /**
     * （1） 初始化和设置授权值
     */
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;    // 存储主密钥句柄
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;  // 需要加载的子密钥句柄
    int failure_return = EXIT_FAILURE;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}};

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0},
            },
            .data = {
                .size = 0,
                .buffer = {0},
            },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,  // 表明这是个RSA密钥
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
            .parameters.rsaDetail = {
                .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB},
                .scheme = {.scheme = TPM2_ALG_NULL},
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {},
            },
        },
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}};

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);  // 为 ESYS_TR_RH_OWNER 设置授权值 authValue，这是 TPM 的所有者授权值。
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error: TR_SetAuth:0x%x", r);
        goto error;
    }

    /**
     * （2）创建主密钥
     */
    TPM2B_PUBLIC* outPublic;
    TPM2B_CREATION_DATA* creationData;
    TPM2B_DIGEST* creationHash;
    TPMT_TK_CREATION* creationTicket;

    // 创建主密钥，输出primaryHandle
    r = Esys_CreatePrimary(esys_context,
                           ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR,
                           &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error: esys create primary:0x%x", r);
        goto error;
    }

    // 为ESYS_TR对象（primaryHandle）设置授权值，在需要授权操作的时候使用
    r = Esys_TR_SetAuth(esys_context, primaryHandle, &authValuePrimary);
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error: TR_SetAuth:0x%x", r);
        goto error;
    }

    /**
     * （3）创建子密钥
     */
    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}};

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 1,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0}},
            .data = {.size = 16, .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}}}};

    inSensitive2.sensitive.userAuth = authKey2;

    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT),

            .authPolicy = {
                .size = 0,
            },
            .parameters.symDetail = {.sym = {.algorithm = TPM2_ALG_AES,  // 表明这是个AES对称密钥
                                             .keyBits = {.aes = 128},
                                             .mode = {.aes = TPM2_ALG_CFB}}},
            .unique.sym = {.size = 0, .buffer = {}}}};

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR2 = {
        .count = 0,
    };

    TPM2B_PUBLIC* outPublic2;
    TPM2B_PRIVATE* outPrivate2;
    TPM2B_CREATION_DATA* creationData2;
    TPM2B_DIGEST* creationHash2;
    TPMT_TK_CREATION* creationTicket2;

    // Esys_Create 函数用于在 TPM 中创建一个新的对象（如密钥），并返回该对象的私有部分和公共部分。
    // 这个函数通常在主密钥下创建子密钥或其他对象。创建的对象在 TPM 内部是未加载的，即它们不在 TPM 的当前会话中可用，需要通过 Esys_Load 函数加载到 TPM 中才能使用。
    r = Esys_Create(esys_context,
                    primaryHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive2,
                    &inPublic2,
                    &outsideInfo2,
                    &creationPCR2,
                    &outPrivate2,
                    &outPublic2,
                    &creationData2, &creationHash2, &creationTicket2);
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error esys create:0x%x", r);
        goto error;
    }

    printf("AES key created.\n");

    /**
     * （4）加载子密钥
     */
    // Esys_Load 函数用于将之前创建的 TPM 对象加载到 TPM 中，使其在当前会话中可用。加载后的对象可以用于各种 TPM 操作，如加密、解密、签名等。
    r = Esys_Load(esys_context,
                  primaryHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error esys load:0x%x", r);
        goto error;
    }

    printf("AES key loaded.\n");

    // 为加载的子密钥设置授权值 authKey2
    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error esys TR_SetAuth:0x%x", r);
        goto error;
    }

    /**
     * （5）加密和解密数据
     */
    ESYS_TR keyHandle_handle = loadedKeyHandle;
    TPMI_YES_NO decrypt = TPM2_YES;          // 设置为 TPM2_YES，表示进行解密操作。
    TPMI_YES_NO encrypt = TPM2_NO;           // 设置为 TPM2_NO，表示不进行加密操作
    TPMI_ALG_SYM_MODE mode = TPM2_ALG_NULL;  //  设置为 TPM2_ALG_NULL，表示不使用特定的加密模式。

    TPM2B_DIGEST* randomBytes;
    r = Esys_GetRandom(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 16, &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOGE("GetRandom FAILED! Response Code : 0x%x", r);
        goto error;
    }

    // 初始化向量（IV），用于加密和解密操作。
    TPM2B_IV ivIn = {
        .size = 16,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}};
    // 输入数据，需要被加密或解密的数据。

    TPM2B_IV ivRandom = {.size = randomBytes->size};
    memcpy(ivRandom.buffer, randomBytes->buffer, randomBytes->size);

    TPM2B_MAX_BUFFER inData = {
        .size = 16,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}};
    const char* plaintext = "my message";
    inData.size = strlen(plaintext);
    memcpy(inData.buffer, plaintext, inData.size);
    // 输出数据和输出初始化向量，由 Esys_EncryptDecrypt 函数分配内存。
    TPM2B_MAX_BUFFER* outData;
    TPM2B_IV* ivOut;

    /***** 加密数据  encrypt ****/
    r = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        encrypt,
        mode,
        &ivRandom,
        &inData,
        &outData,
        &ivOut);

    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOGE("Command TPM2_EncryptDecrypt not supported by TPM.");
        failure_return = -1;
        goto error;
    }

    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error EncryptDecrypt:0x%x", r);
        goto error;
    }
    printf("rsa key encryped: indata = %.*s, outData = %.*s\n", inData.size, inData.buffer, outData->size, outData->buffer);
    TPM2B_MAX_BUFFER* outData2;
    TPM2B_IV* ivOut2;

    /******* 解密数据decrypt ********/
    r = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        decrypt,
        mode,
        &ivIn,
        outData,
        &outData2,
        &ivOut2);

    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOGE("Command TPM2_EncryptDecrypt not supported by TPM.");
        failure_return = -1;
        goto error;
    }

    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error EncryptDecrypt:0x%x", r);
        goto error;
    }

    /********* 验证解密的结果 *********/
    printf("rsa key decryped: indata = %.*s, outData = %.*s\n", outData->size, outData->buffer, outData2->size, outData2->buffer);
    if (outData2->size != inData.size ||
        memcmp(&outData2->buffer, &inData.buffer[0], outData2->size) != 0) {  // 这里是比较加解密的数据
        LOGE("Error: decrypted text not  equal to origin");
        goto error;
    }

    // clean
    r = Esys_FlushContext(esys_context, primaryHandle);
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error during FlushContext:0x%x", r);
        goto error;
    }

    primaryHandle = ESYS_TR_NONE;

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    if (r != TSS2_RC_SUCCESS) {
        LOGE("Error during FlushContext:0x%x", r);
        goto error;
    }

    return EXIT_SUCCESS;
error:
    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOGE("Cleanup primaryHandle failed.");
        }
    }

    if (loadedKeyHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loadedKeyHandle) != TSS2_RC_SUCCESS) {
            LOGE("Cleanup loadedKeyHandle failed.");
        }
    }
    return failure_return;
}
