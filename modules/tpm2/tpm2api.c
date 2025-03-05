//
// Created by fuwei on 25-3-4.
//

#include "esapi_config.h"
#include "esapi.h"

int init_tcti_context_demo(TSS2_TCTI_CONTEXT** tcti_context) {
    TSS2_RC rc;
    size_t tcti_size;
    TSS2_TCTI_CONTEXT* tcti_inner;  // TODO: tcti_context 和 esys_context有什么区别和联系？
    options_info opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port = PORT_DEFAULT,
    };
    tcti_inner = tcti_device_init(opts.device_file);
    if (tcti_inner == NULL) {
        LOG_ERROR("TPM Startup FAILED! Error tcti init");
        exit(1);
    }

    rc = tcti_proxy_initialize(NULL, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("tcti initialization FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    *tcti_context = calloc(1, tcti_size);
    if (tcti_inner == NULL) {
        LOG_ERROR("TPM Startup FAILED! Error tcti init");
        exit(1);
    }

    rc = tcti_proxy_initialize(*tcti_context, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("tcti initialization FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    return TSS2_RC_SUCCESS;
}

int test_encrypt_decrypt_esapi(ESYS_CONTEXT* esys_context) {
    /**
     * （1） 初始化和设置授权值
     */
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;    // 存储主密钥句柄
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;  // 需要加载的子密钥句柄
    int failure_return = EXIT_FAILURE;

    //    TPM2B_PUBLIC inPublic = {
    //        .size = 0,
    //        .publicArea = {
    //            .type = TPM2_ALG_RSA,  // 表明这是个RSA密钥
    //            .nameAlg = TPM2_ALG_SHA256,
    //            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
    //                                 TPMA_OBJECT_RESTRICTED |
    //                                 TPMA_OBJECT_DECRYPT |
    //                                 TPMA_OBJECT_FIXEDTPM |
    //                                 TPMA_OBJECT_FIXEDPARENT |
    //                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
    //            .authPolicy = {
    //                .size = 0,
    //            },
    //            .parameters.rsaDetail = {
    //                .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB},
    //                .scheme = {.scheme = TPM2_ALG_NULL},
    //                .keyBits = 2048,
    //                .exponent = 0,
    //            },
    //            .unique.rsa = {
    //                .size = 0,
    //                .buffer = {},
    //            },
    //        },
    //    };
    //
    //    TPM2B_AUTH authValuePrimary = {
    //        .size = 5,
    //        .buffer = {1, 2, 3, 4, 5}};
    //
    //    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
    //        .size = 4,
    //        .sensitive = {
    //            .userAuth = {
    //                .size = 0,
    //                .buffer = {0},
    //            },
    //            .data = {
    //                .size = 0,
    //                .buffer = {0},
    //            },
    //        },
    //    };
    //
    //    TPM2B_DATA outsideInfo = {
    //        .size = 0,
    //        .buffer = {},
    //    };
    //
    //    TPML_PCR_SELECTION creationPCR = {
    //        .count = 0,
    //    };
    //
    //    /**
    //        * （2）创建主密钥
    //        */
    //    TPM2B_PUBLIC* outPublic;
    //    TPM2B_CREATION_DATA* creationData;
    //    TPM2B_DIGEST* creationHash;
    //    TPMT_TK_CREATION* creationTicket;
    //
    //    // 创建主密钥，输出primaryHandle
    //    r = Esys_CreatePrimary(esys_context,
    //                           ESYS_TR_RH_OWNER,
    //                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
    //                           &inSensitivePrimary, &inPublic,
    //                           &outsideInfo, &creationPCR,
    //                           &primaryHandle,
    //                           &outPublic, &creationData, &creationHash,
    //                           &creationTicket);
    //    if (r != TSS2_RC_SUCCESS) {
    //        LOG_ERROR("Error: esys create primary:0x%x", r);
    //        goto error;
    //    }
    TPM2B_PRIVATE inPrivate = {0};  // 私钥部分
    TPM2B_PUBLIC inPublic = {0};    // 公钥部分

    r = load_persistent_key(esys_context, 0x81010020, &inPrivate, &inPublic);
    if (r != TSS2_RC_SUCCESS) {
        fprintf(stderr, "load_persistent_key failed with code 0x%x\n", r);
        Esys_Finalize(&esys_context);
        return -1;
    }

    // 加载密钥
    r = Esys_Load(esys_context,
                  ESYS_TR_RH_OWNER,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  &inPrivate,
                  &inPublic,
                  &primaryHandle);
    if (r != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_Load failed with code 0x%x\n", r);
        Esys_Finalize(&esys_context);
        return -1;
    }

    printf("Key loaded successfully.\n");

    /**
     * （3）创建子密钥
     */
    TPM2B_AUTH passwordAuth = {};

    const char* password = "qwer1234!@#$";
    passwordAuth.size = strlen(password);
    memcpy(passwordAuth.buffer, password, passwordAuth.size);

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 1,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0}},
            .data = {.size = 16, .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}}}};

    inSensitive2.sensitive.userAuth = passwordAuth;

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
        LOG_ERROR("Error esys create:0x%x", r);
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
        LOG_ERROR("Error esys load:0x%x", r);
        goto error;
    }

    printf("AES key loaded.\n");

    // 为加载的子密钥设置授权值 authKey2
    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &passwordAuth);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error esys TR_SetAuth:0x%x", r);
        goto error;
    }

    /**
    * （5）加密和解密数据
    */
    ESYS_TR keyHandle_handle = loadedKeyHandle;
    TPMI_YES_NO decrypt = TPM2_YES;          // 设置为 TPM2_YES，表示进行解密操作。
    TPMI_YES_NO encrypt = TPM2_NO;           // 设置为 TPM2_NO，表示进行加密操作
    TPMI_ALG_SYM_MODE mode = TPM2_ALG_NULL;  //  设置为 TPM2_ALG_NULL，表示不使用特定的加密模式。
                                             // 初始化向量（IV），用于加密和解密操作。

    TPM2B_IV* ivInRandom = NULL;
    r = Esys_GetRandom(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 16, &ivInRandom);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error getRandom:0x%x", r)
        goto error;
    }

    //    TPM2B_IV ivIn = {};
    // 输入数据，需要被加密或解密的数据。
    TPM2B_MAX_BUFFER inData = {};
    // 输出数据和输出初始化向量，由 Esys_EncryptDecrypt 函数分配内存。
    TPM2B_MAX_BUFFER* outData;
    TPM2B_IV* ivOut;

    const char* plain_text = "hello this is message.!@#$4";
    inData.size = strlen(plain_text);
    memcpy(inData.buffer, plain_text, inData.size);

    /***** 加密数据  encrypt ****/
    r = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        encrypt,
        mode,
        ivInRandom,
        &inData,
        &outData,
        &ivOut);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error Encrypt:0x%x", r);
        goto error;
    }

    printf("aes key encryped: indata = %.*s, outData = %.*s\n", inData.size, inData.buffer, outData->size, outData->buffer);

    // 解密数据
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
        ivInRandom,
        outData,
        &outData2,
        &ivOut2);

    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error Decrypt:0x%x", r);
        goto error;
    }
    /********* 验证解密的结果 *********/
    //    LOGBLOB_DEBUG(&outData2->buffer[0], outData2->size, "** Decrypted data **");
    printf("Decrypted data: %.*s\n", outData2->size, outData2->buffer);

error:
    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.")
        }
    }

    if (loadedKeyHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loadedKeyHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup loadedKeyHandle failed.")
        }
    }
    return failure_return;
}

int load_persistent_key(ESYS_CONTEXT* esys_context, TPM2_HANDLE handler, TPM2B_PRIVATE* inPrivate, TPM2B_PUBLIC* inPublic) {
    TSS2_RC rc;
    // 获取公钥部分
    ESYS_TR esyHandler;
    rc = Esys_TR_FromTPMPublic(esys_context, handler, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &esyHandler);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_TR_FromTPMPublic failed with code 0x%x\n", rc);
        Esys_Finalize(&esys_context);
        return -1;
    }

    rc = Esys_ReadPublic(esys_context,
                         esyHandler,  // 持久句柄
                         ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                         &inPublic,
                         NULL,
                         NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_ReadPublic failed with code 0x%x\n", rc);
        Esys_Finalize(&esys_context);
        return -1;
    }

    // 获取私钥部分
    rc = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            TPM2_CAP_PCRS, 0, 1, NULL, &inPrivate);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_GetCapability failed with code 0x%x\n", rc);
        Esys_Finalize(&esys_context);
        return -1;
    }

    printf("Key loaded successfully.\n");
    return TSS2_RC_SUCCESS;
}
