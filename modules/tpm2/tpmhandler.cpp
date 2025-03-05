//
// Created by fuwei on 25-1-13.
//

#include "tpmhandler.h"
#include <tss2/tss2_esys.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <stdlib.h>
#include <string.h>
#include "dbg.h"

void check_rc(TSS2_RC rc, const std::string& msg) {
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << msg << " failed: 0x" << std::hex << rc << std::endl;
        throw std::runtime_error(msg);
    }
}

void TpmHandler::testInitContextAndCreatePrimaryKey() {
    TSS2_RC rc;
    ESYS_CONTEXT* ctx = nullptr;

    // 初始化 ESAPI 上下文
    rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "ESAPI initialization failed: 0x" << std::hex << rc << std::endl;
        return;
    }

    //    std::cout << "ESAPI initialized successfully!" << std::endl;
    dbg("ESAPI initialized successfully!");

    // 创建主密钥
    ESYS_TR primaryHandle;
    TPM2B_PUBLIC* outPublic = nullptr;
    TPM2B_CREATION_DATA* creationData = nullptr;
    TPM2B_DIGEST* creationHash = nullptr;
    TPMT_TK_CREATION* creationTicket = nullptr;

    TPM2B_SENSITIVE_CREATE inSensitive = {};
    inSensitive.size = 0;  // 不需要敏感数据

    TPM2B_PUBLIC inPublic = {};
    inPublic.publicArea.type = TPM2_ALG_RSA;        // 使用 RSA 算法
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;  // 使用 SHA-256 哈希算法
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
                                           TPMA_OBJECT_FIXEDPARENT |
                                           TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                           TPMA_OBJECT_USERWITHAUTH |
                                           TPMA_OBJECT_DECRYPT;                    // 允许解密操作
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;  // 不使用对称加密
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;        // 不使用特殊方案
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;                       // RSA 密钥长度为 2048 位
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;                         // 默认指数
    inPublic.publicArea.unique.rsa.size = 0;                                       // 唯一标识符为空

    TPM2B_DATA outsideInfo = {};
    outsideInfo.size = 0;

    TPML_PCR_SELECTION creationPCR = {};
    creationPCR.count = 0;

    rc = Esys_CreatePrimary(
        ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive, &inPublic, &outsideInfo, &creationPCR,
        &primaryHandle, &outPublic, &creationData, &creationHash, &creationTicket);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "CreatePrimary failed: 0x" << std::hex << rc << std::endl;
        Esys_Finalize(&ctx);
        return;
    }

    //    std::cout << "Primary key created successfully!" << std::endl;
    dbg("Primary key created successfully!");

    // 清理
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Finalize(&ctx);
}

void TpmHandler::testEncryptDecrypt() {
    TSS2_RC rc;
    ESYS_CONTEXT* ctx = NULL;

    // 初始化 ESAPI 上下文
    rc = Esys_Initialize(&ctx, NULL, NULL);
    check_rc(rc, "ESAPI initialization");

    // 1. 创建主密钥
    ESYS_TR primaryHandle;
    TPM2B_PUBLIC* outPublic = NULL;
    TPM2B_CREATION_DATA* creationData = NULL;
    TPM2B_DIGEST* creationHash = NULL;
    TPMT_TK_CREATION* creationTicket = NULL;

    TPM2B_SENSITIVE_CREATE inSensitive = {};
    inSensitive.size = 0;

    TPM2B_PUBLIC inPublic = {};
    inPublic.publicArea.type = TPM2_ALG_RSA;        // 使用 RSA 算法
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;  // 使用 SHA-256 哈希算法
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
                                           TPMA_OBJECT_FIXEDPARENT |
                                           TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                           TPMA_OBJECT_USERWITHAUTH |
                                           TPMA_OBJECT_DECRYPT;                    // 允许解密操作
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;  // 不使用对称加密
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;        // 不使用特殊方案
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;                       // RSA 密钥长度为 2048 位
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;                         // 默认指数
    inPublic.publicArea.unique.rsa.size = 0;                                       // 唯一标识符为空

    rc = Esys_CreatePrimary(
        ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive, &inPublic, NULL, NULL,
        &primaryHandle, &outPublic, &creationData, &creationHash, &creationTicket);
    check_rc(rc, "CreatePrimary");

    printf("Primary key created successfully!\n");

    // 2. 创建子密钥
    TPM2B_PUBLIC* outPublicKey = NULL;
    TPM2B_PRIVATE* outPrivateKey = NULL;
    TPM2B_PUBLIC inPublicKey = {};
    inPublicKey.publicArea = outPublic->publicArea;  // 使用主密钥的公共参数

    rc = Esys_Create(
        ctx, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive, &inPublicKey, NULL, NULL,
        &outPrivateKey, &outPublicKey, NULL, NULL, NULL);
    check_rc(rc, "Create");

    printf("Sub key created successfully!\n");

    // 3. 加载子密钥
    ESYS_TR keyHandle;
    TPM2B_NAME* keyName = NULL;
    TPM2B_NAME* qualifiedName = NULL;

    rc = Esys_Load(
        ctx, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        outPrivateKey, outPublicKey, &keyHandle);
    check_rc(rc, "Load");

    printf("Sub key loaded successfully!\n");

    // 4. 加密数据
    TPM2B_PUBLIC_KEY_RSA message = {};
    TPM2B_PUBLIC_KEY_RSA* ciphertext = {};

    const char* plaintext = "my message";
    message.size = strlen(plaintext);
    memcpy(message.buffer, plaintext, message.size);

    rc = Esys_RSA_Encrypt(
        ctx, keyHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &message, NULL, NULL, &ciphertext);
    check_rc(rc, "RSA_Encrypt");

    printf("Data encrypted successfully!\n");

    // 5. 解密数据
    TPM2B_PUBLIC_KEY_RSA* decrypted = {};

    rc = Esys_RSA_Decrypt(
        ctx, keyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        ciphertext, NULL, NULL, &decrypted);
    check_rc(rc, "RSA_Decrypt");

    printf("Decrypted data: %.*s\n", decrypted->size, decrypted->buffer);

    // 6. 清理上下文
    rc = Esys_FlushContext(ctx, keyHandle);
    check_rc(rc, "FlushContext (keyHandle)");

    rc = Esys_FlushContext(ctx, primaryHandle);
    check_rc(rc, "FlushContext (primaryHandle)");

    printf("Contexts flushed successfully!\n");

    // 清理资源
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(outPrivateKey);
    Esys_Free(outPublicKey);
    Esys_Free(keyName);
    Esys_Free(qualifiedName);

    // 清理 ESAPI 上下文
    Esys_Finalize(&ctx);
}
