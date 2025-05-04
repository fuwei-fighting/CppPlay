//
// Created by fuwei on 25-3-18.
//

#ifndef TPM2_KYSS_COMMON_H
#define TPM2_KYSS_COMMON_H

#include "pkcs.h"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <string.h>
#include <stdbool.h>

/* config env var for TCTI context */
#define TPM2_PKCS11_TCTI "TPM2_PKCS11_TCTI"

/* The PCR index used to seal/unseal the passphrase */
#define CRYPTFS_TPM2_PCR_INDEX 7

#define DEFAULT_PCRS (0b000000000000000000010101)

#define TPM2B_INIT(xsize) \
    { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

static inline UINT16 tpm2_error_get(TSS2_RC rc) {
    return ((rc & TPM2_ERROR_TSS2_RC_ERROR_MASK));
}

typedef unsigned long CK_RS;  // result

typedef struct tpm_ctx tpm_ctx;

struct tpm_ctx {
    TSS2_TCTI_CONTEXT* tcti_ctx;
    ESYS_CONTEXT* esys_ctx;

    ESYS_TR h_session;
};

struct tpm_op_data {
    tpm_ctx* ctx;

    //    tobject* tobj;

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

///// @static_function

/**
 * @brief 开启tpm会话
 * @param ctx
 * @param auth
 * @param handle
 * @return
 */
CK_RS tpm_session_start(tpm_ctx* ctx, const char* auth, uint32_t handle);

/**
 * @brief 关闭tpm会话
 * @param ctx
 * @return
 */
CK_RS tpm_session_stop(tpm_ctx* ctx);

/**
 * @brief 关闭指定tpm handle
 * @param ctx
 * @param handle
 * @return
 */
bool tpm_flushcontext(tpm_ctx* ctx, uint32_t handle);

/**
 * @brief 设置授权值（输入密码）
 * @param esys_ctx
 * @param handle
 * @param auth
 * @return
 */
bool set_esys_auth(ESYS_CONTEXT* esys_ctx, ESYS_TR handle, const char* auth);

CK_RS tpm_load_handle(tpm_ctx* ctx,
                      uint32_t primary,
                      TPM2B_PUBLIC* in_pub,
                      TPM2B_PRIVATE* in_priv,
                      ESYS_TR* outHandle);

#endif  //TPM2_KYSS_COMMON_H
