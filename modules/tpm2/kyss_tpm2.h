//
// Created by fuwei on 25-3-7.
//

#ifndef TPM2_KYSS_TPM2_H
#define TPM2_KYSS_TPM2_H

#include "log.h"
#include "pkcs.h"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <string.h>
#include <stdbool.h>

#define DEFAULT_SRK_HANDLE 0x81010020
/* config env var for TCTI context */
#define TPM2_PKCS11_TCTI "TPM2_PKCS11_TCTI"

/* The PCR index used to seal/unseal the passphrase */
#define CRYPTFS_TPM2_PCR_INDEX 7

typedef unsigned long CK_RS;  // result

typedef struct tpm_ctx tpm_ctx;

typedef struct tpm_op_data tpm_op_data;

typedef struct tobject tobject;

/**
 * @description: init tpm context (from tcti context)
 * @param config
 * @param tctx
 */
CK_RS kyss_tpm_ctx_new(const char* config, tpm_ctx** tctx);
CK_RS kyss_tpm_ctx_new_fromtcti(void* tcti, tpm_ctx** tctx);

/**
 * @brief tpm根据软件进行初始化，创建系统级全局主密钥。
 * @param app
 * @return
 */
CK_RS kyss_tpm_app_init(tpm_ctx* t_ctx, TPMI_DH_PERSISTENT evict_handle, const char* password);

/**
 * @brief 根据app获取当前的系统主密钥；
 * @param app
 * @return
 */
CK_RS kyss_tpm_get_app_primary(tpm_ctx* t_ctx, uint32_t default_handle, uint32_t* primary_handle, const char** primary_blob);

CK_RS kyss_tpm_generate_key_from_primary(tpm_ctx* tcx,
                                         uint32_t parent,
                                         const char* password,
                                         ESYS_TR* out_handle,
                                         TPM2B_PUBLIC** out_pub,
                                         TPM2B_PRIVATE** out_priv);

CK_RS kyss_tpm_encrypt_rsa(tpm_op_data* tpm_enc_data, CK_BYTE_PTR ctext, CK_ULONG ctextlen,
                           CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen);

CK_RS tpm_session_start(tpm_ctx* ctx, const char* auth, uint32_t handle);
CK_RS tpm_session_stop(tpm_ctx* ctx);

bool tpm_flushcontext(tpm_ctx* ctx, uint32_t handle);

static bool set_esys_auth(ESYS_CONTEXT* esys_ctx, ESYS_TR handle, const char* auth);

static TPMI_DH_PERSISTENT get_or_create_handle(const char* app_name);

#endif  //TPM2_KYSS_TPM2_H
