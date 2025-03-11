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

/**
 * @brief 根据主密钥创建子密钥
 * @param tcx
 * @param parent
 * @param password
 * @param out_handle
 * @param out_pub
 * @param out_priv
 * @return
 */
CK_RS kyss_tpm_generate_key_from_primary(tpm_ctx* tcx,
                                         uint32_t parent,
                                         const char* password,
                                         ESYS_TR* out_handle,
                                         TPM2B_PUBLIC** out_pub,
                                         TPM2B_PRIVATE** out_priv);
/**
 * @brief 使用指定密钥进行rsa加密
 * @param tcx
 * @param handle
 * @param password
 * @param ctext
 * @param ctextlen
 * @param ptext
 * @param ptextlen
 * @return
 */
CK_RS kyss_tpm_encrypt_rsa(tpm_ctx* tcx, uint32_t handle, const char* password, const char* ctext, unsigned int ctextlen,
                           char* ptext, unsigned int* ptextlen);
/**
 * @brief 使用指定密钥进行rsa解密
 * @param tcx
 * @param handle
 * @param password
 * @param ctext
 * @param ctextlen
 * @param ptext
 * @param ptextlen
 * @return
 */
CK_RS kyss_tpm_decrypt_rsa(tpm_ctx* tcx, uint32_t handle, const char* password, const char* ptext, unsigned int ptextlen,
                           char* ctext, unsigned int* ctextlen);

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

///// @deprecated
static TPMI_DH_PERSISTENT get_or_create_handle(const char* app_name);
int test_esys_rsa_encrypt_decrypt(tpm_ctx* tcx);

#endif  //TPM2_KYSS_TPM2_H
