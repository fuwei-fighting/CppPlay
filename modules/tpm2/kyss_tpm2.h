//
// Created by fuwei on 25-3-7.
//

#ifndef TPM2_KYSS_TPM2_H
#define TPM2_KYSS_TPM2_H

#include "log.h"

#include "kyss_common.h"

#define DEFAULT_SRK_HANDLE 0x81010020

/**
 * @description: init tpm context (from tcti context)
 * @param config
 * @param tctx
 */
CK_RS kyss_tpm_ctx_new(const char* config, tpm_ctx** tctx);
CK_RS kyss_tpm_ctx_new_fromtcti(void* tcti, tpm_ctx** tctx);

/**
 * @brief tpm根据软件进行初始化，创建系统级全局主密钥。
 * @param evict_handle
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
 * @brief 通过密码授权创建子密钥
 * @param tcx
 * @param parent 主密钥handle
 * @param password
 * @param out_handle
 * @param out_pub
 * @param out_priv
 * @return
 */
CK_RS kyss_tpm_generate_key_by_password(tpm_ctx* tcx,
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
 * @brief 根据pcr policy创建主密钥
 * @param tcx
 * @param primary_handle
 * @return
 */
CK_RS kyss_tpm_generate_primary_by_policy_pcr(tpm_ctx* tcx,
                                              TPM2B_PUBLIC** out_pub,
                                              TPM2B_PRIVATE** out_priv);

CK_RS kyss_tpm_encrypt_rsa_pcr_policy(tpm_ctx* tcx, uint32_t handle, const char* ctext, unsigned int ctextlen,
                                      char* ptext, unsigned int* ptextlen);

CK_RS kyss_tpm_generate_key_by_primary(tpm_ctx* tcx,
                                       ESYS_TR primary_handle,
                                       TPM2B_PUBLIC** out_pub,
                                       TPM2B_PRIVATE** out_priv);

/**
 * @brief 根据tpm上下文创建子密钥，保存在指定目录
 * @param tcx: tpm上下文
 * @param path: 密钥文件保存路径
 * @param out_pub: 生成的公钥部分
 * @param out_priv: 生成的私钥部分
 * @return
 */
CK_RS kyss_tpm_generate_key(tpm_ctx** tcx,
                            const char* path,
                            TPM2B_PUBLIC** out_pub,
                            TPM2B_PRIVATE** out_priv);

int test_esys_encrypt_decrypt_sym(ESYS_CONTEXT* esys_context);
#endif  //TPM2_KYSS_TPM2_H
