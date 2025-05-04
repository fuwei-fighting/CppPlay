//
// Created by fuwei on 25-3-10.
//

#ifndef TPM2_TESTS_TPM2_H
#define TPM2_TESTS_TPM2_H



/**
 * @brief tpm根据软件进行初始化，创建系统级全局主密钥。
 * @return
 */
int test_tpm2_app_init();

/**
 * @brief tpm根据主密钥创建二级密钥
 * @return
 */
int test_tpm2_create_sub_key();

/**
 * @brief tpm使用密钥进行加密解密
 * @return
 */
int test_tpm2_encrypt_decrypt();

/**
 * @brief tpm使用policy创建密钥等操作
 * @return
 */
int test_tpm2_policy();

int test_tpm2_sym_endecrypt();



#endif //TPM2_TESTS_TPM2_H
