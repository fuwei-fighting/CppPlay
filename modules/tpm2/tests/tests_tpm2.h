//
// Created by fuwei on 25-3-10.
//

#ifndef TPM2_TESTS_TPM2_H
#define TPM2_TESTS_TPM2_H



/**
 * @brief tpm根据软件进行初始化，创建系统级全局主密钥。
 * @param app_name
 * @return
 */
int test_tpm2_app_init();


int test_tpm2_create_sub_key();

#endif //TPM2_TESTS_TPM2_H
