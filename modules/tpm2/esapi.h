//
// Created by fuwei on 25-3-4.
//

#ifndef TPM2_ESAPI_H
#define TPM2_ESAPI_H

TSS2_TCTI_CONTEXT*
tcti_device_init(char const* device_path);

TSS2_TCTI_CONTEXT_PROXY*
tcti_proxy_cast(TSS2_TCTI_CONTEXT* ctx);

TSS2_RC
tcti_proxy_transmit(
    TSS2_TCTI_CONTEXT* tctiContext,
    size_t command_size,
    const uint8_t* command_buffer);

TSS2_RC
tcti_proxy_receive(
    TSS2_TCTI_CONTEXT* tctiContext,
    size_t* response_size,
    uint8_t* response_buffer,
    int32_t timeout);

void tcti_proxy_finalize(
    TSS2_TCTI_CONTEXT* tctiContext);

TSS2_RC
tcti_proxy_initialize(
    TSS2_TCTI_CONTEXT* tctiContext,
    size_t* contextSize,
    TSS2_TCTI_CONTEXT* tctiInner);

int test_invoke_esapi(ESYS_CONTEXT* esys_context);

int test_esys_get_random(ESYS_CONTEXT* esys_context);

int test_esys_nv_ram_ordinary_index(ESYS_CONTEXT* esys_context);

/**
 *
 * @param esys_context
 * @return
 * TODO: 1. 需要把加解密的流程拆开
 *       2. TPM2B_PUBLIC TPM2B_AUTH这几个结构体的作用，如何填？
 *       3.
 */
int test_esys_encrypt_decrypt(ESYS_CONTEXT* esys_context);

void tcti_teardown(TSS2_TCTI_CONTEXT* tcti_context);

/******************************************************************************/

int init_tcti_context_demo(TSS2_TCTI_CONTEXT** tcti_context);

int test_encrypt_decrypt_esapi(ESYS_CONTEXT* esys_context);

int load_persistent_key(ESYS_CONTEXT* esys_context, TPM2_HANDLE handler, TPM2B_PRIVATE* inPrivate, TPM2B_PUBLIC* inPublic);

#endif  //TPM2_ESAPI_H
