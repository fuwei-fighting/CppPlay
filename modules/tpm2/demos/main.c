//
// Created by fuwei on 25-3-4.
//
#include "esapi_config.h"
#include "esapi.h"

#include <tss2/tss2_tctildr.h>

int main(int argc, char* argv[]) {
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT* tcti_context;
    ESYS_CONTEXT* esys_context;

    // 初始化TCTI上下文（可选）
    rc = Tss2_TctiLdr_Initialize(NULL, &tcti_context);  // 使用默认 TCTI
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_Initialize failed with code 0x%x\n", rc);
        Tss2_TctiLdr_Finalize(&tcti_context);
        return -1;
    }
    rc = Esys_Initialize(&esys_context, tcti_context, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    printf("ESYS context initialized successfully.\n");

    rc = Esys_Startup(esys_context, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        LOG_ERROR("Esys_Startup FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    int res = test_encrypt_decrypt_esapi(esys_context);
    //    int res = test_esys_encrypt_decrypt(esys_context)   ;
    if (res != EXIT_SUCCESS) {
        LOG_ERROR("Test esys encrypt failed.")
    }

    Esys_Finalize(&esys_context);
    tcti_teardown(tcti_context);
    return res;
}