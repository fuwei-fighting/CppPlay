//
// Created by fuwei on 25-3-7.
//
#include "kyss_tpm2.h"

#include <setjmp.h>
#include <cmocka.h>

int main(int argc, char* argv[]) {
    CK_RS rs = CKR_GENERAL_ERROR;
    tpm_ctx* tcti_context = NULL;
    rs = kyss_tpm_ctx_new(NULL, &tcti_context);
    assert_int_equal(rs, CKR_OK);

    return TPM2_RC_SUCCESS;
}
