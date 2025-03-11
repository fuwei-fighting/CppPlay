//
// Created by fuwei on 25-3-7.
//
#include "kyss_tpm2.h"

#include "tests/tests_tpm2.h"

int main(int argc, char* argv[]) {
    //    test_tpm2_app_init();
    //    test_tpm2_create_sub_key();
    test_tpm2_encrypt_decrypt();

    //    test_esys_rsa();

    return TPM2_RC_SUCCESS;
}
