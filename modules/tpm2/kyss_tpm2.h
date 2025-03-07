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

/* config env var for TCTI context */
#define TPM2_PKCS11_TCTI "TPM2_PKCS11_TCTI"

typedef unsigned long CK_RS;  // result

typedef struct tpm_ctx tpm_ctx;

CK_RS kyss_tpm_ctx_new(const char* config, tpm_ctx** tctx);
CK_RS kyss_tpm_ctx_new_fromtcti(void* tcti, tpm_ctx** tctx);

#endif  //TPM2_KYSS_TPM2_H
