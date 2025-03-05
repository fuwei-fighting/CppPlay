//
// Created by fuwei on 25-1-13.
//

#ifndef TPM2_TPMHANDLER_H
#define TPM2_TPMHANDLER_H

class TpmHandler {
   public:
    //    static int testEsysEncryptDecrypt(ESYS_CONTEXT* esysContext);
    static void testInitContextAndCreatePrimaryKey();
    static void testEncryptDecrypt();
};

#endif  //TPM2_TPMHANDLER_H
