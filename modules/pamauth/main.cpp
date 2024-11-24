//
// Created by fuwei on 24-11-24.
//
#include <security/pam_appl.h>
#include "pamauth.h"

#include <iostream>

int main(int argc, char* argv[]) {
    PamAuth pamAuth;
    if (pamAuth.execute("filesafe", "fuwei", "") != PAM_SUCCESS) {
        std::cerr << "auth failed" << std::endl;

        return PAM_TRY_AGAIN;
    }
    return 0;
}