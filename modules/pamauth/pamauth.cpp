//
// Created by fuwei on 24-11-24.
//

#include "pamauth.h"
#include <iostream>

struct pam_conv conv = {
    misc_conv,
    nullptr};

PamAuth::PamAuth() {
    m_puid = getuid();
    m_pwd = getpwuid(m_puid);
    char* user = strdup(m_pwd->pw_name);
    m_status = pam_start("check_user", user, &conv, &m_pamHandle);
    if (m_status == PAM_SUCCESS) {
        m_isUser = true;
    }
    delete (user);
    m_userName = std::string(m_pwd->pw_name);
}

PamAuth::PamAuth(const std::string& serivceName, const std::string& userName, pam_conv conv) {
    m_status = pam_start(serivceName.c_str(), userName.c_str(), &conv, &m_pamHandle);

    m_isUser = m_status == PAM_SUCCESS;
}

PamAuth::PamAuth(const std::string& serviceName, pam_conv conv) {
    m_puid = getuid();
    passwd* ppw = getpwuid(m_puid);
    m_userName = std::string(ppw->pw_name);
    if (!serviceName.empty()) {
        m_status = pam_start(serviceName.c_str(), ppw->pw_name, &conv, &m_pamHandle);
        m_isUser = m_status == PAM_SUCCESS;
    } else {
        m_status = 26;
    }
    free(ppw);
}

PamAuth::~PamAuth() {
    if (m_isAuthorized || m_isUser) {
        pam_end(m_pamHandle, 0);
    }
}

int PamAuth::authenticate() {
    if (m_isUser) {
        m_status = PAM_TRY_AGAIN;
        m_status = pam_authenticate(m_pamHandle, 0);
        if (m_status == PAM_SUCCESS) {
            return PAM_SUCCESS;
        }
        return PAM_TRY_AGAIN;
    }
}

int PamAuth::execute(const std::string& serviceName, const std::string& userName,
                     const std::string& runAsUser) {
    pam_handle_t* pamHandle = nullptr;
    uid_t uid = getuid();
    passwd* pwd = getpwuid(uid);
    int auth = -1;
    char* user = strdup(pwd->pw_name);

    if (pwd) {
        std::cout << pwd->pw_name << " enter your password: ";
        int retVal = pam_start(serviceName.c_str(), user, &conv, &pamHandle);
        std::cout << std::endl;
        if (retVal == PAM_SUCCESS) {
            auth = pam_authenticate(pamHandle, 0);
            if (auth != PAM_SUCCESS) {
                pam_end(pamHandle, auth);
                free(user);
                return 1;
            }
            pam_end(pamHandle, auth);
        }
    }
    free(user);
    return 0;
}