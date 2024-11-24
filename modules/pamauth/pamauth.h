//
// Created by fuwei on 24-11-24.
//

#ifndef PAMAUTH_PAMAUTH_H
#define PAMAUTH_PAMAUTH_H

#include <pwd.h>
#include <string>
#include <memory>

extern "C" {
#include <security/pam_appl.h>
#include <security/pam_misc.h>
}

class PamAuth {
   public:
    PamAuth();
    PamAuth(const std::string& serivceName, const std::string& userName, pam_conv conv);
    PamAuth(const std::string& serviceName, pam_conv conv);

    ~PamAuth();

   public:
    int authenticate();
    static int execute(const std::string& serviceName, const std::string& userName, const std::string& runAsUser);

   protected:
    uid_t m_puid;
    passwd* m_pwd = nullptr;

    std::string m_userName;
    pam_handle_t* m_pamHandle = nullptr;

    int m_status;
    bool m_isUser = false;  // allows the user to interact with the object for more funcationality
    bool m_isAuthorized = false;
    int m_authAttempts = 3;
};

#endif  //PAMAUTH_PAMAUTH_H
