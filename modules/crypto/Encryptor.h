//
// Created by fuwei on 24-10-19.
//

#ifndef CRYPTO_ENCRYPTOR_H
#define CRYPTO_ENCRYPTOR_H

#include <string>

class Encryptor {
   public:
    static std::string encryptAES(const std::string& plainText, const std::string& key, const std::string& iv);
};

#endif  // CRYPTO_ENCRYPTOR_H
