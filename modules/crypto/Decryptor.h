//
// Created by fuwei on 24-10-19.
//

#ifndef CRYPTO_DECRYPTOR_H
#define CRYPTO_DECRYPTOR_H

#include <string>

class Decryptor {
   public:
    static std::string decryptAES(const std::string& cipherText, const std::string& key);
};

#endif  //CRYPTO_DECRYPTOR_H
