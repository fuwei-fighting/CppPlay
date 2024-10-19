//
// Created by fuwei on 24-10-19.
//
#include "Encryptor.h"
#include "Decryptor.h"
#include "dbg.h"

int main(int argc, char* argv[]) {
    {
        std::string key = "0123456789abcdef";  // 16 bytes key for AES-128
        std::string iv = "0123456789abcdef";   // 16 bytes IV for AES
        std::string plainText = "AES 128 test";

        std::string encrypted = Encryptor::encryptAES(plainText, key, iv);
        dbg(encrypted);

        std::string decrypted = Decryptor::decryptAES(encrypted, key);
        dbg(decrypted);
    }
    return 0;
}