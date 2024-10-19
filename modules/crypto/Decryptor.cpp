//
// Created by fuwei on 24-10-19.
//

#include "Decryptor.h"
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <iostream>
#include "dbg.h"

using namespace CryptoPP;

std::string Decryptor::decryptAES(const std::string& cipherText, const std::string& key) {
    std::string decryptedText;

    try {
        ECB_Mode<AES>::Decryption decryption;
        decryption.SetKey((const byte*)key.data(), key.size());

        StringSource ss(cipherText, true, new StreamTransformationFilter(decryption, new StringSink(decryptedText)));
    } catch (const CryptoPP::Exception& e) {
        dbg(e.what());
    }

    return decryptedText;
}
