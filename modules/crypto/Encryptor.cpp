//
// Created by fuwei on 24-10-19.
//

#include "Encryptor.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include "dbg.h"

using namespace CryptoPP;

std::string Encryptor::encryptAES(const std::string& plainText, const std::string& key,
                                  const std::string& iv) {
    std::string cipherText;
    try {
        ECB_Mode<AES>::Encryption encryption;
        encryption.SetKey((const byte*)key.data(), key.size());

        StringSource ss(plainText, true, new StreamTransformationFilter(encryption, new StringSink(cipherText)));
    } catch (const CryptoPP::Exception& e) {
        dbg(e.what());
    }

    return cipherText;
}
