//! Unit Tests for MPAGSCipher Cipher Classes
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <string>
#include <vector>

#include "Cipher.hpp"
#include "CipherFactory.hpp"
#include "CipherMode.hpp"
#include "CipherType.hpp"
#include "Exceptions.hpp"

bool testCipher(const Cipher& cipher, const CipherMode mode,
                const std::string& inputText, const std::string& outputText)
{
    return cipher.applyCipher(inputText, mode) == outputText;
}

TEST_CASE("Cipher encryption/decryption", "[ciphers]")
{
    std::vector<std::unique_ptr<Cipher>> ciphers;
    std::vector<std::string> plainText;
    std::vector<std::string> cipherText;
    std::vector<std::string> decryptText;

    ciphers.push_back(cipherFactory(CipherType::Caesar, "10"));
    plainText.push_back("HELLOWORLD");
    cipherText.push_back("ROVVYGYBVN");
    decryptText.push_back("HELLOWORLD");

    ciphers.push_back(cipherFactory(CipherType::Playfair, "hello"));
    plainText.push_back("BOBISSOMESORTOFJUNIORCOMPLEXXENOPHONEONEZEROTHING");
    cipherText.push_back(
        "FHIQXLTLKLTLSUFNPQPKETFENIOLVSWLTFIAFTLAKOWATEQOKPPA");
    decryptText.push_back(
        "BOBISXSOMESORTOFIUNIORCOMPLEXQXENOPHONEONEZEROTHINGZ");

    ciphers.push_back(cipherFactory(CipherType::Vigenere, "hello"));
    plainText.push_back(
        "THISISQUITEALONGMESSAGESOTHEKEYWILLNEEDTOREPEATAFEWTIMES");
    cipherText.push_back(
        "ALTDWZUFTHLEWZBNQPDGHKPDCALPVSFATWZUIPOHVVPASHXLQSDXTXSZ");
    decryptText.push_back(
        "THISISQUITEALONGMESSAGESOTHEKEYWILLNEEDTOREPEATAFEWTIMES");

    for (size_t i{0}; i < ciphers.size(); ++i) {
        REQUIRE(ciphers[i]);
        REQUIRE(testCipher(*ciphers[i], CipherMode::Encrypt, plainText[i],
                           cipherText[i]));
        REQUIRE(testCipher(*ciphers[i], CipherMode::Decrypt, cipherText[i],
                           decryptText[i]));
    }
}

TEST_CASE("Caesar cipher valid key", "[cipher exceptions]")
{
    REQUIRE_NOTHROW(cipherFactory(CipherType::Caesar, "10"));
}

TEST_CASE("Caesar cipher invalid key", "[cipher exceptions]")
{
    REQUIRE_THROWS_AS(cipherFactory(CipherType::Caesar, "-10"), InvalidKey);
    REQUIRE_THROWS_AS(cipherFactory(CipherType::Caesar, "agfag"), InvalidKey);
    REQUIRE_THROWS_AS(cipherFactory(CipherType::Caesar, ";[]'."), InvalidKey);
}

TEST_CASE("Playfair cipher valid key", "[cipher exceptions]")
{
    REQUIRE_NOTHROW(cipherFactory(CipherType::Playfair, "hello"));
}

TEST_CASE("Vigenere cipher valid key", "[cipher exceptions]")
{
    REQUIRE_NOTHROW(cipherFactory(CipherType::Vigenere, "hello"));
}

TEST_CASE("Vigenere cipher invalid key", "[cipher exceptions]")
{
    REQUIRE_THROWS_AS(cipherFactory(CipherType::Vigenere, "1340"), InvalidKey);
    REQUIRE_THROWS_AS(cipherFactory(CipherType::Vigenere, "-10"), InvalidKey);
    REQUIRE_THROWS_AS(cipherFactory(CipherType::Vigenere, ";[]'."), InvalidKey);
}