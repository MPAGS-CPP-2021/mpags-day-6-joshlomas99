//! Unit Tests for MPAGSCipher processCommandLine interface
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "ProcessCommandLine.hpp"
#include "Exceptions.hpp"

TEST_CASE("Help found correctly", "[commandline]")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "--help"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.helpRequested);
}

TEST_CASE("Version found correctly", "[commandline]")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "--version"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.versionRequested);
}

TEST_CASE("Encrypt mode activated")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "--encrypt"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.cipherMode == CipherMode::Encrypt);
}

TEST_CASE("Decrypt mode activated")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "--decrypt"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.cipherMode == CipherMode::Decrypt);
}

TEST_CASE("Key entered with no key specified")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-k"};

    REQUIRE_THROWS_AS(processCommandLine(cmdLine, settings), MissingArgument);
}

TEST_CASE("Key entered with key specified")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-k", "4"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.cipherKey == "4");
}

TEST_CASE("Input file declared without using input file")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-i"};

    REQUIRE_THROWS_AS(processCommandLine(cmdLine, settings), MissingArgument);
}

TEST_CASE("Input file declared")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-i", "input.txt"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.inputFile == "input.txt");
}

TEST_CASE("Output file declared without specifying output file")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-o"};

    REQUIRE_THROWS_AS(processCommandLine(cmdLine, settings), MissingArgument);
}

TEST_CASE("Output file declared")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-o", "output.txt"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.outputFile == "output.txt");
}

TEST_CASE("Cipher type declared without specifying cipher")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c"};

    REQUIRE_THROWS_AS(processCommandLine(cmdLine, settings), MissingArgument);
}

TEST_CASE("Cipher type declared with unknown cipher")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "rubbish"};

    REQUIRE_THROWS_AS(processCommandLine(cmdLine, settings), UnknownArgument);
}

TEST_CASE("Cipher type declared with Caesar cipher")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "caesar"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.cipherType == CipherType::Caesar);
}

TEST_CASE("Cipher type declared with Playfair cipher")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "playfair"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.cipherType == CipherType::Playfair);
}

TEST_CASE("Cipher type declared with Vigenere cipher")
{
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "vigenere"};
    
    REQUIRE_NOTHROW(processCommandLine(cmdLine, settings));
    REQUIRE(settings.cipherType == CipherType::Vigenere);
}