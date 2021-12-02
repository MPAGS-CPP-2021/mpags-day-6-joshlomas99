#include "CipherFactory.hpp"
#include "CipherMode.hpp"
#include "CipherType.hpp"
#include "Exceptions.hpp"
#include "ProcessCommandLine.hpp"
#include "TransformChar.hpp"

#include <cctype>
#include <fstream>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

int main(int argc, char* argv[])
{
    // Convert the command-line arguments into a more easily usable form
    const std::vector<std::string> cmdLineArgs{argv, argv + argc};

    // Options that might be set by the command-line arguments
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};
    
    // Set number of threads to a specific value (for now)
    const size_t threadNum{12};

    // Process command line arguments
    try {
        processCommandLine(cmdLineArgs, settings);
    }
    catch ( const MissingArgument& e ) {
        std::cerr << "[error] Missing argument: " << e.what() << std::endl;
        return 1;
    }
    catch ( const UnknownArgument& e ) {
        std::cerr << "[error] Unknown argument: " << e.what() << std::endl;
        return 1;
    }

    // Handle help, if requested
    if (settings.helpRequested) {
        // Line splitting for readability
        std::cout
            << "Usage: mpags-cipher [-h/--help] [--version] [-i <file>] [-o <file>] [-c <cipher>] [-k <key>] [--encrypt/--decrypt]\n\n"
            << "Encrypts/Decrypts input alphanumeric text using classical ciphers\n\n"
            << "Available options:\n\n"
            << "  -h|--help        Print this help message and exit\n\n"
            << "  --version        Print version information\n\n"
            << "  -i FILE          Read text to be processed from FILE\n"
            << "                   Stdin will be used if not supplied\n\n"
            << "  -o FILE          Write processed text to FILE\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "  -c CIPHER        Specify the cipher to be used to perform the encryption/decryption\n"
            << "                   CIPHER can be caesar, playfair, or vigenere - caesar is the default\n\n"
            << "  -k KEY           Specify the cipher KEY\n"
            << "                   A null key, i.e. no encryption, is used if not supplied\n\n"
            << "  --encrypt        Will use the cipher to encrypt the input text (default behaviour)\n\n"
            << "  --decrypt        Will use the cipher to decrypt the input text\n\n"
            << std::endl;
        // Help requires no further action, so return from main
        // with 0 used to indicate success
        return 0;
    }

    // Handle version, if requested
    // Like help, requires no further action,
    // so return from main with zero to indicate success
    if (settings.versionRequested) {
        std::cout << "0.5.0" << std::endl;
        return 0;
    }

    // Request construction of the appropriate cipher
    std::unique_ptr<Cipher> cipher;
    try {
        cipher = cipherFactory(settings.cipherType, settings.cipherKey);
    }
    catch (const InvalidKey& e) {
        std::cerr << "[error] Invalid key: " << e.what()
                  << std::endl;
        return 1;
    }

    // Check that the cipher was constructed successfully
    if (!cipher) {
        std::cerr << "[error] problem constructing requested cipher"
                  << std::endl;
        return 1;
    }

    // Initialise variables
    char inputChar{'x'};
    std::string inputText;

    // Read in user input from stdin/file
    if (!settings.inputFile.empty()) {
        // Open the file and check that we can read from it
        std::ifstream inputStream{settings.inputFile};
        if (!inputStream.good()) {
            std::cerr << "[error] failed to create istream on file '"
                      << settings.inputFile << "'" << std::endl;
            return 1;
        }

        // Loop over each character from the file
        while (inputStream >> inputChar) {
            inputText += transformChar(inputChar);
        }

    } else {
        // Loop over each character from user input
        // (until Return then CTRL-D (EOF) pressed)
        while (std::cin >> inputChar) {
            inputText += transformChar(inputChar);
        }
    }

    std::string outputText{""};

    if (settings.cipherType == CipherType::Playfair) {
        // We cannot use multi-threading here for the Playfair cipher as splitting
        // up the inputText will mess with the processing of duplicate characters
        // and adding a Z to the end of the string. We would need to implement
        // multi-threading in the applyCipher function of this cipher instead,
        // after all this processing has been completed.
        outputText = cipher->applyCipher(inputText, settings.cipherMode);
    }
    else {
        // Create lambda function to call the 'applyCipher' function on
        // the constructed Cipher object.
        auto doCipher = [&cipher, &settings](std::string input) {
            return cipher->applyCipher(input, settings.cipherMode);
        };
            
        // Create empty container for each thread process    
        std::vector<std::future<std::string>> futures;

        if (settings.cipherType == CipherType::Caesar) {
            // Calculate lengths of inputText chunks to be seperated out for each thread
            const size_t chunkLength{inputText.length()/threadNum};

            // This will miss a few characters so we need the first few text chunks to be
            // 1 longer than the rest, so we define the number of extra characters.
            // This ensures we use every thread as evenly as possible
            size_t endTextLen{inputText.length() - threadNum*chunkLength};

            // Define the starting point of the current text chunk
            size_t inputTextChunkStart{0};
            
            // Loop over the number of threads you want to use (should be configurable but
            // don’t worry about that now!)
            for (size_t threadCount{0}; threadCount < threadNum; threadCount++) {
                // For each iteration, take the next chunk from the input string
                std::string inputTextChunk{inputText.substr(inputTextChunkStart, chunkLength)};
                inputTextChunkStart += chunkLength;

                if (endTextLen > 0) {
                    // If we still require text chunks which are 1 character longer,
                    // make it longer by another character
                    inputTextChunk += inputText.substr(inputTextChunkStart, 1);
                    inputTextChunkStart++;
                    // Decrease the number of extra characters
                    endTextLen -= 1;
                }
                
                // Start a new thread to run the lambda function that calls 'applyCipher'
                futures.push_back(std::async(std::launch::async, doCipher, inputTextChunk));
                
            }
        }
        else if (settings.cipherType == CipherType::Vigenere) {
            // Calculate lengths of inputText chunks to be seperated out for each thread
            // For the Vigenere cipher each chunkLength needs to be a multiple of the key length,
            // until the final chunk, so that we don't skip the end of the keyword half way through
            // the overall inputText, so that the multi-threaded encryption is consistent with the
            // single-threaded encryption.
            const size_t chunkLength = (((inputText.length()/settings.cipherKey.length())/threadNum) + 1)*settings.cipherKey.length();
            
            // Loop over the number of threads you want to use (should be configurable but
            // don’t worry about that now!)
            for (size_t threadCount{0}; threadCount < threadNum; threadCount++) {
                std::cout << threadCount << std::endl;

                // For each iteration, take the next chunk from the input string
                std::string inputTextChunk{""};
                try {
                    inputTextChunk = inputText.substr(threadCount*chunkLength, chunkLength);
                }
                catch (std::out_of_range&) {
                    // If the substr function throws std::out_of_range it means that
                    // we have reached the end of the string so we can stop the loop
                    break;
                }
                std::cout << inputTextChunk << std::endl;
                
                // Start a new thread to run the lambda function that calls 'applyCipher'
                futures.push_back(std::async(std::launch::async, doCipher, inputTextChunk));

            }
        }
        
        // Loop over the futures and wait until they are all completed
        std::future_status status{std::future_status::timeout};
        bool allFuturesReady{true};
        while (!allFuturesReady) {
            allFuturesReady = true;
            for (auto &future : futures) {
                status = future.wait_for(std::chrono::milliseconds(10));
                if (status == std::future_status::timeout) {
                    allFuturesReady = false;
                }
            }
        }

        // // Get the results from them and assemble the final string
        for (auto &future : futures) {
            outputText += future.get();
        }
    }

    // Output the encrypted/decrypted text to stdout/file
    if (!settings.outputFile.empty()) {
        // Open the file and check that we can write to it
        std::ofstream outputStream{settings.outputFile};
        if (!outputStream.good()) {
            std::cerr << "[error] failed to create ostream on file '"
                      << settings.outputFile << "'" << std::endl;
            return 1;
        }

        // Print the encrypted/decrypted text to the file
        outputStream << outputText << std::endl;

    } else {
        // Print the encrypted/decrypted text to the screen
        std::cout << outputText << std::endl;
    }

    // No requirement to return from main, but we do so for clarity
    // and for consistency with other functions
    return 0;
}
