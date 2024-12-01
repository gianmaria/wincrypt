// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include <fstream>
#include <iostream>
#include <memory>
#include <print>
#include <string>
#include <vector>
#include <functional>
#include <cwchar>
#include <stdexcept>
#include <iomanip>
#include <filesystem>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

using std::cout;
using std::endl;
using std::string;
using std::wstring;
using std::string_view;
using std::vector;

using str = std::string;
using str_cref = std::string const&;

using wstr = std::wstring;

template<typename T>
using vec = vector<T>;

using namespace std::string_literals;
using namespace std::string_view_literals;

namespace fs = std::filesystem;

#include "win_cpp_crypt.h"

// https://emn178.github.io/online-tools/sha256.html



std::vector<unsigned char> read_file_to_vector(string_view file_path)
{
    fs::path p1 = file_path;
    // Open file in binary mode
    std::ifstream file(p1, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: ");
    }

    // Move the file pointer to the end to get the size
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read the file contents into a vector
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: ");
    }

    return buffer;
}

bool test_aes(string_view file_path)
{
    using namespace WinCppCrypt;

    auto file_data = read_file_to_vector(file_path);

    // calculate sha256 file
    auto hash_original = SHA256::generate(file_data.data(), file_data.size());

    // encrypt file
    auto ciphertext = AES::encrypt(file_data.data(), file_data.size(), "Passw0rd");

    // decrypt file
    auto plaintext = AES::decrypt(ciphertext.data(), ciphertext.size(), "Passw0rd");

    // calculate again sha256 of decrypted file
    auto hash_decrypted = SHA256::generate(plaintext.data(), plaintext.size());

    auto b1 = base64_encode(hash_original.data(), hash_original.size());
    auto b2 = base64_encode(hash_decrypted.data(), hash_decrypted.size());

    return b1 == b2;
}

int main()
{
    try
    {
        using namespace WinCppCrypt;

        {
#if 1
            auto msg = "The address of a buffer that contains the ciphertext to be decrypted. The cbInput parameter contains the size of the ciphertext to decrypt. For more information, see Remarks."s;
            auto key = "Passw0rd"s;
            auto associated_data = "v1.1"s;

            auto [ciphertext, nonce, tag, err] = AES::encrypt_galois(msg, key, associated_data);

            if (err)
            {
                // error handling here
                std::println("ERROR: '{}', code: {}", err.str, err.code);
                return 1;
            }

            std::cout << "Ciphertext: ";
            for (auto b : ciphertext)
            {
                cout
                    << std::setw(2)
                    << std::setfill('0')
                    << std::hex
                    << std::nouppercase
                    << static_cast<u32>(b);
            }
            cout << endl;

            std::cout << "Tag: ";
            for (auto t : tag)
            {
                std::cout << std::hex << static_cast<int>(t) << " ";
            }
            std::cout << std::endl;

            auto [plaintext, err_d] = AES::decrypt_galois(ciphertext, key, 
                                                          nonce, tag, associated_data);
            
            if (err_d)
            {
                // error handling here
                std::println("ERROR: '{}', code: {}", err_d.str, err_d.code);
                return 1;
            }

            std::cout << "\nPlaintext: ";
            for (auto p : plaintext)
            {
                std::cout << static_cast<char>(p);
            }
            std::cout << std::endl;

#endif // 0


        }

#if 0
        {
            // Example inputs
            std::vector<uint8_t> key(32, 0x11);  // 256-bit key (32 bytes)
            std::vector<uint8_t> nonce(12, 0x22); // 12-byte nonce
            std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', '!', '!'};
            std::vector<uint8_t> associatedData = {0x01, 0x02, 0x03, 0x04}; // Additional authenticated data (optional)

            std::vector<uint8_t> tag;
            auto ciphertext = AES::encrypt_galois(plaintext, key, nonce, associatedData, tag);

            // Print results
            std::cout << "Ciphertext: ";
            for (auto c : ciphertext)
            {
                std::cout << std::hex << static_cast<int>(c) << " ";
            }
            std::cout << "\nTag: ";
            for (auto t : tag)
            {
                std::cout << std::hex << static_cast<int>(t) << " ";
            }
            std::cout << std::endl;


            // Decrypt
            auto plaintext2 = AES::decrypt_galois(ciphertext, key, nonce, associatedData, tag);

            // Print results
            std::cout << "Plaintext2: ";
            for (auto p : plaintext2)
            {
                std::cout << static_cast<char>(p);
            }
            std::cout << std::endl;

        }
#endif // 0


#if 0
        {
            string_view files[] = {
                "big_data_01.bin",
                "big_data_02.mp4",
                "big_data_03.pdf",
            };

            for (auto file : files)
            {
                std::println("testing encrypt/decrypt of file: {} res: {}",
                             file, test_aes(file) ? "success" : "fail!!");
            }

        }

#endif // 0


#if 0
        {
            auto file_path = "data.bin";

            auto file_data = read_file_to_vector(file_path);
            std::cout << "File read successfully. Size: " << file_data.size() << " bytes." << std::endl;

            auto hash = SHA256::generate(file_data.data(), file_data.size());

            std::print("hash of file '{}': ", file_path);
            for (auto b : hash)
            {
                cout
                    << std::setw(2)
                    << std::setfill('0')
                    << std::hex
                    << std::nouppercase
                    << static_cast<u32>(b);
            }
            cout << endl;
        }
#endif // 0


#if 0
        {
            for (int i = 0;
                 i < 20;
                 ++i)
            {
                auto random_data = random_bytes(8);

                std::print("random data: ");
                for (auto d : random_data)
                {
                    cout
                        << std::setw(2)
                        << std::setfill('0')
                        << std::hex
                        << std::nouppercase
                        << static_cast<u32>(d);
                }
                cout << endl;
            }
        }
#endif // 0


#if 0
        {
            auto msg = string("The quick brown fox jumps over the lazy dog");
            auto base64 = base64_encode(msg);

            std::println("<{}>", base64);
        }

#endif // 0

#if 0
        {
            auto msg = str("😂😂😂😂😂");

            auto hash = SHA256::generate(msg);

            std::print("hash of '{}': ", msg);
            for (auto d : hash)
            {
                cout
                    << std::setw(2)
                    << std::setfill('0')
                    << std::hex
                    << std::nouppercase
                    << static_cast<u32>(d);
            }
            cout << endl;
        }
#endif // 0


#if 0
        {
            auto plaintext = string_view("hello world my friends");

            auto cyphertext = AES::encrypt(plaintext, "Passw0rd");

            std::print("encryption '{}' -> ", plaintext);

            for (auto d : cyphertext)
            {
                cout
                    << std::setw(2)
                    << std::setfill('0')
                    << std::hex
                    << std::nouppercase
                    << static_cast<u32>(d);
            }
            cout << endl;

            auto plaintext_back = AES::decrypt(cyphertext.data(), cyphertext.size(), "Passw0rd");

            std::print("decryption -> '");

            for (auto d : plaintext_back)
            {
                cout << static_cast<char>(d);
            }
            cout << "'" << endl;

            if (std::memcmp(plaintext.data(), plaintext_back.data(), std::min(plaintext.size(), plaintext_back.size())) == 0)
            {
                cout << "all good\n";
            }
            else
            {
                cout << "BAD BAD BAD!!!\n";
            }

        }
#endif // 0


        return 0;

    } catch (const std::exception& ex)
    {
        std::cerr << "[EXCEPTION]: " << ex.what() << std::endl;
    }
    
    return 1;
}
