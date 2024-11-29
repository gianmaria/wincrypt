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

#include "win_cpp_crypt.h"

// https://emn178.github.io/online-tools/sha256.html



std::vector<unsigned char> read_file_to_vector(const std::string& file_path)
{
    // Open file in binary mode
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    // Move the file pointer to the end to get the size
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read the file contents into a vector
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + file_path);
    }

    return buffer;
}

int main()
{
    try
    {
        using namespace WinCppCrypt;

        {
            // read file
            auto file_path = "data.bin";

            auto file_data = read_file_to_vector(file_path);
            std::cout << "File read successfully. Size: " << file_data.size() << " bytes." << std::endl;

            // calculate sha256 file
            auto hash_original = SHA256::generate(file_data.data(), file_data.size());
            
            // encrypt file
            auto ciphertext = AES::encrypt(file_data.data(), file_data.size(), "Passw0rd");

            // decrypt file
            auto plaintext = AES::decrypt(file_data.data(), file_data.size(), "Passw0rd");
                        
            // calculate again sha256 of decrypted file
            auto hash_decrypted = SHA256::generate(plaintext.data(), plaintext.size());

            auto b64_1 = base64_encode(hash_original.data(), hash_original.size());
            auto b64_2 = base64_encode(hash_decrypted.data(), hash_decrypted.size());

            std::println("original:  {}", b64_1);
            std::println("decrypted: {}", b64_2);

            if (b64_1 != b64_2)
            {
                std::println("error!! hashes does not matches");
            }
            else
            {
                std::println("all good");
            }

        }


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
