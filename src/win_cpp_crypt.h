// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace WinCppCrypt
{

using std::string;
using std::string_view;
using std::vector;

namespace SHA256
{
vector<uint8_t> generate(const uint8_t* data, uint64_t data_size);
vector<uint8_t> generate(string_view str);
}

namespace AES
{
vector<uint8_t> encrypt(const uint8_t* plaintext, uint64_t plaintext_size, string_view password);
vector<uint8_t> encrypt(string_view plaintext, string_view password);

vector<uint8_t> decrypt(const uint8_t* ciphertext, uint64_t ciphertext_size, string_view password);
vector<uint8_t> decrypt(string_view ciphertext, string_view password);
}

}

