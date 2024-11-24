// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include <string>
#include <vector>
#include <cstdint>

namespace WinCppCrypt
{

using std::string;
using std::vector;

namespace SHA256
{
vector<uint8_t> generate(const uint8_t* data, uint64_t data_size);
vector<uint8_t> generate(const string& str);
vector<uint8_t> generate(const char* str);
}

namespace AES
{
vector<uint8_t> encrypt(const uint8_t* data, uint64_t data_size, const char* password);
vector<uint8_t> encrypt(const string& str, const char* password);
}

}

