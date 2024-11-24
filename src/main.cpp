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

int main()
{
    using namespace WinCppCrypt;

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

    
    
    
    
    
    msg = "1234567890123456";
    auto cypher = AES::encrypt(msg, "password");
    std::print("encryption of '{}': ", msg);
    for (auto d : cypher)
    {
        cout
            << std::setw(2)
            << std::setfill('0')
            << std::hex
            << std::nouppercase
            << static_cast<u32>(d);
    }
    cout << endl;

    return 0;
}
