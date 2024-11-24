// This is an open source non-commercial project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <ntstatus.h>

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


namespace SHA256
{
const char* ntstatus_to_str(NTSTATUS status)
{
    switch (status)
    {
        case STATUS_SUCCESS:
        return "STATUS_SUCCESS";

        case STATUS_NOT_FOUND:
        return "STATUS_NOT_FOUND";

        case STATUS_INVALID_PARAMETER:
        return "STATUS_INVALID_PARAMETER";

        case STATUS_NO_MEMORY:
        return "STATUS_NO_MEMORY";

        case STATUS_BUFFER_TOO_SMALL:
        return "STATUS_BUFFER_TOO_SMALL";

        case STATUS_INVALID_HANDLE:
        return "STATUS_INVALID_HANDLE";

        case STATUS_NOT_SUPPORTED:
        return "STATUS_NOT_SUPPORTED";

        default:
        return "???";
    }
}

vec<u8> generate(const u8* data, u64 data_size)
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    );

    ULONG bytes_copied = 0;

    DWORD object_size = 0;
    status = BCryptGetProperty(
        algo_handle,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_size,
        sizeof(object_size),
        &bytes_copied,
        0
    );

    auto object_buffer = std::make_unique<u8[]>(object_size);

    DWORD hash_size = 0;
    status = BCryptGetProperty(
        algo_handle,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hash_size,
        sizeof(hash_size),
        &bytes_copied,
        0
    );

    auto hash = vec<u8>(hash_size);

    BCRYPT_HASH_HANDLE hash_handle = nullptr;
    status = BCryptCreateHash(
        algo_handle, // [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        &hash_handle, // [out] BCRYPT_HASH_HANDLE *phHash,
        object_buffer.get(), // [out] PUCHAR pbHashObject,
        object_size, // [in, optional] ULONG cbHashObject,
        nullptr, // [in, optional] PUCHAR pbSecret,
        0, // [in] ULONG cbSecret,
        0 // [in] ULONG dwFlags
    );


    status = BCryptHashData(
        hash_handle, // [in, out] BCRYPT_HASH_HANDLE hHash,
        (PUCHAR)data, // [in] PUCHAR pbInput,
        data_size, // [in] ULONG cbInput,
        0 // [in] ULONG dwFlags
    );

    status = BCryptFinishHash(
        hash_handle, // [in, out] BCRYPT_HASH_HANDLE hHash,
        hash.data(), // [out] PUCHAR pbOutput,
        hash.size(), // [in] ULONG cbOutput,
        0// [in] ULONG dwFlags
    );
        
    BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(algo_handle, 0);

    return hash;
}

vec<u8> generate(str_cref str)
{
    return generate(
        reinterpret_cast<const u8*>(str.data()), 
        str.length()
    );
}

}

int main(int argc, char* argv[])
{
    auto msg = str("hello world");

    auto hash = SHA256::generate(msg);

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

    return 0;
}
