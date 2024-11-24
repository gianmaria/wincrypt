// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include "win_cpp_crypt.h"

#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <ntstatus.h>

#include <memory>
#include <print>
#include <functional>

using std::function;

namespace WinCppCrypt
{

class Defer
{
    function<void()> cleanup = nullptr;

public:

    Defer(function<void()> func)
        : cleanup(std::move(func))
    {
    }

    ~Defer()
    {
        if (cleanup) cleanup();
    }
};

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

namespace SHA256
{

vector<uint8_t> generate(const uint8_t* data, uint64_t data_size)
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,            // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_SHA256_ALGORITHM, // [in] LPCWSTR pszAlgId,
        nullptr,                 // [in] LPCWSTR pszImplementation,
        0                        // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptOpenAlgorithmProvider failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });

    ULONG bytes_copied = 0;

    DWORD object_size = 0;
    status = BCryptGetProperty(
        algo_handle,          // [in]  BCRYPT_HANDLE hObject,
        BCRYPT_OBJECT_LENGTH, // [in]  LPCWSTR pszProperty,
        reinterpret_cast<PUCHAR>(&object_size), // [out] PUCHAR pbOutput,
        sizeof(object_size),  // [in]  ULONG cbOutput,
        &bytes_copied,        // [out] ULONG *pcbResult,
        0                     // [in]  ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptGetProperty for BCRYPT_OBJECT_LENGTH failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto object_buffer = std::make_unique<uint8_t[]>(object_size);

    DWORD hash_size = 0;
    status = BCryptGetProperty(
        algo_handle,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_size),
        sizeof(hash_size),
        &bytes_copied,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptGetProperty for BCRYPT_HASH_LENGTH failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto hash = vector<uint8_t>(hash_size);

    BCRYPT_HASH_HANDLE hash_handle = nullptr;
    status = BCryptCreateHash(
        algo_handle,         // [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        &hash_handle,        // [out] BCRYPT_HASH_HANDLE *phHash,
        object_buffer.get(), // [out] PUCHAR pbHashObject,
        object_size,         // [in, optional] ULONG cbHashObject,
        nullptr,             // [in, optional] PUCHAR pbSecret,
        0,                   // [in] ULONG cbSecret,
        0                    // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptCreateHash failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto destry_hash = Defer([&]()
    {
        BCryptDestroyHash(hash_handle);
    });

    status = BCryptHashData(
        hash_handle,  // [in, out] BCRYPT_HASH_HANDLE hHash,
        (PUCHAR)data, // [in] PUCHAR pbInput,
        static_cast<ULONG>(data_size),    // [in] ULONG cbInput,
        0             // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptHashData failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    status = BCryptFinishHash(
        hash_handle, // [in, out] BCRYPT_HASH_HANDLE hHash,
        hash.data(), // [out] PUCHAR pbOutput,
        static_cast<ULONG>(hash.size()), // [in] ULONG cbOutput,
        0            // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptFinishHash failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    return hash;
}

vector<uint8_t> generate(const string& str)
{
    return generate(
        reinterpret_cast<const uint8_t*>(str.data()),
        str.length()
    );
}

}

}
