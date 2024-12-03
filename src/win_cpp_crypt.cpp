// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include "win_cpp_crypt.h"

#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <ntstatus.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

#include <memory>
#include <print>
#include <functional>
#include <iostream>

using std::function;
using namespace std::string_literals;
using namespace std::string_view_literals;

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

        case STATUS_AUTH_TAG_MISMATCH:
        return "STATUS_AUTH_TAG_MISMATCH";

        case STATUS_INVALID_BUFFER_SIZE:
        return "STATUS_INVALID_BUFFER_SIZE";

        case STATUS_DATA_ERROR:
        return "STATUS_DATA_ERROR";

        default:
        return "???";
    }
}


string base64_encode(const uint8_t* data, uint64_t data_size)
{
    BOOL result = FALSE;

    DWORD output_size = 0;
    result = CryptBinaryToStringA(
        data,      // [in]            const BYTE * pbBinary,
        data_size, // [in]            DWORD      cbBinary,

        CRYPT_STRING_BASE64 | // [in]            DWORD      dwFlags, 
        CRYPT_STRING_NOCRLF,

        nullptr, // [out, optional] LPSTR      pszString,
        &output_size// [in, out]       DWORD * pcchString
    );

    if (result == FALSE)
    {
        std::println("[ERROR] CryptBinaryToStringA failed");
        return {};
    }

    auto base64 = string(output_size - 1, 0);

    result = CryptBinaryToStringA(
        data,      // [in]            const BYTE * pbBinary,
        data_size, // [in]            DWORD      cbBinary,

        CRYPT_STRING_BASE64 | // [in]            DWORD      dwFlags, 
        CRYPT_STRING_NOCRLF,

        base64.data(), // [out, optional] LPSTR      pszString,
        &output_size// [in, out]       DWORD * pcchString
    );

    return base64;
}

string base64_encode(string_view input)
{
    return base64_encode(
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size()
    );
}

vector<uint8_t> random_bytes(uint32_t count)
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,            // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_RNG_ALGORITHM,    // [in] LPCWSTR pszAlgId,
        nullptr,                 // [in] LPCWSTR pszImplementation,
        0                        // [in] ULONG dwFlags
    );
    // TODO: close AlgorithmProvider

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptOpenAlgorithmProvider failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto random_data = vector<uint8_t>(count, 0);

    status = BCryptGenRandom(
        algo_handle, // [in, out] BCRYPT_ALG_HANDLE hAlgorithm,

        random_data.data(), // [in, out] PUCHAR            pbBuffer,
        random_data.size(), // [in]      ULONG             cbBuffer,

        0      // [in]      ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptGenRandom failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    return random_data;
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

    auto destroy_hash = Defer([&]()
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

vector<uint8_t> generate(string_view str)
{
    return generate(
        reinterpret_cast<const uint8_t*>(str.data()),
        str.length()
    );
}

}

namespace AES
{

vector<uint8_t> encrypt(const uint8_t* plaintext, uint64_t plaintext_size,
                        string_view password)
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,            // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_AES_ALGORITHM,    // [in] LPCWSTR pszAlgId,
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

    status = BCryptSetProperty(
        algo_handle,                   // [in, out] BCRYPT_HANDLE hObject,
        BCRYPT_CHAINING_MODE,          // [in]      LPCWSTR       pszProperty,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, // [in]      PUCHAR        pbInput,
        sizeof(BCRYPT_CHAIN_MODE_CBC), // [in]      ULONG         cbInput,
        0                              // [in]      ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptSetProperty for BCRYPT_CHAINING_MODE failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

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

    DWORD block_size = 0;
    status = BCryptGetProperty(
        algo_handle,
        BCRYPT_BLOCK_LENGTH,
        reinterpret_cast<PUCHAR>(&block_size),
        sizeof(block_size),
        &bytes_copied,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptGetProperty for BCRYPT_BLOCK_LENGTH failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto iv = vector<uint8_t>(block_size, 0);

    auto secret = SHA256::generate(password);

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptGenerateSymmetricKey(
        algo_handle,         // [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        &key_handle,         // [out] BCRYPT_KEY_HANDLE *phKey,
        object_buffer.get(), // [out, optional] PUCHAR pbKeyObject,
        object_size,         // [in] ULONG cbKeyObject,
        secret.data(),       // [in] PUCHAR pbSecret,
        secret.size(),       // [in] ULONG cbSecret,
        0                    // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptGenerateSymmetricKey failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto key_destroyer = Defer([&]()
    {
        BCryptDestroyKey(key_handle);
    });

    ULONG ciphertext_len = 0;

    // calculate ciphertext len first
    status = BCryptEncrypt(
        key_handle,          // [in, out] BCRYPT_KEY_HANDLE hKey,
        (PUCHAR)plaintext,        // [in] PUCHAR pbInput,
        plaintext_size,           // [in] ULONG cbInput,
        nullptr,             // [in, optional] VOID *pPaddingInfo,
        (PUCHAR)iv.data(),   // [in, out, optional] PUCHAR pbIV,
        iv.size(),           // [in] ULONG cbIV,
        nullptr,             // [out, optional]      PUCHAR pbOutput,
        0,                   // [in] ULONG cbOutput,
        &ciphertext_len,     // [out] ULONG *pcbResult,
        BCRYPT_BLOCK_PADDING // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptEncrypt failed while calculating ciphertext len: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto ciphertext = vector<uint8_t>(ciphertext_len, 0);

    ULONG encrypted_size = 0;
    status = BCryptEncrypt(
        key_handle,          // [in, out] BCRYPT_KEY_HANDLE hKey,
        (PUCHAR)plaintext,        // [in] PUCHAR pbInput,
        plaintext_size,           // [in] ULONG cbInput,
        nullptr,             // [in, optional] VOID *pPaddingInfo,
        (PUCHAR)iv.data(),   // [in, out, optional] PUCHAR pbIV,
        iv.size(),           // [in] ULONG cbIV,
        (PUCHAR)ciphertext.data(), // [out, optional]      PUCHAR pbOutput,
        ciphertext.size(),   // [in] ULONG cbOutput,
        &encrypted_size,       // [out] ULONG *pcbResult,
        BCRYPT_BLOCK_PADDING // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptEncrypt failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    return ciphertext;
}

vector<uint8_t> encrypt(string_view plaintext, string_view password)
{
    return encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(),
        password
    );
}


vector<uint8_t> decrypt(const uint8_t* ciphertext, uint64_t ciphertext_size,
                        string_view password)
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,            // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_AES_ALGORITHM,    // [in] LPCWSTR pszAlgId,
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

    status = BCryptSetProperty(
        algo_handle,                   // [in, out] BCRYPT_HANDLE hObject,
        BCRYPT_CHAINING_MODE,          // [in]      LPCWSTR       pszProperty,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, // [in]      PUCHAR        pbInput,
        sizeof(BCRYPT_CHAIN_MODE_CBC), // [in]      ULONG         cbInput,
        0                              // [in]      ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptSetProperty for BCRYPT_CHAINING_MODE failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

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

    DWORD block_size = 0;
    status = BCryptGetProperty(
        algo_handle,
        BCRYPT_BLOCK_LENGTH,
        reinterpret_cast<PUCHAR>(&block_size),
        sizeof(block_size),
        &bytes_copied,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptGetProperty for BCRYPT_BLOCK_LENGTH failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto iv = vector<uint8_t>(block_size, 0);

    auto secret = SHA256::generate(password);

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptGenerateSymmetricKey(
        algo_handle,         // [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        &key_handle,         // [out] BCRYPT_KEY_HANDLE *phKey,
        object_buffer.get(), // [out, optional] PUCHAR pbKeyObject,
        object_size,         // [in] ULONG cbKeyObject,
        secret.data(),       // [in] PUCHAR pbSecret,
        secret.size(),       // [in] ULONG cbSecret,
        0                    // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptGenerateSymmetricKey failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto key_destroyer = Defer([&]()
    {
        BCryptDestroyKey(key_handle);
    });

    ULONG plaintext_len = 0;

    // calculate plaintext len first
    status = BCryptDecrypt(
        key_handle,          // [in, out] BCRYPT_KEY_HANDLE hKey,
        (PUCHAR)ciphertext,        // [in] PUCHAR pbInput,
        ciphertext_size,           // [in] ULONG cbInput,
        nullptr,             // [in, optional] VOID *pPaddingInfo,
        (PUCHAR)iv.data(),   // [in, out, optional] PUCHAR pbIV,
        iv.size(),           // [in] ULONG cbIV,
        nullptr,             // [out, optional]      PUCHAR pbOutput,
        0,                   // [in] ULONG cbOutput,
        &plaintext_len,     // [out] ULONG *pcbResult,
        BCRYPT_BLOCK_PADDING // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptDecrypt failed while calculating plaintext len: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    auto plaintext = vector<uint8_t>(plaintext_len, 0);

    ULONG decrypted_size = 0;
    status = BCryptDecrypt(
        key_handle,          // [in, out] BCRYPT_KEY_HANDLE hKey,
        (PUCHAR)ciphertext,        // [in] PUCHAR pbInput,
        ciphertext_size,           // [in] ULONG cbInput,
        nullptr,             // [in, optional] VOID *pPaddingInfo,
        (PUCHAR)iv.data(),   // [in, out, optional] PUCHAR pbIV,
        iv.size(),           // [in] ULONG cbIV,
        (PUCHAR)plaintext.data(), // [out, optional]      PUCHAR pbOutput,
        plaintext.size(),   // [in] ULONG cbOutput,
        &decrypted_size,    // [out] ULONG *pcbResult,
        BCRYPT_BLOCK_PADDING // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        std::println("[ERROR] BCryptDecrypt failed: '{}' code: 0x{:x}",
                     ntstatus_to_str(status),
                     static_cast<uint32_t>(status));
        return {};
    }

    plaintext.resize(decrypted_size);

    return plaintext;
}

vector<uint8_t> decrypt(string_view ciphertext, string_view password)
{
    return decrypt(
        reinterpret_cast<const uint8_t*>(ciphertext.data()),
        ciphertext.size(),
        password
    );
}








auto encrypt_galois(string_view plaintext, // P
                    string_view password, // K
                    string_view associated_data // A
) -> tuple<Ciphertext, Nonce, Tag, Error>
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;

    status = BCryptOpenAlgorithmProvider(
        &algo_handle,         // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_AES_ALGORITHM, // [in]  LPCWSTR           pszAlgId,
        nullptr,              // [in]  LPCWSTR           pszImplementation,
        0                     // [in]  ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {}, {}, {.str = ntstatus_to_str(status), .code = status}};
    }

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });

    status = BCryptSetProperty(
        algo_handle,                     // [in, out] BCRYPT_HANDLE hObject,
        BCRYPT_CHAINING_MODE,            // [in]      LPCWSTR       pszProperty,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,   // [in]      PUCHAR        pbInput,
        sizeof(BCRYPT_CHAIN_MODE_GCM),   // [in]      ULONG         cbInput,
        0                                // [in]      ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {}, {}, {.str = ntstatus_to_str(status), .code = status}};
    }

#if 1
    // TODO: i known the size of tag array
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths {};
    ULONG bytes_copied = 0;
    status = BCryptGetProperty(
        algo_handle,            // [in]  BCRYPT_HANDLE hObject,
        BCRYPT_AUTH_TAG_LENGTH, // [in]  LPCWSTR       pszProperty,
        (PUCHAR)&authTagLengths,          // [out] PUCHAR        pbOutput,
        sizeof(authTagLengths),   // [in]  ULONG         cbOutput,
        &bytes_copied,          // [out] ULONG         *pcbResult,
        0                       // [in]  ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {}, {}, {.str = ntstatus_to_str(status), .code = status}};
    }
#endif // 0


    // Import the AES key
    // TODO: 
    //  bad! bad! bad!
    //  use BCryptDeriveKeyPBKDF2 to derive the key
    auto key = SHA256::generate(password); // very bad!!!
    
    BCRYPT_KEY_DATA_BLOB_HEADER key_blob_header = {
        BCRYPT_KEY_DATA_BLOB_MAGIC,
        BCRYPT_KEY_DATA_BLOB_VERSION1,
        (ULONG)key.size()
    };

    auto key_blob = ByteArray(sizeof(key_blob_header) + key.size());

    auto tmp = string_view( // use std::span ?
                           reinterpret_cast<const char*>(&key_blob_header),
                           sizeof(key_blob_header)
    );

    key_blob.insert(key_blob.begin(), tmp.begin(), tmp.end());
    key_blob.insert(key_blob.begin() + sizeof(key_blob_header), key.begin(), key.end());

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptImportKey(
        algo_handle,          // [in]            BCRYPT_ALG_HANDLE hAlgorithm,
        nullptr,              // [in, optional]  BCRYPT_KEY_HANDLE hImportKey,
        BCRYPT_KEY_DATA_BLOB, // [in]            LPCWSTR           pszBlobType,
        &key_handle,          // [out]           BCRYPT_KEY_HANDLE *phKey,
        nullptr,              // [out, optional] PUCHAR            pbKeyObject,
        0,                    // [in]            ULONG             cbKeyObject,
        key_blob.data(),      // [in]            PUCHAR            pbInput,
        key_blob.size(),      // [in]            ULONG             cbInput,
        0                     // [in]            ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {}, {}, {.str = ntstatus_to_str(status), .code = status}};
    }

    auto destroy_key = Defer([&]()
    {
        BCryptDestroyKey(key_handle);
    });


    // Prepare the GCM authentication information
    const uint32_t nonce_size = 12; // 96 bit
    auto nonce = random_bytes(nonce_size);

    const uint32_t tag_size = 16; // 128 bit
    auto tag = ByteArray(tag_size, 0);
 
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = const_cast<BYTE*>(nonce.data());
    authInfo.cbNonce = (ULONG)nonce.size();
    authInfo.pbAuthData = (BYTE*)associated_data.data(); // TODO: fix const removal
    authInfo.cbAuthData = (ULONG)associated_data.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = tag_size;


#if 0
    // Calculate ciphertext size
    ULONG ciphertextSize = 0;
    status = BCryptEncrypt(
        key_handle,               //   [in, out]           BCRYPT_KEY_HANDLE hKey, 

        (PUCHAR)plaintext.data(), //   [in]                PUCHAR            pbInput, 
        (ULONG)plaintext.size(),  //   [in]                ULONG             cbInput, 

        &authInfo,                //   [in, optional]      VOID              *pPaddingInfo, 

        nullptr,             //   [in, out, optional] PUCHAR            pbIV, (handled in authInfo)
        0,             //   [in]                ULONG             cbIV, 

        nullptr,                  //   [out, optional]     PUCHAR            pbOutput, 
        0,                        //   [in]                ULONG             cbOutput, 

        &ciphertextSize,          //   [out]               ULONG             *pcbResult,

        0                         //   [in]                ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {}, {}, {.str = ntstatus_to_str(status), .code = status}};
    }
#endif // 0


    auto ciphertext = ByteArray(plaintext.size(), 0);
    //ULONG bytes_copied = 0;

    status = BCryptEncrypt(
        key_handle,               //   [in, out]           BCRYPT_KEY_HANDLE hKey, 
        
        (PUCHAR)plaintext.data(), //   [in]                PUCHAR            pbInput, 
        (ULONG)plaintext.size(),  //   [in]                ULONG             cbInput, 
        
        &authInfo,                //   [in, optional]      VOID              *pPaddingInfo, 
        
        nullptr,             //   [in, out, optional] PUCHAR            pbIV, 
        0,             //   [in]                ULONG             cbIV, 
        
        ciphertext.data(),        //   [out, optional]     PUCHAR            pbOutput, 
        ciphertext.size(),        //   [in]                ULONG             cbOutput, 
        
        &bytes_copied,            //   [out]               ULONG             *pcbResult,
        
        0                         //   [in]                ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {}, {}, {.str = ntstatus_to_str(status), .code = status}};
    }

    // tuple<Ciphertext, Nonce, Tag, Error>
    return {ciphertext, nonce, tag, {}};
}

auto decrypt_galois(
    ByteArray ciphertext, // C
    string_view password, // K
    ByteArray nonce, // IV
    ByteArray tag, // T
    string_view associated_data // A
) -> tuple<Plaintext, Error>
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,         // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_AES_ALGORITHM, // [in]  LPCWSTR           pszAlgId,
        nullptr,              // [in]  LPCWSTR           pszImplementation,
        0                     // [in]  ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {.str = ntstatus_to_str(status), .code = status}};
    }

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });

    status = BCryptSetProperty(
        algo_handle,                     // [in, out] BCRYPT_HANDLE hObject,
        BCRYPT_CHAINING_MODE,            // [in]      LPCWSTR       pszProperty,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,   // [in]      PUCHAR        pbInput,
        sizeof(BCRYPT_CHAIN_MODE_GCM),   // [in]      ULONG         cbInput,
        0                                // [in]      ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {.str = ntstatus_to_str(status), .code = status}};
    }

    // Import the AES key
    auto key = SHA256::generate(password);
    BCRYPT_KEY_DATA_BLOB_HEADER key_blob_header = {
        BCRYPT_KEY_DATA_BLOB_MAGIC,
        BCRYPT_KEY_DATA_BLOB_VERSION1,
        (ULONG)key.size()
    };

    auto key_blob = ByteArray(sizeof(key_blob_header) + key.size());

    auto tmp = string_view( // use std::span ?
                           reinterpret_cast<const char*>(&key_blob_header),
                           sizeof(key_blob_header)
    );

    key_blob.insert(key_blob.begin(), tmp.begin(), tmp.end());
    key_blob.insert(key_blob.begin() + sizeof(key_blob_header), key.begin(), key.end());

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptImportKey(
        algo_handle,          // [in]            BCRYPT_ALG_HANDLE hAlgorithm,
        nullptr,              // [in, optional]  BCRYPT_KEY_HANDLE hImportKey,
        BCRYPT_KEY_DATA_BLOB, // [in]            LPCWSTR           pszBlobType,
        &key_handle,          // [out]           BCRYPT_KEY_HANDLE *phKey,
        nullptr,              // [out, optional] PUCHAR            pbKeyObject,
        0,                    // [in]            ULONG             cbKeyObject,
        key_blob.data(),      // [in]            PUCHAR            pbInput,
        key_blob.size(),      // [in]            ULONG             cbInput,
        0                     // [in]            ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {.str = ntstatus_to_str(status), .code = status}};
    }

    auto destroy_key = Defer([&]()
    {
        BCryptDestroyKey(key_handle);
    });

    // Prepare the GCM authentication information
    const uint32_t nonce_size = 12;

    const uint32_t tag_size = 16;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = const_cast<BYTE*>(nonce.data());
    authInfo.cbNonce = (ULONG)nonce.size();
    authInfo.pbAuthData = (BYTE*)associated_data.data(); // TODO: fix const removal
    authInfo.cbAuthData = (ULONG)associated_data.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = tag_size;

    auto plaintext = ByteArray(ciphertext.size(), 0);

    ULONG bytes_copied = 0;
    status = BCryptDecrypt(
        key_handle,                 // [in, out]           BCRYPT_KEY_HANDLE hKey,
        (PUCHAR)ciphertext.data(),  // [in]                PUCHAR            pbInput,
        (ULONG)ciphertext.size(),   // [in]                ULONG             cbInput,
        &authInfo,                  // [in, optional]      VOID              *pPaddingInfo,
        nullptr,                    // [in, out, optional] PUCHAR            pbIV,
        0,                          // [in]                ULONG             cbIV,
        plaintext.data(),           // [out, optional]     PUCHAR            pbOutput,
        plaintext.size(),           // [in]                ULONG             cbOutput,
        &bytes_copied,              // [out]               ULONG             *pcbResult,
        0                           // [in]                ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {{}, {.str = ntstatus_to_str(status), .code = status}};
    }

    return {plaintext, {}};
}


} // AES

} // WinCppCrypt

