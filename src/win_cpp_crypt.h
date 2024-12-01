// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <tuple>

/*
* TODO:
*   [X] test AES::encrypt and AES::decrypt
*   [] add non zero IV
*   [] salt password
*/

namespace WinCppCrypt
{

using std::string;
using std::string_view;
using std::vector;
using std::tuple;

using ByteArray = vector<uint8_t>;

using Ciphertext = ByteArray;
using Plaintext = ByteArray;
using Nonce = ByteArray;
using Tag = ByteArray;

string base64_encode(const uint8_t* data, uint64_t data_size);
string base64_encode(string_view input);

vector<uint8_t> random_bytes(uint32_t count);

namespace SHA256
{
vector<uint8_t> generate(const uint8_t* data, uint64_t data_size);
vector<uint8_t> generate(string_view str);
} // SHA256

namespace AES
{
vector<uint8_t> encrypt(const uint8_t* plaintext, uint64_t plaintext_size,
                        string_view password);
vector<uint8_t> encrypt(string_view plaintext, string_view password);

vector<uint8_t> decrypt(const uint8_t* ciphertext, uint64_t ciphertext_size,
                        string_view password);
vector<uint8_t> decrypt(string_view ciphertext, string_view password);

struct Error
{
    string str;
    int32_t code = -1;

    operator bool() const
    {
        return str.length() != 0;
    }
};

auto encrypt_galois(
    string_view plaintext,
    string_view password,
    string_view associated_data = {} // optional
) -> tuple<Ciphertext, Nonce, Tag, Error>;

auto decrypt_galois(
    ByteArray ciphertext,
    string_view password,
    ByteArray nonce,
    ByteArray tag,
    string_view associated_data = {} // optional
) -> tuple<Plaintext, Error>;

} // AES

} // WinCppCrypt