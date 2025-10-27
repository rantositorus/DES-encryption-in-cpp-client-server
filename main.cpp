#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cassert>
#include <unordered_map>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <bitset>
#include "httplib.h"

using namespace std;

// ---------- CONFIG ----------
const string SHARED_KEY_HEX = "0123456789ABCDEF";
const int BLOCK_SIZE_BYTES = 8;
// ----------------------------

// initial permutation
const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};

// inverse initial permutation
const int IIP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};

// expansion permutation
const int EP[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

// permutation function
const int P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25};

// S-boxes (unchanged)
const int S_BOX[8][4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

// shift_table for key schedule
const int SHIFT_TABLE[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Permutation Choice 1 & 2
const int PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};
const int PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

// ---------- Utility conversions ----------

string hex_to_bin(const string &hex)
{
    assert(hex.length() == 16);
    string bin = "";
    unordered_map<char, string> bin_map = {
        {'0', "0000"}, {'1', "0001"}, {'2', "0010"}, {'3', "0011"}, {'4', "0100"}, {'5', "0101"}, {'6', "0110"}, {'7', "0111"}, {'8', "1000"}, {'9', "1001"}, {'A', "1010"}, {'B', "1011"}, {'C', "1100"}, {'D', "1101"}, {'E', "1110"}, {'F', "1111"}};
    for (unsigned int i = 0; i < hex.size(); i++)
    {
        bin += bin_map[hex[i]];
    }
    int zero_count = 64 - bin.length();
    for (int i = 0; i < zero_count; i++)
    {
        bin = "0" + bin;
    }
    return bin;
}

string bin_to_hex(const string &bin)
{
    assert(bin.length() == 64);
    string hex = "";
    unordered_map<string, char> hex_map = {
        {"0000", '0'}, {"0001", '1'}, {"0010", '2'}, {"0011", '3'}, {"0100", '4'}, {"0101", '5'}, {"0110", '6'}, {"0111", '7'}, {"1000", '8'}, {"1001", '9'}, {"1010", 'A'}, {"1011", 'B'}, {"1100", 'C'}, {"1101", 'D'}, {"1110", 'E'}, {"1111", 'F'}};
    for (unsigned int i = 0; i < bin.length(); i += 4)
    {
        string chunk = bin.substr(i, 4);
        hex += hex_map[chunk];
    }
    return hex;
}

string hex_encode(const string &input)
{
    static const char *hex_chars = "0123456789ABCDEF";
    string output;
    for (unsigned char c : input)
    {
        output.push_back(hex_chars[(c >> 4) & 0x0F]);
        output.push_back(hex_chars[c & 0x0F]);
    }
    return output;
}

string hex_decode(const string &input)
{
    string output;
    for (size_t i = 0; i < input.length(); i += 2)
    {
        unsigned char high = toupper(input[i]);
        unsigned char low = toupper(input[i + 1]);
        high = (high >= 'A') ? (high - 'A' + 10) : (high - '0');
        low = (low >= 'A') ? (low - 'A' + 10) : (low - '0');
        output.push_back((high << 4) | low);
    }
    return output;
}

string dec_to_bin(const string &dec)
{
    unordered_map<string, string> bin_map = {
        {"0", "0000"}, {"1", "0001"}, {"2", "0010"}, {"3", "0011"}, {"4", "0100"}, {"5", "0101"}, {"6", "0110"}, {"7", "0111"}, {"8", "1000"}, {"9", "1001"}, {"10", "1010"}, {"11", "1011"}, {"12", "1100"}, {"13", "1101"}, {"14", "1110"}, {"15", "1111"}};
    return bin_map.at(dec);
}

string XOR(const string &s1, const string &s2)
{
    assert(s1.length() == s2.length());
    string out;
    out.reserve(s1.length());
    for (size_t i = 0; i < s1.length(); ++i)
        out += (s1[i] == s2[i]) ? '0' : '1';
    return out;
}

string add_padding(const string &data)
{
    int padding_len = BLOCK_SIZE_BYTES - (data.length() % BLOCK_SIZE_BYTES);
    if (padding_len == 0)
        padding_len = BLOCK_SIZE_BYTES;
    char pc = (char)padding_len;
    string padded = data;
    padded.append(padding_len, pc);
    return padded;
}

string remove_padding(const string &data)
{
    if (data.empty())
        return data;
    unsigned char pc = data.back();
    int pad = (int)pc;
    if (pad < 1 || pad > BLOCK_SIZE_BYTES)
        return data;
    for (int i = 0; i < pad; ++i)
        if ((unsigned char)data[data.size() - 1 - i] != pc)
            return data;
    return data.substr(0, data.size() - pad);
}

string bytes_to_bin(const string &data)
{
    stringstream ss;
    for (unsigned char c : data)
        ss << bitset<8>(c);
    return ss.str();
}

string bin_to_bytes(const string &bin)
{
    if (bin.length() % 8 != 0)
        throw invalid_argument("Binary length not multiple of 8");
    string out;
    out.reserve(bin.length() / 8);
    for (size_t i = 0; i < bin.length(); i += 8)
    {
        string b = bin.substr(i, 8);
        unsigned char val = (unsigned char)bitset<8>(b).to_ulong();
        out.push_back((char)val);
    }
    return out;
}

// Base64 (unchanged)
static const string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static inline bool is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}
string base64_encode(string const &in)
{
    string out;
    int val = 0, valb = -6;
    for (unsigned char c : in)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}
string base64_decode(string const &encoded_string)
{
    int in_len = encoded_string.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    string out;
    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; (i < 3); i++)
                out += char_array_3[i];
            i = 0;
        }
    }
    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;
        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; (j < i - 1); j++)
            out += char_array_3[j];
    }
    return out;
}

// S-box apply
string apply_s_box(const string &bit_stream)
{
    assert(bit_stream.length() == 48);
    string out;
    out.reserve(32);
    for (int i = 0; i < 8; ++i)
    {
        string chunk = bit_stream.substr(i * 6, 6);
        string row_bits = "";
        row_bits += chunk[0];
        row_bits += chunk[5];
        string col_bits = chunk.substr(1, 4);
        int row = stoi(row_bits, nullptr, 2);
        int col = stoi(col_bits, nullptr, 2);
        int s_box_value = S_BOX[i][row][col];
        out += dec_to_bin(to_string(s_box_value));
    }
    return out;
}

string apply_permutation(const string &bit_stream)
{
    string out;
    for (int i = 0; i < 32; ++i)
        out += bit_stream[P[i] - 1];
    return out;
}
string apply_initial_permutation(const string &text)
{
    string out;
    for (int i = 0; i < 64; ++i)
        out += text[IP[i] - 1];
    return out;
}
string apply_inverse_initial_permutation(const string &text)
{
    string out;
    for (int i = 0; i < 64; ++i)
        out += text[IIP[i] - 1];
    return out;
}
string apply_expansion_permutation(const string &r)
{
    string out;
    for (int i = 0; i < 48; ++i)
        out += r[EP[i] - 1];
    return out;
}
string apply_permutation_choice_1(const string &k)
{
    string out;
    for (int i = 0; i < 56; ++i)
        out += k[PC1[i] - 1];
    return out;
}
string apply_permutation_choice_2(const string &k)
{
    string out;
    for (int i = 0; i < 48; ++i)
        out += k[PC2[i] - 1];
    return out;
}

vector<string> generate_subkeys(const string &key)
{
    vector<string> subkeys;
    subkeys.reserve(16);
    string temp_key;
    for (int i = 0; i < 16; ++i)
    {
        string left, right;
        if (i == 0)
        {
            string perm = apply_permutation_choice_1(key);
            left = perm.substr(0, 28);
            right = perm.substr(28, 28);
        }
        else
        {
            left = temp_key.substr(0, 28);
            right = temp_key.substr(28, 28);
        }
        if (SHIFT_TABLE[i] == 1)
        {
            left = left.substr(1) + left.substr(0, 1);
            right = right.substr(1) + right.substr(0, 1);
        }
        else
        {
            left = left.substr(2) + left.substr(0, 2);
            right = right.substr(2) + right.substr(0, 2);
        }
        temp_key = left + right;
        subkeys.push_back(apply_permutation_choice_2(temp_key));
    }
    return subkeys;
}

string function_F(const string &right, const string &subkey)
{
    string expanded = apply_expansion_permutation(right);
    string x = XOR(expanded, subkey);
    string s = apply_s_box(x);
    return apply_permutation(s);
}

string des_encrypt(const string &plaintext, const vector<string> &subkeys)
{
    string perm = apply_initial_permutation(plaintext);
    string left = perm.substr(0, 32), right = perm.substr(32, 32), temp;
    for (int i = 0; i < 16; ++i)
    {
        temp = right;
        right = XOR(left, function_F(right, subkeys[i]));
        left = temp;
    }
    string combined = right + left;
    return apply_inverse_initial_permutation(combined);
}

string des_decrypt(const string &ciphertext, const vector<string> &subkeys)
{
    string perm = apply_initial_permutation(ciphertext);
    string left = perm.substr(0, 32), right = perm.substr(32, 32), temp;
    for (int i = 15; i >= 0; --i)
    {
        temp = right;
        right = XOR(left, function_F(right, subkeys[i]));
        left = temp;
    }
    string combined = right + left;
    return apply_inverse_initial_permutation(combined);
}

string des_encrypt_blocks(const string &plaintext_bin, const vector<string> &subkeys)
{
    assert(plaintext_bin.size() % 64 == 0);
    string out;
    out.reserve(plaintext_bin.size());
    for (size_t i = 0; i < plaintext_bin.size(); i += 64)
        out += des_encrypt(plaintext_bin.substr(i, 64), subkeys);
    return out;
}

string des_decrypt_blocks(const string &ciphertext_bin, const vector<string> &subkeys)
{
    assert(ciphertext_bin.size() % 64 == 0);
    string out;
    out.reserve(ciphertext_bin.size());
    for (size_t i = 0; i < ciphertext_bin.size(); i += 64)
        out += des_decrypt(ciphertext_bin.substr(i, 64), subkeys);
    return out;
}

// ---------- Receiver ----------
void run_receiver_mode()
{
    httplib::Server svr;

    svr.Post("/decrypt", [](const httplib::Request &req, httplib::Response &res)
             {
        string key_bin = hex_to_bin(SHARED_KEY_HEX);
        // string permuted_key = apply_permutation_choice_1(key_bin); // HAPUS
        vector<string> subkeys = generate_subkeys(key_bin); // gunakan key 64-bit langsung
        cout << "[receiver] using shared key (hex): " << SHARED_KEY_HEX << '\n';

        auto data_it = req.params.find("data");
        if (data_it == req.params.end()) {
            res.status = 400;
            res.set_content("Missing 'data' parameter", "text/plain");
            return;
        }

        cout << "[receiver] received decryption request\n";
        string received_data = data_it->second;

        cout << "[receiver] data (hex): " << received_data << endl;

        string received_encrypted = hex_decode(received_data);
        cout << "[receiver] data (bytes): " << received_encrypted << endl;

        string encrypted_data_bin = bytes_to_bin(received_encrypted);

        string decrypted_data_bin = des_decrypt_blocks(encrypted_data_bin, subkeys);
        string decrypted_data = bin_to_bytes(decrypted_data_bin);
        cout << "[receiver] after decryption (hex): " << hex_encode(decrypted_data) << endl;

        decrypted_data = remove_padding(decrypted_data);
        cout << "[receiver] after removing padding (hex): " << hex_encode(decrypted_data) << endl;
        
        string decoded_plaintext = hex_decode(decrypted_data);
        cout << "[receiver] decoded plaintext : " << decoded_plaintext << '\n';

        res.set_content(decoded_plaintext, "text/plain"); });

    cout << "Receiver mode running on http://0.0.0.0:8080/decrypt" << endl;
    svr.listen("0.0.0.0", 8080);
}

// ---------- Sender ----------
void run_sender_mode(const string &receiver_host, const string &plaintext)
{
    cout << "[sender] original plaintext : " << plaintext << '\n';

    string wrapped = hex_encode(plaintext);
    cout << "[sender] Hex encoded plaintext: " << wrapped << '\n';

    string padded_plaintext = add_padding(wrapped);
    cout << "[sender] Padded plaintext: " << padded_plaintext << '\n';

    string plaintext_bin = bytes_to_bin(padded_plaintext);
    cout << "[sender] Plaintext in bits (first 64 bits): " << plaintext_bin.substr(0, 64) << " bits\n";

    string key_bin = hex_to_bin(SHARED_KEY_HEX);
    vector<string> subkeys = generate_subkeys(key_bin);

    string encrypted_data_bin = des_encrypt_blocks(plaintext_bin, subkeys);
    string encrypted_data = bin_to_bytes(encrypted_data_bin);
    cout << "[sender] After encryption (hex): " << hex_encode(encrypted_data) << '\n';

    httplib::Client cli(receiver_host.c_str());
    httplib::Params params;
    params.emplace("data", hex_encode(encrypted_data));

    auto res = cli.Post("/decrypt", params);

    if (res && res->status == 200)
    {
        cout << "Decrypted response from receiver: " << res->body << endl;
    }
    else
    {
        cout << "Failed to get response from receiver." << endl;
    }
}

int main()
{
    string mode;
    cout << "Enter mode (sender/receiver): ";
    cin >> mode;
    cin.ignore();

    if (mode == "receiver")
    {
        run_receiver_mode();
    }
    else if (mode == "sender")
    {
        string receiver_host;
        cout << "Enter receiver host (e.g. http://<IP>:8080) : ";
        getline(cin, receiver_host);

        string plaintext;
        cout << "Enter plaintext to encrypt: ";
        getline(cin, plaintext);

        run_sender_mode(receiver_host, plaintext);
    }
    else
    {
        cout << "Invalid mode selected." << endl;
    }
    return 0;
}
