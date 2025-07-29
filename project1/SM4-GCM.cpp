/*project1.b.
*
* SM4-GCM.cpp：实现了基于SM4分组密码的GCM工作模式，包含加密、解密和认证功能。
* GHASH类：实现Galois域认证乘法及认证标签计算;
* ctr_crypt()：CTR计数器模式加密/解密（调用sm4_crypt）;
* sm4_gcm_encrypt()：对明文进行GCM加密，输出密文和认证标签；
* sm4_gcm_decrypt()：对密文进行GCM解密并验证标签，返回认证结果。
* 编译方式：g++ -O3 -march=native -maes SM4-GCM.cpp -o SM4-GCM
*
* 22密码2班 梁钰舜 202200460175
*
*/

#include <iostream>
#include <vector>
#include <cstring>
#include <immintrin.h>
#include <wmmintrin.h>
#include <chrono>
#include <random>
#include <stdexcept>

using namespace std;

// 类型定义
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

// SM4常量定义
constexpr u32 FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
constexpr u32 CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// SM4 S盒
constexpr u8 SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// ==================== SM4核心实现 ====================
inline u32 rotl(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

u32 T_table[4][256];
u32 T_prime_table[256];

void init_tables() {
    for (int i = 0; i < 256; ++i) {
        u32 b = SBOX[i];
        u32 val = (b << 24) | (b << 16) | (b << 8) | b;
        T_table[0][i] = val;
        T_table[1][i] = rotl(val, 2);
        T_table[2][i] = rotl(val, 10);
        T_table[3][i] = rotl(val, 18) ^ rotl(val, 24);

        T_prime_table[i] = val ^ rotl(val, 13) ^ rotl(val, 23);
    }
}

inline u32 T(u32 x) {
    return T_table[0][(x >> 24) & 0xFF] ^
        T_table[1][(x >> 16) & 0xFF] ^
        T_table[2][(x >> 8) & 0xFF] ^
        T_table[3][x & 0xFF];
}

inline u32 T_prime(u32 x) {
    return T_prime_table[(x >> 24) & 0xFF] ^
        T_prime_table[(x >> 16) & 0xFF] ^
        T_prime_table[(x >> 8) & 0xFF] ^
        T_prime_table[x & 0xFF];
}

void key_schedule(const u8 key[16], u32 rk[32]) {
    u32 mk[4];
    for (int i = 0; i < 4; ++i) {
        mk[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    u32 k[36];
    for (int i = 0; i < 4; ++i) {
        k[i] = mk[i] ^ FK[i];
    }

    for (int i = 0; i < 32; ++i) {
        k[i + 4] = k[i] ^ T_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        rk[i] = k[i + 4];
    }
}

void sm4_round(u32 x[4], const u32 rk) {
    u32 tmp = x[1] ^ x[2] ^ x[3] ^ rk;
    tmp = T(tmp);
    x[0] ^= tmp;

    u32 t = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = t;
}

void sm4_crypt(const u8 in[16], u8 out[16], const u32 rk[32], bool encrypt) {
    u32 x[4];
    for (int i = 0; i < 4; ++i) {
        x[i] = (in[4 * i] << 24) | (in[4 * i + 1] << 16) | (in[4 * i + 2] << 8) | in[4 * i + 3];
    }

    if (encrypt) {
        for (int i = 0; i < 32; ++i) {
            sm4_round(x, rk[i]);
        }
    }
    else {
        for (int i = 31; i >= 0; --i) {
            sm4_round(x, rk[i]);
        }
    }

    u32 tmp = x[0];
    x[0] = x[3];
    x[3] = tmp;
    tmp = x[1];
    x[1] = x[2];
    x[2] = tmp;

    for (int i = 0; i < 4; ++i) {
        out[4 * i] = (x[i] >> 24) & 0xFF;
        out[4 * i + 1] = (x[i] >> 16) & 0xFF;
        out[4 * i + 2] = (x[i] >> 8) & 0xFF;
        out[4 * i + 3] = x[i] & 0xFF;
    }
}

// ==================== GCM实现 ====================
class GHASH {
    u8 H[16];
    alignas(16) u8 table[16][256][16]; // 按字节存储并保证内存对齐

public:
    explicit GHASH(const u8 hash_key[16]) {
        // 初始化H
        memcpy(H, hash_key, 16);

        // 清零表
        memset(table, 0, sizeof(table));

        // 预计算乘法表
        for (int i = 0; i < 16; ++i) {
            u8 v[16] = { 0 };
            v[15 - i] = 1;  // 设置对应位置的位

            for (int j = 1; j < 256; ++j) {
                // 左移1位
                u8 carry = 0;
                for (int k = 15; k >= 0; --k) {
                    u16 val = (v[k] << 1) | carry;
                    v[k] = val & 0xFF;
                    carry = val >> 8;
                }

                // 模约简 (多项式x^128 + x^7 + x^2 + x + 1)
                if (carry) {
                    for (int k = 0; k < 16; ++k) {
                        v[k] ^= H[k];
                    }
                    v[15] ^= 0xE1;  // x^128 mod poly = x^7 + x^2 + x + 1
                }

                // 存储到表
                memcpy(table[i][j], v, 16);
            }
        }
    }

    void multiply(u8 x[16]) {
        u8 result[16] = { 0 };

        for (int i = 0; i < 16; ++i) {
            u8 byte = x[i];
            if (byte == 0) continue;

            // 直接访问预计算的字节数组
            const u8* entry = table[15 - i][byte];
            for (int j = 0; j < 16; ++j) {
                result[j] ^= entry[j];
            }
        }

        memcpy(x, result, 16);
    }
};
void increment_counter(u8 ctr[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++ctr[i] != 0) break;
    }
}

void ctr_crypt(const u8* in, u8* out, size_t len, const u8 iv[12], const u32 rk[32]) {
    u8 ctr[16];
    memcpy(ctr, iv, 12);
    memset(ctr + 12, 0, 4);

    u8 keystream[16];
    for (size_t i = 0; i < len; i += 16) {
        sm4_crypt(ctr, keystream, rk, true);

        size_t block_len = min((size_t)16, len - i);
        for (size_t j = 0; j < block_len; ++j) {
            out[i + j] = in[i + j] ^ keystream[j];
        }

        increment_counter(ctr);
    }
}

void sm4_gcm_encrypt(
    const u8* plaintext, size_t plaintext_len,
    const u8* aad, size_t aad_len,
    const u8* key, const u8* iv,
    u8* ciphertext, u8 tag[16]
) {
    // 初始化SM4
    u32 rk[32];
    key_schedule(key, rk);

    // 计算H = E(K, 0^128)
    u8 H[16] = { 0 };
    sm4_crypt(H, H, rk, true);
    GHASH ghash(H);

    // 初始化计数器
    u8 ctr[16];
    memcpy(ctr, iv, 12);
    ctr[12] = ctr[13] = ctr[14] = 0;
    ctr[15] = 1;

    // CTR模式加密
    ctr_crypt(plaintext, ciphertext, plaintext_len, iv, rk);

    // 计算认证标签
    u8 auth_data[16] = { 0 };

    // AAD长度(64位) || 密文长度(64位)
    u64 len_bits[2] = {
        (u64)aad_len * 8,
        (u64)plaintext_len * 8
    };

    // 处理AAD
    for (size_t i = 0; i < aad_len; i += 16) {
        u8 block[16] = { 0 };
        size_t block_len = min((size_t)16, aad_len - i);
        memcpy(block, aad + i, block_len);

        for (int j = 0; j < 16; ++j) {
            auth_data[j] ^= block[j];
        }
        ghash.multiply(auth_data);
    }

    // 处理密文
    for (size_t i = 0; i < plaintext_len; i += 16) {
        u8 block[16] = { 0 };
        size_t block_len = min((size_t)16, plaintext_len - i);
        memcpy(block, ciphertext + i, block_len);

        for (int j = 0; j < 16; ++j) {
            auth_data[j] ^= block[j];
        }
        ghash.multiply(auth_data);
    }

    // 处理长度域
    for (int i = 0; i < 16; ++i) {
        u8 byte = i < 8 ? ((u8*)len_bits)[7 - i] : ((u8*)len_bits)[15 - i];
        auth_data[i] ^= byte;
    }
    ghash.multiply(auth_data);

    // 计算最终标签
    u8 s[16];
    ctr[15] = 0;
    sm4_crypt(ctr, s, rk, true);

    for (int i = 0; i < 16; ++i) {
        tag[i] = auth_data[i] ^ s[i];
    }
}

bool sm4_gcm_decrypt(
    const u8* ciphertext, size_t ciphertext_len,
    const u8* aad, size_t aad_len,
    const u8* key, const u8* iv,
    const u8 tag[16], u8* plaintext
) {
    // 初始化SM4
    u32 rk[32];
    key_schedule(key, rk);

    // 计算H = E(K, 0^128)
    u8 H[16] = { 0 };
    sm4_crypt(H, H, rk, true);
    GHASH ghash(H);

    // 计算认证标签
    u8 auth_data[16] = { 0 };

    // AAD长度(64位) || 密文长度(64位)
    u64 len_bits[2] = {
        (u64)aad_len * 8,
        (u64)ciphertext_len * 8
    };

    // 处理AAD
    for (size_t i = 0; i < aad_len; i += 16) {
        u8 block[16] = { 0 };
        size_t block_len = min((size_t)16, aad_len - i);
        memcpy(block, aad + i, block_len);

        for (int j = 0; j < 16; ++j) {
            auth_data[j] ^= block[j];
        }
        ghash.multiply(auth_data);
    }

    // 处理密文
    for (size_t i = 0; i < ciphertext_len; i += 16) {
        u8 block[16] = { 0 };
        size_t block_len = min((size_t)16, ciphertext_len - i);
        memcpy(block, ciphertext + i, block_len);

        for (int j = 0; j < 16; ++j) {
            auth_data[j] ^= block[j];
        }
        ghash.multiply(auth_data);
    }

    // 处理长度域
    for (int i = 0; i < 16; ++i) {
        u8 byte = i < 8 ? ((u8*)len_bits)[7 - i] : ((u8*)len_bits)[15 - i];
        auth_data[i] ^= byte;
    }
    ghash.multiply(auth_data);

    // 验证标签
    u8 s[16];
    u8 ctr[16];
    memcpy(ctr, iv, 12);
    ctr[12] = ctr[13] = ctr[14] = ctr[15] = 0;
    sm4_crypt(ctr, s, rk, true);

    u8 computed_tag[16];
    for (int i = 0; i < 16; ++i) {
        computed_tag[i] = auth_data[i] ^ s[i];
    }

    // 比较标签
    bool tag_valid = true;
    for (int i = 0; i < 16; ++i) {
        if (computed_tag[i] != tag[i]) {
            tag_valid = false;
            break;
        }
    }

    if (!tag_valid) {
        return false;
    }

    // 解密数据
    ctr_crypt(ciphertext, plaintext, ciphertext_len, iv, rk);
    return true;
}

// ==================== 测试代码 ====================
void generate_random_data(u8* data, size_t size) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<u8>(dis(gen));
    }
}

void print_hex(const u8* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 4 == 0) printf(" ");
    }
    if (size % 16 != 0) printf("\n");
}

void test_sm4_gcm() {
    // 测试数据
    u8 key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    u8 iv[12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b };

    const size_t plaintext_len = 64;
    u8 plaintext[plaintext_len];
    generate_random_data(plaintext, plaintext_len);

    const size_t aad_len = 32;
    u8 aad[aad_len];
    generate_random_data(aad, aad_len);

    // 加密
    u8 ciphertext[plaintext_len];
    u8 tag[16];

    sm4_gcm_encrypt(plaintext, plaintext_len, aad, aad_len, key, iv, ciphertext, tag);

    cout << "Encryption successful!\n";
    cout << "Tag: ";
    print_hex(tag, 16);

    // 解密
    u8 decrypted[plaintext_len];
    bool success = sm4_gcm_decrypt(ciphertext, plaintext_len, aad, aad_len, key, iv, tag, decrypted);

    if (success) {
        cout << "Decryption successful!\n";

        // 验证解密结果
        if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
            cout << "Plaintext matches decrypted data!\n";
        }
        else {
            cout << "Plaintext does NOT match decrypted data!\n";
        }
    }
    else {
        cout << "Decryption failed: tag verification failed!\n";
    }

    // 测试篡改检测
    ciphertext[0] ^= 0x01; // 修改第一个字节
    success = sm4_gcm_decrypt(ciphertext, plaintext_len, aad, aad_len, key, iv, tag, decrypted);
    cout << "Tamper detection test: " << (success ? "FAILED" : "PASSED") << "\n";
}

int main() {
    init_tables();
    test_sm4_gcm();
    return 0;
}