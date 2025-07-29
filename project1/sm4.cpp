/*project1.a0.
* 
* sm4.cpp：SM4基础的软件实现。我们定义并设计了循环移位函数rotl()、加解密合成变换T()、
* 密钥扩展合成变换T_prime()、密钥扩展函数key_schedule()、解密函数sm4_crypt()；
* 另外我们设计了对于SM4软件实现的正确性测试，随机生成明文和密钥，通过对加密后的解密结果
* 与原始明文的对比来验证是否正确；
* 以及性能测试，对于随机生成的大量明文进行加密，测算单次加密用时，及其吞吐量（用MB/s表示）。
* 注：我们实现了加解密功能，但在测试中没有输出具体的案例，如有必要可以选择输出。
* 
* 22密码2班 梁钰舜 202200460175
* 
*/

#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <cstring>
#include <immintrin.h>

// 类型定义
using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

// 系统参数 FK 和 CK（常量轮密钥）
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

// S盒
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

// 循环左移函数
inline u32 rotl(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 合成变换T：非线性变换τ + 线性变换L
inline u32 T(u32 x) {
    // 非线性变换τ (S盒替换)
    u32 b = (SBOX[(x >> 24) & 0xFF] << 24) |
        (SBOX[(x >> 16) & 0xFF] << 16) |
        (SBOX[(x >> 8) & 0xFF] << 8) |
        (SBOX[x & 0xFF]);

    // 线性变换L
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
}

// 密钥扩展使用的合成变换T'
inline u32 T_prime(u32 x) {
    // 非线性变换τ (S盒替换)
    u32 b = (SBOX[(x >> 24) & 0xFF] << 24) |
        (SBOX[(x >> 16) & 0xFF] << 16) |
        (SBOX[(x >> 8) & 0xFF] << 8) |
        (SBOX[x & 0xFF]);

    // 线性变换L'
    return b ^ rotl(b, 13) ^ rotl(b, 23);
}

// 密钥扩展函数
void key_schedule(const u8 key[16], u32 rk[32]) {
    u32 mk[4];
    // 将16字节密钥转换为4个字
    for (int i = 0; i < 4; ++i) {
        mk[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    // 中间密钥K
    u32 k[36];
    for (int i = 0; i < 4; ++i) {
        k[i] = mk[i] ^ FK[i];
    }

    // 生成轮密钥
    for (int i = 0; i < 32; ++i) {
        k[i + 4] = k[i] ^ T_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        rk[i] = k[i + 4];
    }
}

// 一轮加密/解密
inline void sm4_round(u32 x[4], const u32 rk) {
    u32 tmp = x[1] ^ x[2] ^ x[3] ^ rk;
    tmp = T(tmp);
    x[0] ^= tmp;

    // 循环左移
    u32 t = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = t;
}

// SM4加密/解密函数
void sm4_crypt(const u8 in[16], u8 out[16], const u32 rk[32], bool encrypt) {
    u32 x[4];

    // 输入转换为4个字
    for (int i = 0; i < 4; ++i) {
        x[i] = (in[4 * i] << 24) | (in[4 * i + 1] << 16) | (in[4 * i + 2] << 8) | in[4 * i + 3];
    }

    // 32轮迭代
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

    // 逆序变换
    u32 tmp = x[0];
    x[0] = x[3];
    x[3] = tmp;
    tmp = x[1];
    x[1] = x[2];
    x[2] = tmp;

    // 输出转换回字节
    for (int i = 0; i < 4; ++i) {
        out[4 * i] = (x[i] >> 24) & 0xFF;
        out[4 * i + 1] = (x[i] >> 16) & 0xFF;
        out[4 * i + 2] = (x[i] >> 8) & 0xFF;
        out[4 * i + 3] = x[i] & 0xFF;
    }
}

// 生成随机数据
void generate_random_data(u8* data, size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<u8>(dis(gen));
    }
}

// 打印十六进制数据
void print_hex(const u8* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 4 == 0) printf(" ");
    }
    if (size % 16 != 0) printf("\n");
}

// 正确性测试
bool correctness_test() {
    u8 key[16];
    u8 plaintext[16];
    u8 ciphertext[16];
    u8 decrypted[16];

    // 生成随机密钥和明文
    generate_random_data(key, 16);
    generate_random_data(plaintext, 16);

    // 密钥扩展
    u32 rk[32];
    key_schedule(key, rk);

    // 加密
    sm4_crypt(plaintext, ciphertext, rk, true);

    // 解密
    sm4_crypt(ciphertext, decrypted, rk, false);

    // 比较解密结果与原始明文
    if (memcmp(plaintext, decrypted, 16) != 0) {
        std::cerr << "Correctness test failed!\n";
        std::cout << "Original plaintext:\n";
        print_hex(plaintext, 16);
        std::cout << "Decrypted plaintext:\n";
        print_hex(decrypted, 16);
        return false;
    }

    std::cout << "Correctness test passed!\n";
    return true;
}

// 性能测试
void performance_test() {
    const int NUM_ITERATIONS = 1000000;
    u8 key[16];
    u8 plaintext[16];
    u8 ciphertext[16];

    // 生成随机密钥和明文
    generate_random_data(key, 16);
    generate_random_data(plaintext, 16);

    // 密钥扩展
    u32 rk[32];
    key_schedule(key, rk);

    // 预热缓存
    for (int i = 0; i < 1000; ++i) {
        sm4_crypt(plaintext, ciphertext, rk, true);
    }

    // 开始计时
    auto start = std::chrono::high_resolution_clock::now();

    // 执行大量加密操作
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        sm4_crypt(plaintext, ciphertext, rk, true);
    }

    // 结束计时
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // 计算性能指标
    double total_time_sec = duration / 1000000.0;
    double time_per_encryption_ns = (duration * 1000.0) / NUM_ITERATIONS;
    double throughput_mbps = (16 * NUM_ITERATIONS) / (total_time_sec * 1024 * 1024);

    std::cout << "Performance test results:\n";
    std::cout << "Total encryptions: " << NUM_ITERATIONS << "\n";
    std::cout << "Total time: " << total_time_sec << " seconds\n";
    std::cout << "Time per encryption: " << time_per_encryption_ns << " ns\n";
    std::cout << "Throughput: " << throughput_mbps << " MB/s\n";
}

int main() {
    // 进行正确性测试
    if (!correctness_test()) {
        return 1;
    }

    // 进行性能测试
    performance_test();

    return 0;
}