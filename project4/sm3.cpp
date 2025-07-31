#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <sstream> 
#include <chrono>
#include <random>

// SM3算法实现
class SM3 {
public:
    SM3() {
        reset();
    }

    // 重置哈希状态
    void reset() {
        // 初始IV值
        state[0] = 0x7380166F;
        state[1] = 0x4914B2B9;
        state[2] = 0x172442D7;
        state[3] = 0xDA8A0600;
        state[4] = 0xA96F30BC;
        state[5] = 0x163138AA;
        state[6] = 0xE38DEE4D;
        state[7] = 0xB0FB0E4E;

        total_len = 0;
        buffer_len = 0;
    }

    // 更新哈希计算
    void update(const uint8_t* data, size_t len) {
        total_len += len;

        // 如果缓冲区有数据且新数据足够填满一个块
        if (buffer_len > 0 && buffer_len + len >= BLOCK_SIZE) {
            size_t fill_len = BLOCK_SIZE - buffer_len;
            memcpy(buffer + buffer_len, data, fill_len);
            process_block(buffer);
            data += fill_len;
            len -= fill_len;
            buffer_len = 0;
        }

        // 处理完整块
        while (len >= BLOCK_SIZE) {
            process_block(data);
            data += BLOCK_SIZE;
            len -= BLOCK_SIZE;
        }

        // 剩余数据存入缓冲区
        if (len > 0) {
            memcpy(buffer + buffer_len, data, len);
            buffer_len += len;
        }
    }

    // 完成哈希计算，返回结果
    std::vector<uint8_t> final() {
        // 计算填充
        uint64_t bit_len = total_len * 8;
        size_t pad_len = (buffer_len < 56) ? (56 - buffer_len) : (120 - buffer_len);

        uint8_t padding[64] = { 0 };
        padding[0] = 0x80;

        update(padding, pad_len);

        // 添加长度
        uint8_t length[8];
        for (int i = 0; i < 8; ++i) {
            length[i] = (bit_len >> (56 - i * 8)) & 0xFF;
        }
        update(length, 8);

        // 返回结果
        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }

        reset();
        return digest;
    }

private:
    static const size_t BLOCK_SIZE = 64; // 512 bits

    uint32_t state[8]; // 哈希状态
    uint64_t total_len; // 总消息长度(字节)
    size_t buffer_len; // 缓冲区长度
    uint8_t buffer[BLOCK_SIZE]; // 消息缓冲区

    // 循环左移
    static uint32_t rotate_left(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    // 布尔函数FFj
    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
        if (j < 16) {
            return x ^ y ^ z;
        }
        else {
            return (x & y) | (x & z) | (y & z);
        }
    }

    // 布尔函数GGj
    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
        if (j < 16) {
            return x ^ y ^ z;
        }
        else {
            return (x & y) | ((~x) & z);
        }
    }

    // 置换函数P0
    static uint32_t P0(uint32_t x) {
        return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
    }

    // 置换函数P1
    static uint32_t P1(uint32_t x) {
        return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
    }

    // 处理一个512位块
    void process_block(const uint8_t* block) {
        // 消息扩展
        uint32_t W[68];
        uint32_t W1[64];

        // 将块分成16个32位字
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        // 扩展其余部分
        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15))
                ^ rotate_left(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 压缩函数
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        // 常量Tj
        const uint32_t T[64] = {
            0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
            0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
            0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
            0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
            0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
        };

        // 迭代压缩
        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T[j], j), 7);
            uint32_t SS2 = SS1 ^ rotate_left(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = rotate_left(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotate_left(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }
};

// 辅助函数：将字节数组转换为十六进制字符串
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// 效率测试函数
void performance_test() {
    SM3 sm3;
    const size_t TEST_SIZE = 1024 * 1024 * 100; // 测试100MB数据
    const int ITERATIONS = 10; // 重复测试次数

    // 生成随机测试数据
    std::vector<uint8_t> test_data(TEST_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : test_data) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    std::cout << "开始SM3性能测试 (" << (TEST_SIZE / (1024 * 1024)) << "MB数据)..." << std::endl;

    double total_time = 0;
    double min_time = std::numeric_limits<double>::max();
    double max_time = 0;

    for (int i = 0; i < ITERATIONS; ++i) {
        auto start = std::chrono::high_resolution_clock::now();

        sm3.reset();
        sm3.update(test_data.data(), test_data.size());
        auto hash = sm3.final(); // 确保结果被使用，防止编译器优化

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        double seconds = elapsed.count();

        total_time += seconds;
        min_time = std::min(min_time, seconds);
        max_time = std::max(max_time, seconds);

        std::cout << "迭代 " << i + 1 << ": " << seconds << " 秒, "
            << (TEST_SIZE / (1024 * 1024 * seconds)) << " MB/s" << std::endl;
    }

    std::cout << "\n性能测试结果:" << std::endl;
    std::cout << "平均速度: " << (TEST_SIZE / (1024 * 1024 * (total_time / ITERATIONS))) << " MB/s" << std::endl;
    std::cout << "最快速度: " << (TEST_SIZE / (1024 * 1024 * min_time)) << " MB/s" << std::endl;
    std::cout << "最慢速度: " << (TEST_SIZE / (1024 * 1024 * max_time)) << " MB/s" << std::endl;
    std::cout << "总时间: " << total_time << " 秒 (" << ITERATIONS << " 次迭代)" << std::endl;
}

int main() {
    // 测试SM3实现
    SM3 sm3;

    // 测试空字符串
    std::vector<uint8_t> empty;
    auto hash = sm3.final();
    std::cout << "SM3(\"\") = " << bytes_to_hex(hash) << std::endl;

    // 测试"abc"
    sm3.reset();
    std::string abc = "abc";
    sm3.update(reinterpret_cast<const uint8_t*>(abc.data()), abc.size());
    hash = sm3.final();
    std::cout << "SM3(\"abc\") = " << bytes_to_hex(hash) << std::endl;

    // 测试长字符串
    sm3.reset();
    std::string long_str(1000, 'a'); // 1000个'a'
    sm3.update(reinterpret_cast<const uint8_t*>(long_str.data()), long_str.size());
    hash = sm3.final();
    std::cout << "SM3(\"" << long_str.substr(0, 10) << "...\") = " << bytes_to_hex(hash) << std::endl;

    std::cout << "\n-------- 开始效率测试 --------" << std::endl;
    performance_test();

    return 0;
}