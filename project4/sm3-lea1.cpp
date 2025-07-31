#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

class SM3 {
public:
    SM3() { reset(); }

    // 重置为初始状态
    void reset() {
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

    // 从指定状态初始化（用于长度扩展攻击）
    void reset_from_state(const uint32_t new_state[8], uint64_t known_len) {
        memcpy(state, new_state, sizeof(state));
        total_len = known_len;
        buffer_len = 0;
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;

        if (buffer_len > 0 && buffer_len + len >= BLOCK_SIZE) {
            size_t fill_len = BLOCK_SIZE - buffer_len;
            memcpy(buffer + buffer_len, data, fill_len);
            process_block(buffer);
            data += fill_len;
            len -= fill_len;
            buffer_len = 0;
        }

        while (len >= BLOCK_SIZE) {
            process_block(data);
            data += BLOCK_SIZE;
            len -= BLOCK_SIZE;
        }

        if (len > 0) {
            memcpy(buffer + buffer_len, data, len);
            buffer_len += len;
        }
    }

    std::vector<uint8_t> final() {
        // 计算填充
        uint64_t bit_len = total_len * 8;
        size_t pad_len = (buffer_len < 56) ? (56 - buffer_len) : (120 - buffer_len);

        uint8_t padding[64] = { 0 };
        padding[0] = 0x80;

        update(padding, pad_len);

        uint8_t length[8];
        for (int i = 0; i < 8; ++i) {
            length[i] = (bit_len >> (56 - i * 8)) & 0xFF;
        }
        update(length, 8);

        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }

        return digest;
    }

    // 获取当前内部状态（用于长度扩展攻击）
    void get_state(uint32_t out_state[8]) const {
        memcpy(out_state, state, sizeof(state));
    }

    // 获取消息总长度（用于长度扩展攻击）
    uint64_t get_total_len() const {
        return total_len;
    }

private:
    static const size_t BLOCK_SIZE = 64; // 512 bits

    uint32_t state[8];
    uint64_t total_len;
    size_t buffer_len;
    uint8_t buffer[BLOCK_SIZE];

    static uint32_t rotate_left(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    static uint32_t P0(uint32_t x) {
        return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
    }

    static uint32_t P1(uint32_t x) {
        return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
    }

    void process_block(const uint8_t* block) {
        uint32_t W[68];
        uint32_t W1[64];

        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15))
                ^ rotate_left(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(j < 16 ? 0x79CC4519 : 0x7A879D8A, j), 7);
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

// 字节数组转十六进制字符串
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// 构造填充块
std::vector<uint8_t> create_padding(uint64_t original_len) {
    std::vector<uint8_t> padding;
    uint64_t bit_len = original_len * 8;
    size_t pad_len = (original_len % 64 < 56) ? (56 - original_len % 64) : (120 - original_len % 64);

    padding.push_back(0x80);
    padding.resize(padding.size() + pad_len - 1, 0x00);

    for (int i = 0; i < 8; ++i) {
        padding.push_back((bit_len >> (56 - i * 8)) & 0xFF);
    }

    return padding;
}

// 长度扩展攻击演示
void length_extension_attack() {
    // 原始消息和密钥（密钥对攻击者未知）
    std::string secret_key = "secret";
    std::string original_message = "original_message";

    // 1. 正常计算 Hash(secret_key || original_message)
    SM3 normal_sm3;
    normal_sm3.update(reinterpret_cast<const uint8_t*>(secret_key.data()), secret_key.size());
    normal_sm3.update(reinterpret_cast<const uint8_t*>(original_message.data()), original_message.size());
    std::vector<uint8_t> original_hash = normal_sm3.final();

    std::cout << "原始哈希 (Hash(secret_key || original_message)): \n"
        << bytes_to_hex(original_hash) << "\n\n";

    // 2. 攻击者知道original_message和original_hash，但不知道secret_key
    // 攻击者想要计算 Hash(secret_key || original_message || padding || malicious_extension)

    // 攻击者构造恶意扩展
    std::string malicious_extension = "malicious_extension";

    // 3. 攻击者计算原始消息的总长度（包括密钥）
    uint64_t secret_key_len = secret_key.size();
    uint64_t original_total_len = secret_key_len + original_message.size();

    // 4. 攻击者构造填充块
    std::vector<uint8_t> padding = create_padding(original_total_len);

    // 5. 攻击者从已知哈希中恢复内部状态
    uint32_t recovered_state[8];
    for (int i = 0; i < 8; ++i) {
        recovered_state[i] = (original_hash[i * 4] << 24) |
            (original_hash[i * 4 + 1] << 16) |
            (original_hash[i * 4 + 2] << 8) |
            original_hash[i * 4 + 3];
    }

    // 6. 攻击者使用恢复的状态初始化新的SM3实例
    SM3 malicious_sm3;
    malicious_sm3.reset_from_state(recovered_state,
        original_total_len + padding.size());

    // 7. 攻击者计算扩展部分的哈希
    malicious_sm3.update(reinterpret_cast<const uint8_t*>(malicious_extension.data()),
        malicious_extension.size());
    std::vector<uint8_t> malicious_hash = malicious_sm3.final();

    std::cout << "攻击生成的哈希 (Hash(secret_key || original_message || padding || malicious_extension)): \n"
        << bytes_to_hex(malicious_hash) << "\n\n";

    // 8. 验证攻击是否成功 - 正常计算完整消息的哈希
    SM3 verification_sm3;
    verification_sm3.update(reinterpret_cast<const uint8_t*>(secret_key.data()), secret_key.size());
    verification_sm3.update(reinterpret_cast<const uint8_t*>(original_message.data()), original_message.size());
    verification_sm3.update(padding.data(), padding.size());
    verification_sm3.update(reinterpret_cast<const uint8_t*>(malicious_extension.data()), malicious_extension.size());
    std::vector<uint8_t> expected_hash = verification_sm3.final();

    std::cout << "实际完整哈希 (用于验证): \n"
        << bytes_to_hex(expected_hash) << "\n\n";

    // 比较结果
    if (malicious_hash == expected_hash) {
        std::cout << "攻击成功! 长度扩展攻击验证通过。\n";
    }
    else {
        std::cout << "攻击失败! 哈希值不匹配。\n";
    }
}

int main() {
    try {
        std::cout << "-------- SM3长度扩展攻击验证 --------\n\n";
        length_extension_attack();
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
}