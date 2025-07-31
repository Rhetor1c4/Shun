#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <memory>
#include <cmath>
#include <stdexcept>
#include <cstring>

// SM3哈希算法实现
class SM3 {
public:
    SM3() { reset(); }

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

        reset();
        return digest;
    }

private:
    static const size_t BLOCK_SIZE = 64;
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

// 辅助函数
std::vector<uint8_t> sm3_hash(const std::vector<uint8_t>& data) {
    SM3 sm3;
    sm3.update(data.data(), data.size());
    return sm3.final();
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::vector<uint8_t> concat_hashes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> combined;
    combined.reserve(a.size() + b.size());
    combined.insert(combined.end(), a.begin(), a.end());
    combined.insert(combined.end(), b.begin(), b.end());
    return combined;
}

// RFC6962的Merkle树实现
class MerkleTree {
public:
    explicit MerkleTree(const std::vector<std::vector<uint8_t>>& leaves) {
        if (leaves.empty()) {
            throw std::invalid_argument("At least one leaf is required");
        }

        // 构建叶子节点层
        tree_levels_.emplace_back();
        for (const auto& leaf : leaves) {
            tree_levels_[0].push_back(sm3_hash(leaf));
        }

        // 构建中间节点层
        while (tree_levels_.back().size() > 1) {
            const auto& current_level = tree_levels_.back();
            std::vector<std::vector<uint8_t>> next_level;

            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    next_level.push_back(sm3_hash(concat_hashes(current_level[i], current_level[i + 1])));
                }
                else {
                    // 奇数个节点，复制最后一个
                    next_level.push_back(sm3_hash(concat_hashes(current_level[i], current_level[i])));
                }
            }

            tree_levels_.push_back(next_level);
        }
    }

    // 获取根哈希
    std::vector<uint8_t> get_root_hash() const {
        return tree_levels_.back()[0];
    }

    // 生成存在性证明
    std::vector<std::vector<uint8_t>> generate_inclusion_proof(size_t index) const {
        std::vector<std::vector<uint8_t>> proof;

        if (index >= tree_levels_[0].size()) {
            throw std::out_of_range("Index out of range");
        }

        for (size_t level = 0; level < tree_levels_.size() - 1; ++level) {
            bool is_right = index % 2;
            size_t sibling_index = is_right ? index - 1 : index + 1;

            if (sibling_index < tree_levels_[level].size()) {
                proof.push_back(tree_levels_[level][sibling_index]);
            }
            else {
                // 如果没有右兄弟节点，使用左兄弟节点（RFC6962要求）
                proof.push_back(tree_levels_[level][index - 1]);
            }

            index /= 2;
        }

        return proof;
    }

    // 验证存在性证明
    static bool verify_inclusion_proof(
        const std::vector<uint8_t>& leaf,
        const std::vector<uint8_t>& root_hash,
        const std::vector<std::vector<uint8_t>>& proof,
        size_t index) {

        std::vector<uint8_t> current_hash = sm3_hash(leaf);

        for (size_t i = 0; i < proof.size(); ++i) {
            bool is_right = index % 2;
            index /= 2;

            if (is_right) {
                current_hash = sm3_hash(concat_hashes(proof[i], current_hash));
            }
            else {
                current_hash = sm3_hash(concat_hashes(current_hash, proof[i]));
            }
        }

        return current_hash == root_hash;
    }

    // 生成不存在性证明
    std::pair<std::vector<std::vector<uint8_t>>, std::vector<size_t>>
        generate_exclusion_proof(const std::vector<uint8_t>& non_leaf) const {
        // 1. 计算待证明不存在节点的哈希
        auto non_leaf_hash = sm3_hash(non_leaf);

        // 2. 在叶子层中找到插入位置
        const auto& leaves = tree_levels_[0];
        auto it = std::lower_bound(leaves.begin(), leaves.end(), non_leaf_hash);

        std::vector<size_t> indices;
        std::vector<std::vector<uint8_t>> proof;

        if (it == leaves.end()) {
            // 比所有叶子都大，使用最后一个叶子
            indices.push_back(leaves.size() - 1);
            proof = generate_inclusion_proof(leaves.size() - 1);
        }
        else if (it == leaves.begin()) {
            // 比所有叶子都小，使用第一个叶子
            indices.push_back(0);
            proof = generate_inclusion_proof(0);
        }
        else {
            // 在中间，使用前一个和后一个叶子
            size_t prev_idx = std::distance(leaves.begin(), it) - 1;
            size_t next_idx = prev_idx + 1;

            indices.push_back(prev_idx);
            indices.push_back(next_idx);

            auto prev_proof = generate_inclusion_proof(prev_idx);
            auto next_proof = generate_inclusion_proof(next_idx);

            // 合并两个证明（去重）
            proof = prev_proof;
            for (const auto& h : next_proof) {
                if (std::find(proof.begin(), proof.end(), h) == proof.end()) {
                    proof.push_back(h);
                }
            }
        }

        return { proof, indices };
    }

    // 验证不存在性证明
    static bool verify_exclusion_proof(
        const std::vector<uint8_t>& non_leaf,
        const std::vector<uint8_t>& root_hash,
        const std::vector<std::vector<uint8_t>>& proof,
        const std::vector<size_t>& indices,
        const std::vector<std::vector<uint8_t>>& all_leaves) {

        if (indices.empty()) return false;

        // 验证所有相邻叶子的存在性证明
        for (size_t idx : indices) {
            if (idx >= all_leaves.size()) return false;

            auto leaf_hash = sm3_hash(all_leaves[idx]);
            if (!verify_inclusion_proof(all_leaves[idx], root_hash, proof, idx)) {
                return false;
            }
        }

        // 确保non_leaf确实不存在于这些相邻叶子之间
        auto non_leaf_hash = sm3_hash(non_leaf);
        for (size_t i = 0; i < indices.size() - 1; ++i) {
            if (sm3_hash(all_leaves[indices[i]]) < non_leaf_hash &&
                non_leaf_hash < sm3_hash(all_leaves[indices[i + 1]])) {
                return true;
            }
        }

        return false;
    }

    // 获取所有叶子节点（用于验证）
    const std::vector<std::vector<uint8_t>>& get_leaves() const {
        return tree_levels_[0];
    }

private:
    std::vector<std::vector<std::vector<uint8_t>>> tree_levels_;
};

// 生成随机数据
std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    for (auto& byte : data) {
        byte = static_cast<uint8_t>(rand() % 256);
    }
    return data;
}

int main() {
    try {
        // 设置随机种子
        srand(static_cast<unsigned>(time(nullptr)));

        // 1. 准备10万个叶子节点
        const size_t NUM_LEAVES = 100000;
        std::vector<std::vector<uint8_t>> leaves;
        leaves.reserve(NUM_LEAVES);

        std::cout << "Generating " << NUM_LEAVES << " leaf nodes..." << std::endl;
        for (size_t i = 0; i < NUM_LEAVES; ++i) {
            leaves.push_back(generate_random_data(32)); // 每个叶子32字节
        }

        // 排序叶子节点（RFC6962要求）
        std::sort(leaves.begin(), leaves.end());

        // 2. 构建Merkle树
        std::cout << "Building Merkle tree..." << std::endl;
        MerkleTree tree(leaves);
        auto root_hash = tree.get_root_hash();
        std::cout << "Merkle tree built. Root hash: " << bytes_to_hex(root_hash) << std::endl;

        // 3. 测试存在性证明
        size_t test_index = 12345; // 测试第12345个叶子
        std::cout << "\nTesting inclusion proof for index " << test_index << "..." << std::endl;

        auto inclusion_proof = tree.generate_inclusion_proof(test_index);
        bool is_valid = MerkleTree::verify_inclusion_proof(
            leaves[test_index], root_hash, inclusion_proof, test_index);

        std::cout << "Inclusion proof verification: " << (is_valid ? "SUCCESS" : "FAILED") << std::endl;

        // 4. 测试不存在性证明
        std::vector<uint8_t> non_existent_leaf = generate_random_data(32);
        std::cout << "\nTesting exclusion proof..." << std::endl;

        auto exclusion_result = tree.generate_exclusion_proof(non_existent_leaf);
        bool is_non_existent = MerkleTree::verify_exclusion_proof(
            non_existent_leaf, root_hash, exclusion_result.first,
            exclusion_result.second, tree.get_leaves());

        std::cout << "Exclusion proof verification: " << (is_non_existent ? "SUCCESS" : "FAILED") << std::endl;

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}