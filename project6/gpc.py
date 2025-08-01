import random
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


# 模拟群运算（实际应用应使用椭圆曲线或大素数域）
class DDHGroup:
    def __init__(self, bits=256):
        self.p = getPrime(bits)  # 大素数
        self.g = self.find_generator()

    def find_generator(self):
        # 简化版：找一个生成元（实际需要更严谨的方法）
        return 2  # 假设2是生成元

    def random_key(self):
        return random.randint(1, self.p - 2)

    def pow(self, x, k):
        return pow(x, k, self.p)


# 模拟加法同态加密（实际应用需用Paillier等）
class AdditiveHomomorphicEncryption:
    def __init__(self):
        self.public_key = "mock_pk"
        self.private_key = "mock_sk"

    def encrypt(self, value):
        # 模拟：返回(value + noise, noise)的元组
        noise = random.randint(1, 100)
        return (value + noise, noise)

    def decrypt(self, ciphertext):
        return ciphertext[0] - ciphertext[1]

    def add(self, c1, c2):
        return (c1[0] + c2[0], c1[1] + c2[1])


# 协议实现
class PrivateIntersectionSum:
    def __init__(self):
        self.group = DDHGroup()
        self.ahe = AdditiveHomomorphicEncryption()

    def hash_to_group(self, item):
        # 模拟哈希到群元素
        h = SHA256.new(str(item).encode()).hexdigest()
        return int(h, 16) % self.group.p

    def run_protocol(self, P1_items, P2_items_with_values):
        # --- Round 1 (P1 -> P2) ---
        k1 = self.group.random_key()
        P1_hashed = [self.group.pow(self.hash_to_group(v), k1) for v in P1_items]
        random.shuffle(P1_hashed)  # 打乱顺序

        # --- Round 2 (P2 -> P1) ---
        k2 = self.group.random_key()
        # P2处理P1发来的数据
        P2_hashed_k1k2 = [self.group.pow(h, k2) for h in P1_hashed]

        # P2处理自己的数据
        P2_hashed_k2 = []
        for w, t in P2_items_with_values:
            hashed_w = self.group.pow(self.hash_to_group(w), k2)
            encrypted_t = self.ahe.encrypt(t)
            P2_hashed_k2.append((hashed_w, encrypted_t))
        random.shuffle(P2_hashed_k2)  # 打乱顺序

        # --- Round 3 (P1 -> P2) ---
        # P1计算交集
        P1_hashed_k1k2 = []
        for h, _ in P2_hashed_k2:
            P1_hashed_k1k2.append(self.group.pow(h, k1))

        intersection_indices = []
        for i, h in enumerate(P1_hashed_k1k2):
            if h in P2_hashed_k1k2:
                intersection_indices.append(i)

        # P1同态求和
        sum_ct = self.ahe.encrypt(0)
        for i in intersection_indices:
            sum_ct = self.ahe.add(sum_ct, P2_hashed_k2[i][1])

        # --- 结果 ---
        intersection_size = len(intersection_indices)
        intersection_sum = self.ahe.decrypt(sum_ct)

        return intersection_size, intersection_sum


# 测试
if __name__ == "__main__":
    protocol = PrivateIntersectionSum()

    # 模拟数据
    P1_ids = [123, "abc", True]
    P2_data = [(123, 10), ("abc", 20), (False, 30)]
    # 预期结果: 交集大小=2 (123和abc), 总和=30

    size, total = protocol.run_protocol(P1_ids, P2_data)
    print(f"交集大小: {size}, 数值总和: {total}")  # 应输出: 交集大小: 2, 数值总和: 300