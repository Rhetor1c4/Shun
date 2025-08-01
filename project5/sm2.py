import hashlib
import secrets
from typing import Tuple, Optional

# SM2 参数
P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
H = 1

class SM2:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.h = H
        self.G = (Gx, Gy)

    # 有限域运算
    def inv(self, a: int, n: int) -> int:
        """模逆的扩展欧几里得算法"""
        if a == 0:
            return 0
        lm, hm = 1, 0
        low, high = a % n, n
        while low > 1:
            r = high // low
            nm = hm - lm * r
            new = high - low * r
            hm, lm = lm, nm
            high, low = low, new
        return lm % n

    def add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线上的点加法"""
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            return None  # 无穷远点

        if P == Q:
            # 点加倍
            lam = (3 * x1 * x1 + self.a) * self.inv(2 * y1, self.p) % self.p
        else:
            lam = (y2 - y1) * self.inv(x2 - x1, self.p) % self.p

        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:

        R = None
        Q = P

        while k > 0:
            if k % 2 == 1:
                R = self.add(R, Q)
            Q = self.add(Q, Q)
            k = k // 2
        return R

    # SM3 哈希函数（简化版）
    def sm3_hash(self, data: bytes) -> bytes:
        """简化的 SM3 哈希函数（使用 SHA-256 替代）"""

        return hashlib.sha256(data).digest()

    # 密钥派生函数
    def kdf(self, Z: bytes, klen: int) -> bytes:
        """密钥派生函数"""
        v = 32  # SM3 输出为 256 位（32 字节）
        ct = 0x00000001
        Ha_list = []

        for i in range((klen + v - 1) // v):
            # 哈希 Z || ct（以大端序的4字节表示）
            data = Z + ct.to_bytes(4, 'big')
            Ha = self.sm3_hash(data)
            Ha_list.append(Ha)
            ct += 1

        # 连接所有 Ha 块
        K = b''.join(Ha_list)

        # 如果 klen 不是 v 的倍数，则截断
        if klen % v != 0:
            K = K[:klen]
        else:
            K = K[:klen]

        return K

    # SM2 密钥生成
    def key_gen(self) -> Tuple[int, Tuple[int, int]]:
        """生成 SM2 密钥对（私钥，公钥）"""
        d = secrets.randbelow(self.n - 1) + 1
        P = self.mul(d, self.G)
        return (d, P)

    # SM2 签名
    def sign(self, d: int, M: bytes, IDA: bytes = b'1234567812345678') -> Tuple[int, int]:
        """SM2 签名生成"""
        # 预计算 ZA
        entlA = len(IDA) * 8
        ENTL = entlA.to_bytes(2, 'big')
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        xG_bytes = self.G[0].to_bytes(32, 'big')
        yG_bytes = self.G[1].to_bytes(32, 'big')

        # 计算公钥
        P = self.mul(d, self.G)
        xA, yA = P
        xA_bytes = xA.to_bytes(32, 'big')
        yA_bytes = yA.to_bytes(32, 'big')

        # ZA = H256(ENTL || IDA || a || b || xG || yG || xA || yA)
        data = ENTL + IDA + a_bytes + b_bytes + xG_bytes + yG_bytes + xA_bytes + yA_bytes
        ZA = self.sm3_hash(data)

        # M_ = ZA || M
        M_ = ZA + M

        # e = Hv(M_)
        e_bytes = self.sm3_hash(M_)
        e = int.from_bytes(e_bytes, 'big')

        while True:
            # 生成随机数 k
            k = secrets.randbelow(self.n - 1) + 1

            # 计算 (x1, y1) = kG
            x1, y1 = self.mul(k, self.G)

            # 计算 r = (e + x1) mod n
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue  # 重试其他 k

            # 计算 s = ((1 + d)^-1 * (k - r*d)) mod n
            s = (self.inv(1 + d, self.n) * (k - r * d)) % self.n
            if s == 0:
                continue  # 重试其他 k

            return (r, s)

    # SM2 签名验证
    def verify(self, P: Tuple[int, int], M: bytes, signature: Tuple[int, int],
               IDA: bytes = b'1234567812345678') -> bool:
        """SM2 签名验证"""
        r, s = signature

        # 检查 r 和 s 是否在 [1, n-1] 范围内
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False

        # 预计算 ZA（与签名中相同）
        entlA = len(IDA) * 8
        ENTL = entlA.to_bytes(2, 'big')
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        xG_bytes = self.G[0].to_bytes(32, 'big')
        yG_bytes = self.G[1].to_bytes(32, 'big')
        xA, yA = P
        xA_bytes = xA.to_bytes(32, 'big')
        yA_bytes = yA.to_bytes(32, 'big')

        data = ENTL + IDA + a_bytes + b_bytes + xG_bytes + yG_bytes + xA_bytes + yA_bytes
        ZA = self.sm3_hash(data)

        # M_ = ZA || M
        M_ = ZA + M

        # e = Hv(M_)
        e_bytes = self.sm3_hash(M_)
        e = int.from_bytes(e_bytes, 'big')

        # 计算 t = (r + s) mod n
        t = (r + s) % self.n
        if t == 0:
            return False

        # 计算 (x1', y1') = sG + tP
        sG = self.mul(s, self.G)
        tP = self.mul(t, P)
        x1_prime, y1_prime = self.add(sG, tP)

        # 计算 R = (e + x1') mod n
        R = (e + x1_prime) % self.n

        return R == r

    def encrypt(self, P: Tuple[int, int], M: bytes) -> bytes:
        """SM2 加密"""
        klen = len(M) * 8  # 消息长度（以比特为单位）

        while True:
            # 生成随机 k
            k = secrets.randbelow(self.n - 1) + 1

            # 计算 C1 = kG = (x1, y1)
            x1, y1 = self.mul(k, self.G)
            C1 = x1.to_bytes(32, 'big') + y1.to_bytes(32, 'big')

            # 计算 S = hP（h 是倍数因子，通常为 1）
            S = self.mul(self.h, P)
            if S is None:  # 无穷远点
                continue  # 尝试另一个 k

            # 计算 kP = (x2, y2)
            x2, y2 = self.mul(k, P)

            # 计算 t = KDF(x2 || y2, klen)
            x2_bytes = x2.to_bytes(32, 'big')
            y2_bytes = y2.to_bytes(32, 'big')
            t = self.kdf(x2_bytes + y2_bytes, klen)

            if all(b == 0 for b in t):  # t 全为 0
                continue  # 尝试另一个 k

            # 计算 C2 = M xor t（逐字节异或）
            C2 = bytes([m ^ t[i] for i, m in enumerate(M)])

            # 计算 C3 = Hash(x2 || M || y2)
            C3 = self.sm3_hash(x2_bytes + M + y2_bytes)

            # 密文 C = C1 || C2 || C3
            C = C1 + C2 + C3
            return C

    def decrypt(self, d: int, C: bytes) -> bytes:
        """SM2 解密"""
        # 拆分密文
        C1 = C[:64]  # 前 32 字节 x，后 32 字节 y
        C2 = C[64:-32]
        C3 = C[-32:]

        # 从 C1 提取 (x1, y1)
        x1 = int.from_bytes(C1[:32], 'big')
        y1 = int.from_bytes(C1[32:], 'big')
        C1_point = (x1, y1)

        # 检查 C1 是否在椭圆曲线上
        # （实现留作练习）

        # 计算 S = hC1
        S = self.mul(self.h, C1_point)
        if S is None:  # 无穷远点
            raise ValueError("密文无效：S 为无穷远点")

        # 计算 dB*C1 = (x2, y2)
        x2, y2 = self.mul(d, C1_point)

        # 计算 t = KDF(x2 || y2, klen)
        klen = len(C2) * 8
        x2_bytes = x2.to_bytes(32, 'big')
        y2_bytes = y2.to_bytes(32, 'big')
        t = self.kdf(x2_bytes + y2_bytes, klen)

        if all(b == 0 for b in t):  # t 全为 0
            raise ValueError("密文无效：t 全为零")

        # 计算 M' = C2 xor t（逐字节异或）
        M_prime = bytes([c ^ t[i] for i, c in enumerate(C2)])

        # 计算 u = Hash(x2 || M' || y2)
        u = self.sm3_hash(x2_bytes + M_prime + y2_bytes)

        # 检查 u == C3
        if u != C3:
            raise ValueError("密文无效：哈希校验失败")

        return M_prime

# 示例用法
if __name__ == "__main__":
    sm2 = SM2()

    # 密钥生成
    d, P = sm2.key_gen()
    print(f"Private key: {hex(d)}")
    print(f"Public key: ({hex(P[0])}, {hex(P[1])})")

    # 签名
    message = b"Hello, SM2!"
    r, s = sm2.sign(d, message)
    print(f"Signature: (r={hex(r)}, s={hex(s)})")

    # 验证
    is_valid = sm2.verify(P, message, (r, s))
    print(f"Signature valid: {is_valid}")

    # 加解密
    plaintext = b"Secret message"
    ciphertext = sm2.encrypt(P, plaintext)
    decrypted = sm2.decrypt(d, ciphertext)
    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted}")
    print(f"Decryption successful: {decrypted == plaintext}")
