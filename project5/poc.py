import hashlib
import secrets
from typing import Tuple, Optional


class SM2:
    # 初始化参数（省略部分常量定义）
    def __init__(self):
        self.p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
        self.a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
        self.b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
        self.n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
        self.G = (0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
                  0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2)

    # 有限域运算（省略部分方法）
    def inv(self, a: int, n: int) -> int:
        """模逆"""
        if a == 0: return 0
        lm, hm = 1, 0
        low, high = a % n, n
        while low > 1:
            r = high // low
            nm = hm - lm * r
            new = high - low * r
            hm, lm = lm, nm
            high, low = low, new
        return lm % n

    # 椭圆曲线运算（省略点加和点乘方法）
    def add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """点加"""
        if P is None: return Q
        if Q is None: return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 != y2: return None
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * self.inv(2 * y1, self.p) % self.p
        else:
            lam = (y2 - y1) * self.inv(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """标量乘法"""
        R = None
        Q = P
        while k > 0:
            if k % 2 == 1: R = self.add(R, Q)
            Q = self.add(Q, Q)
            k = k // 2
        return R

    # 辅助函数
    def sm3_hash(self, data: bytes) -> bytes:
        """简化版SM3（实际应用应替换为真实SM3）"""
        return hashlib.sha256(data).digest()

    def compute_ZA(self, IDA: bytes, P: Tuple[int, int]) -> bytes:
        """计算ZA"""
        entlA = len(IDA) * 8
        ENTL = entlA.to_bytes(2, 'big')
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        xG, yG = self.G
        xG_bytes = xG.to_bytes(32, 'big')
        yG_bytes = yG.to_bytes(32, 'big')
        xA, yA = P
        xA_bytes = xA.to_bytes(32, 'big')
        yA_bytes = yA.to_bytes(32, 'big')
        data = ENTL + IDA + a_bytes + b_bytes + xG_bytes + yG_bytes + xA_bytes + yA_bytes
        return self.sm3_hash(data)

    # 签名相关方法
    def sign(self, d: int, M: bytes, IDA: bytes = b'1234567812345678') -> Tuple[int, int]:
        """标准签名"""
        ZA = self.compute_ZA(IDA, self.mul(d, self.G))
        return self.sign_with_za(d, M, ZA)

    def sign_with_za(self, d: int, M: bytes, ZA: bytes) -> Tuple[int, int]:
        """使用预计算ZA签名"""
        k = secrets.randbelow(self.n - 1) + 1
        return self.sign_with_k(d, M, ZA, k)

    def sign_with_k(self, d: int, M: bytes, ZA: bytes, k: int) -> Tuple[int, int]:
        """使用指定k值签名（用于攻击演示）"""
        M_ = ZA + M
        e = int.from_bytes(self.sm3_hash(M_), 'big')
        x1, _ = self.mul(k, self.G)
        r = (e + x1) % self.n
        if r == 0 or r + k == self.n:
            raise ValueError("Bad k value")
        s = (self.inv(1 + d, self.n) * (k - r * d)) % self.n
        if s == 0:
            raise ValueError("Bad k value")
        return (r, s)

    def verify(self, P: Tuple[int, int], M: bytes, signature: Tuple[int, int],
               IDA: bytes = b'1234567812345678') -> bool:
        """验证签名"""
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        ZA = self.compute_ZA(IDA, P)
        M_ = ZA + M
        e = int.from_bytes(self.sm3_hash(M_), 'big')
        t = (r + s) % self.n
        if t == 0:
            return False
        sG = self.mul(s, self.G)
        tP = self.mul(t, P)
        x1, _ = self.add(sG, tP)
        R = (e + x1) % self.n
        return R == r

    # 攻击演示方法
    def reuse_k_attack_demo(self):
        """情况1：同一用户重用k值"""
        d, P = self.key_gen()
        IDA = b'Alice_ID_123'

        # 生成两个不同消息的签名（使用相同k）
        k = secrets.randbelow(self.n - 1) + 1
        ZA = self.compute_ZA(IDA, P)
        r1, s1 = self.sign_with_k(d, b"Message 1", ZA, k)
        r2, s2 = self.sign_with_k(d, b"Message 2", ZA, k)

        # 计算私钥d
        numerator = (s2 - s1) % self.n
        denominator = (s1 - s2 + r1 - r2) % self.n
        d_recovered = (numerator * self.inv(denominator, self.n)) % self.n

        print("\n-------- 情况1：同一用户重用k值 --------")
        print(f"原始私钥: {hex(d)}")
        print(f"恢复私钥: {hex(d_recovered)}")
        print(f"恢复成功: {d == d_recovered}")

    def same_k_diff_users_attack_demo(self):
        """情况2：不同用户使用相同k值"""
        dA, PA = self.key_gen()
        dB, PB = self.key_gen()
        IDA = b'Alice_ID_123'
        IDB = b'Bob_ID_456'

        # 相同k值
        k = secrets.randbelow(self.n - 1) + 1

        # 用户A签名
        ZA = self.compute_ZA(IDA, PA)
        r1, s1 = self.sign_with_k(dA, b"Message from Alice", ZA, k)

        # 用户B签名
        ZB = self.compute_ZA(IDB, PB)
        r2, s2 = self.sign_with_k(dB, b"Message from Bob", ZB, k)

        # 恢复私钥dA
        numerator_a = (k - s1) % self.n
        denominator_a = (s1 + r1) % self.n
        dA_recovered = (numerator_a * self.inv(denominator_a, self.n)) % self.n

        # 恢复私钥dB
        numerator_b = (k - s2) % self.n
        denominator_b = (s2 + r2) % self.n
        dB_recovered = (numerator_b * self.inv(denominator_b, self.n)) % self.n

        print("\n-------- 情况2：不同用户使用相同k值 --------")
        print(f"Alice原始私钥: {hex(dA)}")
        print(f"Alice恢复私钥: {hex(dA_recovered)}")
        print(f"Bob原始私钥: {hex(dB)}")
        print(f"Bob恢复私钥: {hex(dB_recovered)}")
        print(f"恢复成功: {dA == dA_recovered and dB == dB_recovered}")

    def ecdsa_sm2_same_dk_attack_demo(self):
        """情况3：与ECDSA使用相同d和k"""
        d, P = self.key_gen()
        IDA = b'User_ID_123'

        # 相同k值
        k = secrets.randbelow(self.n - 1) + 1

        # ECDSA签名
        msg_ecdsa = b"ECDSA Message"
        e_hash = int.from_bytes(self.sm3_hash(msg_ecdsa), 'big')
        x1, _ = self.mul(k, self.G)
        r1 = x1 % self.n
        s1 = (e_hash + r1 * d) * self.inv(k, self.n) % self.n

        # SM2签名
        ZA = self.compute_ZA(IDA, P)
        r2, s2 = self.sign_with_k(d, b"SM2 Message", ZA, k)

        # 恢复私钥
        numerator = (s1 * s2 - e_hash) % self.n
        denominator = (r1 - s1 * s2 - s1 * r2) % self.n
        d_recovered = (numerator * self.inv(denominator, self.n)) % self.n

        print("\n-------- 情况3：与ECDSA使用相同d和k --------")
        print(f"原始私钥: {hex(d)}")
        print(f"恢复私钥: {hex(d_recovered)}")
        print(f"恢复成功: {d == d_recovered}")

    def signature_malleability_demo(self):
        """情况4：签名可延展性"""
        d, P = self.key_gen()
        M = b"Test message"
        IDA = b'123456789'

        # 正常签名
        r, s = self.sign(d, M, IDA)

        # 修改签名
        s_neg = (-s) % self.n

        # 验证两个签名
        valid1 = self.verify(P, M, (r, s), IDA)
        valid2 = self.verify(P, M, (r, s_neg), IDA)

        print("\n-------- 情况4：签名可延展性 --------")
        print(f"原始签名(r,s): {(hex(r), hex(s))}")
        print(f"修改后签名(r,-s): {(hex(r), hex(s_neg))}")
        print(f"原始签名验证: {valid1}")
        print(f"修改后签名验证: {valid2}")

    def key_gen(self) -> Tuple[int, Tuple[int, int]]:
        """生成密钥对"""
        d = secrets.randbelow(self.n - 1) + 1
        P = self.mul(d, self.G)
        return (d, P)


# 运行所有演示
if __name__ == "__main__":
    sm2 = SM2()
    sm2.reuse_k_attack_demo()
    sm2.same_k_diff_users_attack_demo()
    sm2.ecdsa_sm2_same_dk_attack_demo()
    sm2.signature_malleability_demo()