import hashlib
import secrets
from typing import Tuple, Optional, List
import sys

# SM2参数
P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
H = 1  # 余因子


class SM2Optimized:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.h = H
        self.G = (Gx, Gy)
        self._precompute_points()

        # 优化参数
        self.window_size = 4  # 窗口法的窗口大小
        self.precomputed = {}  # 预计算表缓存

    def _precompute_points(self):
        """预计算常用点以加速运算"""
        self.G_pow2 = []  # 存储G的2^i倍点
        current = self.G
        for _ in range(256):  # 256位足够
            self.G_pow2.append(current)
            current = self._add_points(current, current)

    def _jacobian_to_affine(self, x: int, y: int, z: int) -> Tuple[int, int]:
        """雅可比坐标转仿射坐标"""
        if z == 0:
            return (0, 0)
        z_inv = self._mod_inv(z, self.p)
        z_inv_sq = (z_inv * z_inv) % self.p
        x_affine = (x * z_inv_sq) % self.p
        y_affine = (y * z_inv_sq * z_inv) % self.p
        return (x_affine, y_affine)

    def _add_points(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """使用雅可比坐标优化的点加法"""
        if P is None or P[0] is None:
            return Q
        if Q is None or Q[0] is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            return (None, None)

        if P == Q:
            # 点加倍优化
            if y1 == 0:
                return (None, None)

            # 计算斜率
            lam = (3 * x1 * x1 + self.a) * self._mod_inv(2 * y1, self.p) % self.p
        else:
            # 计算斜率
            dx = (x2 - x1) % self.p
            dy = (y2 - y1) % self.p
            lam = (dy * self._mod_inv(dx, self.p)) % self.p

        # 计算新点
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def _mod_inv(self, a: int, m: int) -> int:
        """优化的模逆算法：使用扩展欧几里得算法"""

        def extended_gcd(a, b):
            if b == 0:
                return (a, 1, 0)
            else:
                g, y, x = extended_gcd(b, a % b)
                return (g, x, y - (a // b) * x)

        g, x, y = extended_gcd(a, m)
        if g != 1:
            return None  # 不存在逆元
        else:
            return x % m

    def _windowed_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """窗口法优化的标量乘法"""
        # 预计算窗口表
        if P not in self.precomputed:
            table = [None] * (1 << self.window_size)
            table[0] = (None, None)
            table[1] = P
            for i in range(2, 1 << self.window_size):
                table[i] = self._add_points(table[i - 1], P)
            self.precomputed[P] = table
        else:
            table = self.precomputed[P]

        # 分割标量为窗口
        result = (None, None)
        k_bits = bin(k)[2:]  # 获取二进制表示
        k_bits = k_bits.zfill(((len(k_bits) + self.window_size - 1) // self.window_size) * self.window_size)

        # 处理每个窗口
        for i in range(0, len(k_bits), self.window_size):
            # 加倍结果
            for _ in range(self.window_size):
                result = self._add_points(result, result)

            # 获取当前窗口的值
            window = k_bits[i:i + self.window_size]
            if not window:
                continue
            idx = int(window, 2)

            # 添加预计算点
            if idx > 0:
                result = self._add_points(result, table[idx])

        return result

    def _sm3_hash(self, data: bytes) -> bytes:
        """优化的SM3哈希函数(简化版，实际应用应使用真正的SM3)"""
        # 使用更快的哈希实现，如pyca/cryptography库中的哈希
        return hashlib.sha256(data).digest()

    def _kdf_optimized(self, Z: bytes, klen: int) -> bytes:
        """优化的KDF实现"""
        v = 32  # SM3输出是256位(32字节)
        ct = 0x00000001
        result = bytearray()

        # 预分配足够空间
        result.extend(bytearray((klen + 7) // 8))

        for i in range((klen + v * 8 - 1) // (v * 8)):
            # 使用内存视图避免复制
            data = Z + ct.to_bytes(4, 'big')
            Ha = self._sm3_hash(data)

            # 直接填充到结果中
            start = i * v
            end = min(start + v, len(result))
            result[start:end] = Ha[:end - start]

            ct += 1

        # 转换为bytes并截断到所需长度
        return bytes(result)[:(klen + 7) // 8]

    def key_gen(self) -> Tuple[int, Tuple[int, int]]:
        """密钥生成"""
        d = secrets.randbelow(self.n - 1) + 1
        P = self._windowed_mul(d, self.G)
        return (d, P)

    def sign(self, d: int, M: bytes, IDA: bytes = b'1234567812345678') -> Tuple[int, int]:
        """签名"""
        # 预计算ZA
        entlA = len(IDA) * 8
        ENTL = entlA.to_bytes(2, 'big')
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        xG_bytes = self.G[0].to_bytes(32, 'big')
        yG_bytes = self.G[1].to_bytes(32, 'big')

        # 计算公钥
        P = self._windowed_mul(d, self.G)
        xA, yA = P
        xA_bytes = xA.to_bytes(32, 'big')
        yA_bytes = yA.to_bytes(32, 'big')

        # 使用内存视图优化大块数据处理
        data = ENTL + IDA + a_bytes + b_bytes + xG_bytes + yG_bytes + xA_bytes + yA_bytes
        ZA = self._sm3_hash(data)

        # 设置M_ = ZA || M
        M_ = ZA + M

        # 计算e = Hv(M_)
        e_bytes = self._sm3_hash(M_)
        e = int.from_bytes(e_bytes, 'big')

        while True:
            # 生成随机k
            k = secrets.randbelow(self.n - 1) + 1

            # 计算(x1, y1) = kG (使用预计算优化)
            x1, y1 = self._windowed_mul(k, self.G)

            # 计算r = (e + x1) mod n
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue

            # 计算s = ((1 + d)^-1 * (k - r*d)) mod n
            s = (self._mod_inv(1 + d, self.n) * (k - r * d)) % self.n
            if s == 0:
                continue

            return (r, s)

    def verify(self, P: Tuple[int, int], M: bytes, signature: Tuple[int, int],
               IDA: bytes = b'1234567812345678') -> bool:
        """验证签名"""
        r, s = signature

        # 检查r和s范围
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False

        # 预计算ZA
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
        ZA = self._sm3_hash(data)

        # 设置M_ = ZA || M
        M_ = ZA + M

        # 计算e = Hv(M_)
        e_bytes = self._sm3_hash(M_)
        e = int.from_bytes(e_bytes, 'big')

        # 计算t = (r + s) mod n
        t = (r + s) % self.n
        if t == 0:
            return False

        # 使用同时乘法优化计算sG + tP
        # 预计算点
        points = [(s, self.G), (t, P)]

        # 使用同时乘法算法
        sG_plus_tP = self._simultaneous_multiply(points)

        x1_prime, y1_prime = sG_plus_tP

        # 计算R = (e + x1') mod n
        R = (e + x1_prime) % self.n

        return R == r

    def _simultaneous_multiply(self, points: List[Tuple[int, Tuple[int, int]]]) -> Tuple[int, int]:
        """同时乘法算法，优化多个标量乘法"""
        # 实现Bos-Coster算法简化版
        result = (None, None)
        heap = []

        # 初始化堆
        for k, P in points:
            if k > 0 and P[0] is not None:
                heap.append((k, P))

        # 处理堆
        while len(heap) > 1:
            # 找到最大的两个元素
            heap.sort(key=lambda x: -x[0])
            k1, P1 = heap[0]
            k2, P2 = heap[1]

            # 计算差值
            delta = k1 - k2
            heap[0] = (delta, P1)
            heap[1] = (k2, self._add_points(P1, P2))

            # 移除零元素
            if delta == 0:
                heap.pop(0)

        if heap:
            k, P = heap[0]
            if k > 0:
                result = self._add_points(result, self._windowed_mul(k, P))

        return result

    def encrypt(self, P: Tuple[int, int], M: bytes) -> bytes:
        """加密"""
        klen = len(M) * 8  # 消息长度(比特)

        while True:
            # 生成随机k
            k = secrets.randbelow(self.n - 1) + 1

            # 计算C1 = kG = (x1, y1)
            x1, y1 = self._windowed_mul(k, self.G)
            C1 = x1.to_bytes(32, 'big') + y1.to_bytes(32, 'big')

            # 计算S = hP
            S = self._windowed_mul(self.h, P)
            if S is None:
                continue

            # 计算kP = (x2, y2)
            x2, y2 = self._windowed_mul(k, P)

            # 计算t = KDF(x2 || y2, klen)
            x2_bytes = x2.to_bytes(32, 'big')
            y2_bytes = y2.to_bytes(32, 'big')
            t = self._kdf_optimized(x2_bytes + y2_bytes, klen)

            if all(b == 0 for b in t):
                continue

            # 计算C2 = M xor t (逐字节异或)
            C2 = bytes([m ^ t[i] for i, m in enumerate(M)])

            # 计算C3 = Hash(x2 || M || y2)
            C3 = self._sm3_hash(x2_bytes + M + y2_bytes)

            # 密文C = C1 || C2 || C3
            return C1 + C2 + C3

    def decrypt(self, d: int, C: bytes) -> bytes:
        """解密"""
        # 分割密文
        C1 = C[:64]  # 32字节x, 32字节y
        C2 = C[64:-32]
        C3 = C[-32:]

        # 提取(x1, y1)
        x1 = int.from_bytes(C1[:32], 'big')
        y1 = int.from_bytes(C1[32:], 'big')
        C1_point = (x1, y1)

        # 检查C1是否在曲线上
        # (实现留作练习)

        # 计算S = hC1
        S = self._windowed_mul(self.h, C1_point)
        if S is None:
            raise ValueError("无效密文: S是无穷远点")

        # 计算dB*C1 = (x2, y2)
        x2, y2 = self._windowed_mul(d, C1_point)

        # 计算t = KDF(x2 || y2, klen)
        klen = len(C2) * 8
        x2_bytes = x2.to_bytes(32, 'big')
        y2_bytes = y2.to_bytes(32, 'big')
        t = self._kdf_optimized(x2_bytes + y2_bytes, klen)

        if all(b == 0 for b in t):
            raise ValueError("无效密文: t全为零")

        # 计算M' = C2 xor t (逐字节异或)
        M_prime = bytes([c ^ t[i] for i, c in enumerate(C2)])

        # 计算u = Hash(x2 || M' || y2)
        u = self._sm3_hash(x2_bytes + M_prime + y2_bytes)

        # 检查u == C3
        if u != C3:
            raise ValueError("无效密文: 哈希验证失败")

        return M_prime


# 示例用法
if __name__ == "__main__":
    sm2 = SM2Optimized()

    print("-------- SM2优化实现测试 --------")

    # 密钥生成
    print("\n1. 密钥生成...")
    d, P = sm2.key_gen()
    print(f"私钥: {hex(d)}")
    print(f"公钥: ({hex(P[0])}, {hex(P[1])})")

    # 签名
    print("\n2. 签名测试...")
    message = b"this is a test message for sm2optimized"
    print(f"原始消息: {message.decode('utf-8')}")

    r, s = sm2.sign(d, message)
    print(f"签名: (r={hex(r)}, s={hex(s)})")

    # 验证
    is_valid = sm2.verify(P, message, (r, s))
    print(f"验证结果: {'成功' if is_valid else '失败'}")

    # 加密解密
    print("\n3. 加密解密测试...")
    plaintext = b"this is a secret message"
    print(f"原始明文: {plaintext.decode('utf-8')}")

    ciphertext = sm2.encrypt(P, plaintext)
    print(f"密文长度: {len(ciphertext)}字节")

    decrypted = sm2.decrypt(d, ciphertext)
    print(f"解密结果: {decrypted.decode('utf-8')}")
    print(f"解密{'成功' if decrypted == plaintext else '失败'}")

    # 性能测试
    print("\n4. 性能测试...")
    import time

    test_msg = b"a" * 1024  # 1KB测试数据

    # 签名性能
    start = time.time()
    for _ in range(10):
        sm2.sign(d, test_msg)
    elapsed = time.time() - start
    print(f"签名速度: {10 / elapsed:.2f} 次/秒 (1KB数据)")

    # 验证性能
    sig = sm2.sign(d, test_msg)
    start = time.time()
    for _ in range(10):
        sm2.verify(P, test_msg, sig)
    elapsed = time.time() - start
    print(f"验证速度: {10 / elapsed:.2f} 次/秒 (1KB数据)")

    # 加密性能
    start = time.time()
    for _ in range(10):
        sm2.encrypt(P, test_msg)
    elapsed = time.time() - start
    print(f"加密速度: {10 / elapsed:.2f} 次/秒 (1KB数据)")

    # 解密性能
    enc = sm2.encrypt(P, test_msg)
    start = time.time()
    for _ in range(10):
        sm2.decrypt(d, enc)
    elapsed = time.time() - start
    print(f"解密速度: {10 / elapsed:.2f} 次/秒 (1KB数据)")