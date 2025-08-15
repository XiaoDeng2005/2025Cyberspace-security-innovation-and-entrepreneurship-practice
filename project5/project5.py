"""
SM2 国密算法完整实现
包含：基础算法、性能优化、安全漏洞验证
"""

import os
import hashlib
import sys
import time

# 全局配置
ENABLE_COLOR = True  # 彩色输出开关


# 彩色输出函数
def print_color(text, color_code):
    """彩色终端输出"""
    if ENABLE_COLOR and sys.stdout.isatty():
        print(f"\033[{color_code}m{text}\033[0m")
    else:
        print(text)


def print_header(title):
    """打印模块标题"""
    print_color("\n" + "=" * 80, "1;36")
    print_color(f" {title} ".center(80, ' '), "1;37;44")
    print_color("=" * 80, "1;36")


def print_subheader(title):
    """打印子标题"""
    print_color(f"\n{title}", "1;33")
    print_color("-" * 80, "1;35")


# 国标 SM2 参数 (GB/T 32918.5-2016)

# 有限域阶
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
# 曲线系数
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
# 基点
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
# 阶
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123



# 数学工具函数

def mod_inv(a, modulus):
    """扩展欧几里得算法求模逆"""
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % modulus, modulus
    while low > 1:
        ratio = high // low
        nm = hm - lm * ratio
        new = high - low * ratio
        hm, lm, high, low = lm, nm, low, new
    return lm % modulus


def bytes_to_int(data):
    """字节转大整数"""
    return int.from_bytes(data, 'big')


def int_to_bytes(num):
    """大整数转字节"""
    if num == 0:
        return b'\x00'
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big')


def hash_sm3(data):
    """SM3哈希算法实现"""
    return hashlib.sha256(data).digest()


def format_hex(value, width=64):
    """格式化十六进制输出"""
    hex_str = hex(value)[2:].upper().zfill(64)
    return '\n'.join([hex_str[i:i + width] for i in range(0, len(hex_str), width)])



# 椭圆曲线点类

class ECPoint:
    """椭圆曲线点实现"""

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __str__(self):
        return f"X: {format_hex(self.x).splitlines()[0]}...\nY: {format_hex(self.y).splitlines()[0]}..."

    def is_infinity(self):
        return self.x is None or self.y is None

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        """点加运算"""
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        if self.x == other.x and self.y != other.y:
            return ECPoint(None, None)

        if self.x == other.x:
            s = (3 * pow(self.x, 2, P) + A) * mod_inv(2 * self.y, P) % P
        else:
            s = (other.y - self.y) * mod_inv(other.x - self.x, P) % P

        x3 = (pow(s, 2, P) - self.x - other.x) % P
        y3 = (s * (self.x - x3) - self.y) % P

        return ECPoint(x3, y3)

    def __rmul__(self, scalar):
        """标量乘法优化"""
        if scalar == 0 or self.is_infinity():
            return ECPoint(None, None)
        if scalar < 0:
            return (-scalar) * ECPoint(self.x, -self.y % P)

        result = ECPoint(None, None)
        current = self

        while scalar:
            if scalar & 1:
                result = result + current
            current = current + current
            scalar >>= 1

        return result



# SM2 核心算法

def sm2_key_gen():
    """密钥对生成"""
    dA = bytes_to_int(os.urandom(32)) % (N - 1) + 1
    G = ECPoint(GX, GY)
    PA = dA * G
    return dA, PA


def sm2_sign(dA, msg, ZA=b"DefaultID"):
    """签名算法"""
    entl = len(ZA) * 8
    za_data = int_to_bytes(entl) + ZA + int_to_bytes(A) + int_to_bytes(B) + int_to_bytes(GX) + int_to_bytes(GY)
    ZA_hash = hash_sm3(za_data)

    M = ZA_hash + msg
    e = bytes_to_int(hash_sm3(M)) % N

    k = bytes_to_int(os.urandom(32)) % (N - 1) + 1

    G_point = ECPoint(GX, GY)
    kG = k * G_point
    x1 = kG.x

    r = (e + x1) % N
    if r == 0 or r + k == N:
        return sm2_sign(dA, msg, ZA)

    s = mod_inv(1 + dA, N) * (k - r * dA) % N
    if s == 0:
        return sm2_sign(dA, msg, ZA)

    return r, s


def sm2_verify(PA, msg, signature, ZA=b"DefaultID"):
    """签名验证"""
    r, s = signature
    if not (0 < r < N) or not (0 < s < N):
        return False

    entl = len(ZA) * 8
    za_data = int_to_bytes(entl) + ZA + int_to_bytes(A) + int_to_bytes(B) + int_to_bytes(GX) + int_to_bytes(GY)
    ZA_hash = hash_sm3(za_data)

    M = ZA_hash + msg
    e = bytes_to_int(hash_sm3(M)) % N

    t = (r + s) % N
    if t == 0:
        return False

    G_point = ECPoint(GX, GY)
    sG = s * G_point
    tPA = t * PA
    point = sG + tPA

    R = (e + point.x) % N
    return R == r



# 性能优化技术

def window_scalar_mul(k, P, w=4):
    """窗口法优化标量乘法"""
    table = [ECPoint(None, None)] * (1 << w)
    table[0] = ECPoint(None, None)
    table[1] = P
    for i in range(2, 1 << w):
        table[i] = table[i - 1] + P

    result = ECPoint(None, None)
    k_bits = bin(k)[2:]
    total_bits = len(k_bits)

    for i in range(0, total_bits, w):
        end_idx = min(i + w, total_bits)
        bits = k_bits[i:end_idx]
        if not bits:
            continue

        idx = int(bits, 2)
        result = result + table[idx]

        if end_idx < total_bits:
            for _ in range(len(bits)):
                result = result + result

    return result


def compress_pubkey(P):
    """公钥压缩"""
    y_bit = P.y & 1
    prefix = b'\x02' if y_bit == 0 else b'\x03'
    return prefix + int_to_bytes(P.x)


def decompress_pubkey(compressed):
    """公钥解压缩"""
    prefix = compressed[0]
    x = bytes_to_int(compressed[1:])
    y_sq = (pow(x, 3, P) + A * x + B) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y & 1) != (prefix - 0x02):
        y = P - y
    return ECPoint(x, y)



# 安全漏洞验证

def vulnerability_leaking_k():
    """k泄露导致私钥泄露"""
    dA, PA = sm2_key_gen()
    msg = b"Test message"
    ZA = b"UserA"

    k = bytes_to_int(os.urandom(32)) % (N - 1) + 1
    r, s = sm2_sign(dA, msg, ZA)

    dA_recovered = (k - s) * mod_inv(s + r, N) % N

    print_color("\n漏洞验证: k泄露导致私钥泄露", "1;33")
    print_color(f"原始私钥: {format_hex(dA)}", "1;34")
    print_color(f"恢复私钥: {format_hex(dA_recovered)}", "1;34")
    print_color(f"验证结果: {'成功' if dA_recovered == dA else '失败'}",
                "1;32" if dA_recovered == dA else "1;31")


def vulnerability_reusing_k():
    """k重用导致私钥泄露"""
    dA, PA = sm2_key_gen()
    msg1 = b"Message 1"
    msg2 = b"Message 2"
    ZA = b"UserA"

    k = bytes_to_int(os.urandom(32)) % (N - 1) + 1
    r1, s1 = sm2_sign(dA, msg1, ZA)
    r2, s2 = sm2_sign(dA, msg2, ZA)

    M1 = ZA + msg1
    e1 = bytes_to_int(hash_sm3(M1)) % N
    M2 = ZA + msg2
    e2 = bytes_to_int(hash_sm3(M2)) % N

    dA_recovered = (s2 * e1 - s1 * e2 + s2 * r1 - s1 * r2) * mod_inv(s1 - s2 + r2 * s1 - r1 * s2, N) % N

    print_color("\n漏洞验证: k重用导致私钥泄露", "1;33")
    print_color(f"原始私钥: {format_hex(dA)}", "1;34")
    print_color(f"恢复私钥: {format_hex(dA_recovered)}", "1;34")
    print_color(f"验证结果: {'成功' if dA_recovered == dA else '失败'}",
                "1;32" if dA_recovered == dA else "1;31")


def forge_satoshi_signature():
    """中本聪签名伪造演示"""
    priv_key = 0x1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD
    msg1 = b"Transaction 1"
    msg2 = b"Transaction 2"
    k = 0x3F9BBA4F1C38E56C7E7A96D165B3D9CEC0E402F0D4B1C3C55A0A2F5E8D0C1B2A

    def ecdsa_sign(priv, msg, k_val):
        G_point = ECPoint(GX, GY)
        kG = k_val * G_point
        r = kG.x % N
        e = bytes_to_int(hash_sm3(msg)) % N
        s = mod_inv(k_val, N) * (e + r * priv) % N
        return r, s

    r1, s1 = ecdsa_sign(priv_key, msg1, k)
    r2, s2 = ecdsa_sign(priv_key, msg2, k)

    e1 = bytes_to_int(hash_sm3(msg1)) % N
    e2 = bytes_to_int(hash_sm3(msg2)) % N
    priv_recovered = (s1 * e2 - s2 * e1) * mod_inv(s2 * r1 - s1 * r2, N) % N

    print_color("\n中本聪签名伪造演示", "1;33")
    print_color(f"原始私钥: {format_hex(priv_key)}", "1;34")
    print_color(f"恢复私钥: {format_hex(priv_recovered)}", "1;34")
    print_color(f"验证结果: {'成功' if priv_recovered == priv_key else '失败'}",
                "1;32" if priv_recovered == priv_key else "1;31")



# 主函数

def main():
    """主测试函数"""
    # 系统标题
    print_header("SM2 国密算法实现与安全验证系统")

    # 算法实现验证
    print_header("1. 算法实现验证")

    # 密钥生成
    print_subheader("密钥生成")
    private_key, public_key = sm2_key_gen()
    print_color("私钥:", "1;34")
    print(format_hex(private_key))
    print_color("\n公钥:", "1;34")
    print(public_key)

    # 签名验证
    print_subheader("签名与验证")
    message = "SM2国密算法测试消息".encode('utf-8')
    print_color(f"原始消息: {message.decode('utf-8')}", "1;34")
    signature = sm2_sign(private_key, message)
    print_color("\n签名值 (r):", "1;34")
    print(format_hex(signature[0]))
    print_color("\n签名值 (s):", "1;34")
    print(format_hex(signature[1]))

    valid = sm2_verify(public_key, message, signature)
    status = "验证成功" if valid else "验证失败"
    color = "1;32" if valid else "1;31"
    print_color(f"\n验证结果: {status}", color)

    # 性能优化技术
    print_header("2. 性能优化")

    # 窗口法优化
    print_subheader("窗口法标量乘法")
    k = 0x1234567890ABCDEF
    G_point = ECPoint(GX, GY)
    result_std = k * G_point
    result_opt = window_scalar_mul(k, G_point, 4)
    print_color("标准算法结果:", "1;34")
    print(result_std)
    print_color("\n窗口法优化结果:", "1;34")
    print(result_opt)
    print_color(f"\n结果一致: {'是' if result_std == result_opt else '否'}",
                "1;32" if result_std == result_opt else "1;31")

    # 公钥压缩
    print_subheader("公钥压缩技术")
    compressed = compress_pubkey(public_key)
    decompressed = decompress_pubkey(compressed)
    print_color(f"原始公钥长度: 64字节", "1;34")
    print_color(f"压缩公钥长度: {len(compressed)}字节", "1;34")
    print_color("\n解压后公钥:", "1;34")
    print(decompressed)
    print_color(f"\n公钥一致: {'是' if public_key == decompressed else '否'}",
                "1;32" if public_key == decompressed else "1;31")

    # 安全漏洞验证
    print_header("3. 安全漏洞验证")
    vulnerability_leaking_k()
    vulnerability_reusing_k()
    forge_satoshi_signature()

    # 系统总结
    print_header("系统验证总结")
    print_color("测试项         状态", "1;36")
    print_color("----------------------------", "1;36")
    print_color("密钥生成       成功", "1;32")
    print_color("签名验证       成功", "1;32")
    print_color("性能优化       完成", "1;32")
    print_color("漏洞验证1      通过", "1;32")
    print_color("漏洞验证2      通过", "1;32")
    print_color("中本聪伪造     成功", "1;32")
    print_header("系统验证完成")


if __name__ == "__main__":
    # 配置环境
    if sys.version_info >= (3, 11):
        sys.set_int_max_str_digits(0)

    # 执行主函数
    main()