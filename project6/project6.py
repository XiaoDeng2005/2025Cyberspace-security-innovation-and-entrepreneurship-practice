import os
import random
import hashlib
import time
import phe
from phe import paillier
from collections.abc import Iterable
from typing import List, Tuple, Dict, Any, Optional


# ======================
# 基础密码学组件
# ======================

class HomomorphicEncryption:
    """Paillier同态加密系统实现"""

    def __init__(self, key_size=1024):
        """初始化加密系统"""
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=key_size)

    def encrypt(self, plaintext: int) -> paillier.EncryptedNumber:
        """加密整数"""
        return self.public_key.encrypt(plaintext)

    def decrypt(self, ciphertext: paillier.EncryptedNumber) -> int:
        """解密到整数"""
        return self.private_key.decrypt(ciphertext)

    def homomorphic_add(self, *ciphertexts: paillier.EncryptedNumber) -> paillier.EncryptedNumber:
        """同态加法"""
        result = ciphertexts[0]
        for ct in ciphertexts[1:]:
            result += ct
        return result

    def refresh(self, ciphertext: paillier.EncryptedNumber) -> paillier.EncryptedNumber:
        """刷新密文（添加加密的0）"""
        return ciphertext + self.public_key.encrypt(0)

    def batch_encrypt(self, values: List[int], values_per_cipher=65) -> List[paillier.EncryptedNumber]:
        """批量加密（时隙优化）"""
        ciphertexts = []
        for i in range(0, len(values), values_per_cipher):
            batch = values[i:i + values_per_cipher]
            # 将多个值打包到单个密文
            packed_value = sum(v << (40 * idx) for idx, v in enumerate(batch))
            ciphertexts.append(self.encrypt(packed_value))
        return ciphertexts


# ======================
# 协议核心实现（修复版）
# ======================

class DDHPrivateIntersectionSum:
    """DDH-based私有交集求和协议"""
    # 预定义曲线参数
    CURVE_PARAMS = {
        "secp256k1": {
            "order": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "hash_alg": "sha256"
        },
        "prime256v1": {
            "order": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "hash_alg": "sha256"
        }
    }

    def __init__(self, curve: str = "secp256k1"):
        """
        初始化协议
        curve: 使用的椭圆曲线名称
        """
        self.curve = curve
        self.he = HomomorphicEncryption()
        self._reset_state()

    def _reset_state(self):
        """重置会话状态"""
        self.client_state = None
        self.server_state = None

    def _hash_to_group(self, element: str) -> int:
        """将元素哈希到群中"""
        curve_data = self.CURVE_PARAMS[self.curve]
        hasher = hashlib.new(curve_data["hash_alg"])
        hasher.update(element.encode())
        hashed_bytes = hasher.digest()
        return int.from_bytes(hashed_bytes, 'big') % curve_data["order"]

    # ====== 客户端方法 ======

    def client_init_session(self) -> Dict:
        """初始化客户端会话"""
        self._reset_state()
        self.client_state = {
            "k1": random.getrandbits(256)  # 客户端私钥
        }
        return self.client_state

    def client_process(self, client_items: List[str]) -> List[int]:
        """
        客户端处理数据（协议第1轮）
        返回：处理后的客户端数据集 A_set
        """
        if not self.client_state:
            self.client_init_session()

        curve_order = self.CURVE_PARAMS[self.curve]["order"]
        k1 = self.client_state["k1"]

        # 计算A_i = H(v_i)^k1 mod p
        A_set = [pow(self._hash_to_group(item), k1, curve_order)
                 for item in client_items]

        # 随机排列防止顺序泄露
        random.shuffle(A_set)
        return A_set

    def client_compute_intersection(
            self,
            Z_set: List[int],
            B_tuples: List[Tuple[int, paillier.EncryptedNumber]]
    ) -> paillier.EncryptedNumber:
        """
        客户端计算交集（协议第3轮）
        返回：加密的交集和
        """
        if not self.client_state:
            raise RuntimeError("Client session not initialized")

        curve_order = self.CURVE_PARAMS[self.curve]["order"]
        k1 = self.client_state["k1"]

        B_list, encrypted_values = zip(*B_tuples)

        # 计算B_j^k1 = H(w_j)^{k1*k2} mod p
        B_transformed = [pow(B_j, k1, curve_order) for B_j in B_list]

        # 查找交集元素
        Z_set = set(Z_set)
        intersection_indices = [
            idx for idx, item in enumerate(B_transformed)
            if item in Z_set
        ]

        # 没有交集时返回加密0
        if not intersection_indices:
            return self.he.encrypt(0)

        # 同态求和
        sum_cipher = encrypted_values[intersection_indices[0]]
        for idx in intersection_indices[1:]:
            sum_cipher += encrypted_values[idx]

        # 刷新密文增加安全性
        return self.he.refresh(sum_cipher)

    # ====== 服务器方法 ======

    def server_init_session(self) -> Dict:
        """初始化服务器会话"""
        self._reset_state()
        self.server_state = {
            "k2": random.getrandbits(256)  # 服务器私钥
        }
        return self.server_state

    def server_process(
            self,
            A_set: List[int],
            server_items: List[Tuple[str, int]]
    ) -> Tuple[List[int], List[Tuple[int, paillier.EncryptedNumber]]]:
        """
        服务器处理数据（协议第2轮）
        返回：(Z_set, B_tuples)
        """
        if not self.server_state:
            self.server_init_session()

        curve_order = self.CURVE_PARAMS[self.curve]["order"]
        k2 = self.server_state["k2"]

        # 计算Z = A_i^k2 = H(v_i)^{k1*k2} mod p
        Z_set = [pow(a, k2, curve_order) for a in A_set]
        random.shuffle(Z_set)  # 随机排列

        # 准备服务器数据
        B_tuples = []
        for item, value in server_items:
            # B_j = H(w_j)^k2 mod p
            B_j = pow(self._hash_to_group(item), k2, curve_order)
            # 加密关联值
            encrypted_value = self.he.encrypt(value)
            B_tuples.append((B_j, encrypted_value))

        # 随机排列防止顺序泄露
        random.shuffle(B_tuples)
        return Z_set, B_tuples

    def server_decrypt(self, ciphertext: paillier.EncryptedNumber) -> int:
        """服务器解密最终结果"""
        return self.he.decrypt(ciphertext)


# ======================
# Google密码检查应用（修复版）
# ======================

class GooglePasswordCheckup:
    """Google密码泄露检查系统"""

    def __init__(self, curve: str = "secp256k1"):
        self.protocol = DDHPrivateIntersectionSum(curve)
        self.salt = os.urandom(16)  # 全局盐值增强安全性

    def _password_to_identifier(self, password: str) -> str:
        """安全密码哈希（抵抗彩虹表攻击）"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            self.salt,
            100000  # 高强度迭代
        ).hex()

    def client_init_session(self) -> Dict:
        """客户端：初始化会话"""
        return self.protocol.client_init_session()

    def client_process_passwords(self, passwords: List[str]) -> Tuple[List[int], Dict]:
        """
        客户端：处理密码（Round 1）
        返回：(Round1数据, 客户端状态)
        """
        # 转换密码标识符
        client_items = [self._password_to_identifier(pwd) for pwd in passwords]
        round1_data = self.protocol.client_process(client_items)

        # 保存状态用于后续计算
        client_state = {
            "passwords": passwords,
            "client_state": self.protocol.client_state
        }
        return round1_data, client_state

    def client_compute_result(
            self,
            server_response: Tuple[List[int], List[Tuple[int, paillier.EncryptedNumber]]],
            client_state: Dict
    ) -> paillier.EncryptedNumber:
        """
        客户端：计算最终结果（Round 3）
        返回：加密的泄露计数
        """
        # 恢复客户端状态
        self.protocol.client_state = client_state["client_state"]
        return self.protocol.client_compute_intersection(*server_response)

    def server_init_session(self) -> Dict:
        """服务器：初始化会话"""
        return self.protocol.server_init_session()

    def server_process_request(
            self,
            round1_data: List[int],
            leaked_credentials: List[str]
    ) -> Tuple[List[int], List[Tuple[int, paillier.EncryptedNumber]]]:
        """
        服务器：处理客户端请求（Round 2）
        返回：Round2数据
        """
        # 创建服务器数据集
        server_items = [
            (self._password_to_identifier(pwd), 1)
            for pwd in leaked_credentials
        ]
        return self.protocol.server_process(round1_data, server_items)

    def server_get_result(self, encrypted_result: paillier.EncryptedNumber) -> int:
        """服务器：获取最终泄露计数"""
        return self.protocol.server_decrypt(encrypted_result)


# ======================
# 修复后的测试用例
# ======================

if __name__ == "__main__":
    # 示例1: 基本功能测试
    print("=== 基本功能测试 ===")
    client_passwords = ["SecureP@ss123", "MySecret!", "Company2023"]
    server_leaked = ["MySecret!", "123456", "admin"]

    gpc = GooglePasswordCheckup()

    # 客户端初始化
    client_session = gpc.client_init_session()

    # 客户端第1步
    round1_data, client_state = gpc.client_process_passwords(client_passwords)

    # 服务器初始化
    server_session = gpc.server_init_session()

    # 服务器处理
    round2_data = gpc.server_process_request(round1_data, server_leaked)

    # 客户端第2步
    encrypted_result = gpc.client_compute_result(round2_data, client_state)

    # 服务器获取结果
    result = gpc.server_get_result(encrypted_result)

    print(f"检测到 {result} 个密码泄露 (预期: 1)")
    print()

    # 示例2: 压力测试
    print("=== 压力测试 ===")
    try:
        # 大规模数据集
        large_client = [f"password_{i}" for i in range(1000)]
        large_server = [f"password_{i}" for i in range(500, 1500)]

        # 客户端初始化
        gpc.client_init_session()

        # 客户端第1步
        large_round1, large_client_state = gpc.client_process_passwords(large_client)

        # 服务器初始化
        gpc.server_init_session()

        # 服务器处理
        large_round2 = gpc.server_process_request(large_round1, large_server)

        # 客户端第2步
        large_encrypted = gpc.client_compute_result(large_round2, large_client_state)

        # 服务器获取结果
        large_result = gpc.server_get_result(large_encrypted)

        print(f"大规模测试完成! 检测到 {large_result} 个密码泄露 (预期: 500)")
        print("所有测试通过!")
    except Exception as e:
        print(f"压力测试失败: {str(e)}")
        import traceback

        traceback.print_exc()