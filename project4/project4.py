import os
import struct
import hashlib
import math
from typing import List, Tuple, Optional


# ====================== a) SM3 优化实现 ======================
class SM3:
    # 初始IV值 (RFC 1319) - 8个32位整数
    IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]

    # 常量表
    T = [0x79cc4519] * 16 + [0x7a879d8a] * 48

    @staticmethod
    def _left_rotate(x: int, n: int) -> int:
        """循环左移"""
        return ((x << (n % 32)) & 0xFFFFFFFF) | (x >> (32 - (n % 32)))

    @staticmethod
    def _ff(x: int, y: int, z: int, j: int) -> int:
        """布尔函数 FF"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _gg(x: int, y: int, z: int, j: int) -> int:
        """布尔函数 GG"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | (~x & z)

    @staticmethod
    def _p0(x: int) -> int:
        """置换函数 P0"""
        return x ^ SM3._left_rotate(x, 9) ^ SM3._left_rotate(x, 17)

    @staticmethod
    def _p1(x: int) -> int:
        """置换函数 P1"""
        return x ^ SM3._left_rotate(x, 15) ^ SM3._left_rotate(x, 23)

    @staticmethod
    def _padding(msg: bytes) -> bytes:
        """消息填充 (优化版)"""
        length = len(msg)
        bit_length = length * 8
        pad = b'\x80' + b'\x00' * ((56 - (length + 1) % 64) % 64)
        pad += struct.pack('>Q', bit_length)
        return msg + pad

    @staticmethod
    def _compress(iv: list, block: bytes) -> list:
        """压缩函数 (优化版)"""
        # 消息扩展
        w = list(struct.unpack('>16I', block))
        for j in range(16, 68):
            w.append(SM3._p1(w[j - 16] ^ w[j - 9] ^ SM3._left_rotate(w[j - 3], 15)) ^
                     SM3._left_rotate(w[j - 13], 7) ^ w[j - 6])

        # 初始化寄存器
        a, b, c, d, e, f, g, h = iv

        # 主循环
        for j in range(64):
            ss1 = SM3._left_rotate((SM3._left_rotate(a, 12) + e + SM3._left_rotate(SM3.T[j], j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ SM3._left_rotate(a, 12)
            tt1 = (SM3._ff(a, b, c, j) + d + ss2 + (w[j] if j < 16 else w[j] ^ w[j - 4])) & 0xFFFFFFFF
            tt2 = (SM3._gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = SM3._left_rotate(b, 9)
            b = a
            a = tt1
            h = g
            g = SM3._left_rotate(f, 19)
            f = e
            e = SM3._p0(tt2)

        # 更新IV
        return [(iv[i] ^ reg) & 0xFFFFFFFF for i, reg in enumerate([a, b, c, d, e, f, g, h])]

    @staticmethod
    def hash(msg: bytes) -> bytes:
        """SM3 哈希函数 (优化版)"""
        # 填充消息
        padded_msg = SM3._padding(msg)

        # 处理消息分组
        v = SM3.IV.copy()
        for i in range(0, len(padded_msg), 64):
            block = padded_msg[i:i + 64]
            v = SM3._compress(v, block)

        # 将最终状态转换为字节
        return b''.join(struct.pack('>I', x) for x in v)


# ====================== b) 长度扩展攻击验证 ======================
class SM3LengthExtensionAttack:
    @staticmethod
    def attack(original_hash: bytes, original_len: int, extension: bytes) -> bytes:
        """
        长度扩展攻击
        :param original_hash: 原始消息的哈希值
        :param original_len: 原始消息的长度 (字节)
        :param extension: 要附加的消息
        :return: 新消息的哈希值
        """
        # 计算原始消息的填充
        pad_len = (55 - original_len) % 64
        padding = b'\x80' + b'\x00' * pad_len + struct.pack('>Q', original_len * 8)

        # 设置初始状态为原始哈希值
        state = list(struct.unpack('>8I', original_hash))

        # 处理扩展消息 (带填充)
        new_msg = padding + extension
        padded_new_msg = SM3._padding(new_msg)

        # 处理每个分组
        for i in range(0, len(padded_new_msg), 64):
            block = padded_new_msg[i:i + 64]
            state = SM3._compress(state, block)

        return b''.join(struct.pack('>I', x) for x in state)

    @staticmethod
    def verify():
        """验证长度扩展攻击"""
        # 原始消息和密钥
        key = os.urandom(16)
        original_msg = b"Hello, world!"

        # 计算原始哈希
        original_hash = SM3.hash(key + original_msg)
        print(f"原始消息哈希: {original_hash.hex()}")

        # 扩展消息
        extension = b"Extra data appended"

        # 计算新消息的正确哈希
        new_msg = key + original_msg + SM3._padding(key + original_msg)[len(key + original_msg):] + extension
        correct_new_hash = SM3.hash(new_msg)

        # 使用长度扩展攻击计算新哈希
        original_len = len(key) + len(original_msg)
        attack_hash = SM3LengthExtensionAttack.attack(original_hash, original_len, extension)

        # 验证结果
        print(f"正确的新哈希: {correct_new_hash.hex()}")
        print(f"攻击生成哈希: {attack_hash.hex()}")
        print(f"攻击是否成功: {correct_new_hash == attack_hash}")


# ====================== c) Merkle 树实现 ======================
class MerkleTree:
    def __init__(self, data: List[bytes]):
        """
        构建 Merkle 树 (RFC6962)
        :param data: 叶子节点的数据列表
        """
        # 计算叶子节点的哈希 (带前缀 0x00)
        self.leaves = [SM3.hash(b'\x00' + d) for d in data]
        self.tree = self._build_tree(self.leaves)
        self.root = self.tree[-1][0] if self.tree else b''

    def _build_tree(self, nodes: List[bytes]) -> List[List[bytes]]:
        """
        递归构建 Merkle 树
        :param nodes: 当前层的节点列表
        :return: 整个 Merkle 树 (每层节点列表)
        """
        if not nodes:
            return []

        tree = [nodes]
        if len(nodes) == 1:
            return tree

        # 构建父层节点
        parents = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else left
            # 内部节点带前缀 0x01
            parent = SM3.hash(b'\x01' + left + right)
            parents.append(parent)

        # 递归构建
        tree.extend(self._build_tree(parents))
        return tree

    def get_root(self) -> bytes:
        """获取根哈希"""
        return self.root

    def inclusion_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """
        存在性证明
        :param index: 叶子节点的索引
        :return: 证明路径 (节点哈希和位置)
        """
        if index < 0 or index >= len(self.leaves):
            raise ValueError("Invalid index")

        proof = []
        current_index = index
        current_level = 0

        # 从叶子节点到根节点
        while current_level < len(self.tree) - 1:
            level_nodes = self.tree[current_level]

            # 确定兄弟节点的位置
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                is_right = True
            else:
                sibling_index = current_index - 1
                is_right = False

            # 添加兄弟节点 (如果存在)
            if sibling_index < len(level_nodes):
                sibling_hash = level_nodes[sibling_index]
            else:
                sibling_hash = level_nodes[current_index]  # 重复最后一个节点

            proof.append((sibling_hash, is_right))
            current_index //= 2
            current_level += 1

        return proof

    @staticmethod
    def verify_inclusion(root: bytes, leaf: bytes, index: int, proof: List[Tuple[bytes, bool]]) -> bool:
        """
        验证存在性证明
        :param root: 根哈希
        :param leaf: 叶子节点数据
        :param index: 叶子节点索引
        :param proof: 证明路径
        :return: 验证是否成功
        """
        # 计算叶子哈希
        current_hash = SM3.hash(b'\x00' + leaf)

        # 从叶子节点开始重建路径
        for i, (sibling_hash, is_right) in enumerate(proof):
            if is_right:
                current_hash = SM3.hash(b'\x01' + current_hash + sibling_hash)
            else:
                current_hash = SM3.hash(b'\x01' + sibling_hash + current_hash)

        return current_hash == root

    def non_inclusion_proof(self, leaf: bytes) -> Tuple[Optional[int], List[Tuple[bytes, bool]]]:
        """
        不存在性证明
        :param leaf: 要证明不存在的叶子节点数据
        :return: (最近叶子的索引, 证明路径)
        """
        leaf_hash = SM3.hash(b'\x00' + leaf)

        # 查找最近的叶子节点
        closest_index = None
        min_diff = float('inf')

        for i, h in enumerate(self.leaves):
            # 计算哈希的数值差
            diff = abs(int.from_bytes(leaf_hash, 'big') - int.from_bytes(h, 'big'))
            if diff < min_diff:
                min_diff = diff
                closest_index = i

        # 获取存在性证明
        proof = self.inclusion_proof(closest_index)
        return closest_index, proof

    @staticmethod
    def verify_non_inclusion(root: bytes, leaf: bytes, closest_index: int,
                             closest_leaf: bytes, proof: List[Tuple[bytes, bool]]) -> bool:
        """
        验证不存在性证明
        :param root: 根哈希
        :param leaf: 要证明不存在的叶子节点数据
        :param closest_index: 最近叶子的索引
        :param closest_leaf: 最近叶子的数据
        :param proof: 证明路径
        :return: 验证是否成功
        """
        # 验证最近叶子的存在性
        if not MerkleTree.verify_inclusion(root, closest_leaf, closest_index, proof):
            return False

        # 验证目标叶子在最近叶子之间不存在
        leaf_hash = SM3.hash(b'\x00' + leaf)
        closest_hash = SM3.hash(b'\x00' + closest_leaf)

        # 比较哈希值
        if leaf_hash == closest_hash:
            return False  # 如果哈希相同，说明叶子存在

        # 检查叶子是否应该出现在这个位置
        return (int.from_bytes(leaf_hash, 'big') < int.from_bytes(closest_hash, 'big')) == (leaf_hash < closest_hash)


# ====================== 测试函数 ======================
def test_sm3():
    """测试 SM3 实现"""
    # 测试向量
    test_vectors = [
        (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"abcd" * 16, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")
    ]

    print("测试 SM3 实现:")
    for msg, expected in test_vectors:
        digest = SM3.hash(msg).hex()
        status = "通过" if digest == expected else f"失败 (期望: {expected})"
        print(f"消息: {msg[:10]}... 哈希: {digest} {status}")
    print()


def test_length_extension_attack():
    """测试长度扩展攻击"""
    print("测试长度扩展攻击:")
    SM3LengthExtensionAttack.verify()
    print()


def test_merkle_tree():
    """测试 Merkle 树"""
    # 生成 10 个叶子节点 (测试用)
    leaf_count = 10
    print(f"构建 Merkle 树 ({leaf_count} 个叶子节点)...")
    data = [os.urandom(32) for _ in range(leaf_count)]
    tree = MerkleTree(data)

    # 存在性证明
    index = 3
    proof = tree.inclusion_proof(index)
    valid = MerkleTree.verify_inclusion(tree.get_root(), data[index], index, proof)
    print(f"存在性证明验证: {'通过' if valid else '失败'}")

    # 不存在性证明
    non_existent_leaf = os.urandom(32)
    closest_index, proof = tree.non_inclusion_proof(non_existent_leaf)
    closest_leaf = data[closest_index]
    valid = MerkleTree.verify_non_inclusion(
        tree.get_root(), non_existent_leaf, closest_index, closest_leaf, proof
    )
    print(f"不存在性证明验证: {'通过' if valid else '失败'}")


# ====================== 主函数 ======================
if __name__ == "__main__":
    test_sm3()
    test_length_extension_attack()
    test_merkle_tree()