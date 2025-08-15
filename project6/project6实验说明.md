### Google Password Checkup 协议

#### 1. 介绍
Google Password Checkup 是一种隐私保护的密码泄露检查系统，基于 *Private Intersection-Sum with Cardinality* 密码学协议实现。该系统允许用户在不暴露具体密码的前提下，安全检查密码是否出现在泄露数据库中。

**核心特性**：
- 端到端隐私保护（服务器无法知晓用户密码）
- 仅泄露密码数量信息（不暴露具体哪些密码泄露）
- 线性计算复杂度（适用于大规模数据集）

#### 2. 协议数学基础

##### 2.1 Diffie-Hellman 密钥交换
协议建立在 Decisional Diffie-Hellman (DDH) 假设之上：
```math
\begin{aligned}
& \text{设 } \mathbb{G} \text{ 为素数阶 } p \text{ 的循环群} \\
& \text{客户端密钥： } k_1 \xleftarrow{R} \mathbb{Z}_p \\
& \text{服务器密钥： } k_2 \xleftarrow{R} \mathbb{Z}_p \\
& \text{共享密钥： } k = H(\text{password})^{k_1k_2} \mod p
\end{aligned}
```

##### 2.2 同态加密
使用 Paillier 加密系统实现加法同态：
```math
\begin{aligned}
& \text{加密： } \mathcal{E}(m) = g^m \cdot r^n \mod n^2 \\
& \text{加法同态： } \mathcal{E}(m_1) \cdot \mathcal{E}(m_2) = \mathcal{E}(m_1 + m_2) \\
& \text{标量乘法： } \mathcal{E}(m)^k = \mathcal{E}(k \cdot m)
\end{aligned}
```

##### 2.3 协议目标函数
定义私有交集和计算：
```math
\begin{aligned}
& \text{输入：} \\
& \quad \text{客户端： } C = \{c_1, c_2, ..., c_m\} \\
& \quad \text{服务器： } S = \{(s_1, v_1), (s_2, v_2), ..., (s_n, v_n)\} \\
& \text{输出：} \\
& \quad \text{交集大小： } |C \cap S| \\
& \quad \text{关联值和： } \sum_{s_i \in C \cap S} v_i
\end{aligned}
```

#### 3. 协议流程详解

##### 3.1 协议符号定义
| 符号 | 含义 |
|------|------|
| $H(\cdot)$ | 密码哈希函数 (PBKDF2-HMAC-SHA256) |
| $G$ | 椭圆曲线群 (secp256k1) |
| $\mathcal{E}(\cdot)$ | Paillier 同态加密 |
| $\oplus$ | 同态加法操作 |

##### 3.2 四步协议流程

**第1步：客户端初始化**
```math
\begin{aligned}
& \text{输入： } P = \{p_1, p_2, ..., p_m\} \\
& \text{计算： } A_i = H(p_i)^{k_1} \mod p \\
& \text{输出： } A = \{A_1, A_2, ..., A_m\}_{\text{shuffled}}
\end{aligned}
```

**第2步：服务器处理**
```math
\begin{aligned}
& \text{输入： } A, D = \{(d_1, 1), (d_2, 1), ..., (d_n, 1)\} \\
& \text{计算：} \\
& \quad Z_i = A_i^{k_2} \mod p \\
& \quad B_j = H(d_j)^{k_2} \mod p \\
& \quad V_j = \mathcal{E}(1) \\
& \text{输出： } (Z_{\text{shuffled}}, \{(B_j, V_j)\}_{\text{shuffled}})
\end{aligned}
```

**第3步：客户端计算交集**
```math
\begin{aligned}
& \text{计算： } T_j = B_j^{k_1} \mod p \\
& \text{交集索引： } J = \{j | T_j \in Z\} \\
& \text{同态求和： } R = \bigoplus_{j \in J} V_j \\
& \text{输出： } \mathcal{E}(|J|)
\end{aligned}
```

**第4步：服务器解密**
```math
\begin{aligned}
& \text{输入： } \mathcal{E}(s) \\
& \text{输出： } s = \mathcal{D}(\mathcal{E}(s))
\end{aligned}
```

#### 4. 安全实现关键技术

##### 4.1 密码预处理
```python
def _password_to_identifier(password: str) -> str:
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000  # 100,000次迭代
    ).hex()
```
**安全特性**：
- 盐值随机化防御彩虹表攻击
- 高迭代次数增加暴力破解成本
- 域分离防止跨系统重用

##### 4.2 协议优化技术

**批量加密优化**：
```math
\begin{aligned}
& \text{输入值： } v_1, v_2, ..., v_k \\
& \text{打包： } V = \sum_{i=1}^{k} v_i \cdot 2^{40(i-1)} \\
& \text{加密： } \mathcal{E}(V)
\end{aligned}
```


**计算加速**：
```python
# 并行指数计算
from concurrent.futures import ThreadPoolExecutor

def parallel_exponentiation(items, exponent):
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(
            lambda x: pow(x, exponent, CURVE_ORDER),
            items
        ))
    return results
```

##### 4.3 安全增强措施

**密文刷新机制**：
```math
\mathcal{E}'(m) = \mathcal{E}(m) \oplus \mathcal{E}(0)
```
*破坏密文与输入值的可链接性*

**会话密钥管理**：
```python
# 每次会话生成新密钥
self.k1 = random.SystemRandom().getrandbits(256)
self.k2 = random.SystemRandom().getrandbits(256)
```

#### 5. 协议扩展能力

##### 5.1 阈值泄露告警
```math
\text{客户端在 } |J| < \tau \text{ 时中止协议}
```
*防止小数据集统计推断攻击*

##### 5.2 多维度分析
```math
\text{支持同时计算：} 
\begin{cases} 
\sum v_i & \text{(泄露次数)} \\
\sum v_i^2 & \text{(泄露严重性)} \\
\max(v_i) & \text{(最大风险等级)}
\end{cases}
```

##### 5.3 分布式计算
```math
\begin{aligned}
& \text{水平分区： } C = C_1 \cup C_2 \cup \cdots \cup C_k \\
& \text{并行执行： } \text{Protocol}(C_i, S) \\
& \text{合并结果： } s = \sum s_i
\end{aligned}
```


#### 6. 安全分析

**隐私保障**：
1. 客户端隐私：
```math
\forall \text{password} \notin S, \Pr[\text{Server learns password}] \leq \text{negl}(\lambda)
```

2. 服务器隐私：
```math
\text{Client learns only } |C \cap S| \text{ and } \sum v_i
```

**攻击防护**：
- 重放攻击：会话绑定随机数
- 中间人攻击：TLS 1.3 通道加密
- 字典攻击：PBKDF2 高强度哈希

#### 7. 结论

Google Password Checkup 协议创新性地结合了：
1. **DDH 密钥交换**：实现安全的交集计算
2. **Paillier 同态加密**：支持隐私保护的聚合统计
3. **盐值强化哈希**：抵抗预计算攻击

该协议在保护用户隐私的前提下，提供了高效的密码泄露检查服务，其设计理念可扩展到其他隐私计算场景，如：
- 医疗数据分析
- 金融风控系统
- 跨机构数据协作
