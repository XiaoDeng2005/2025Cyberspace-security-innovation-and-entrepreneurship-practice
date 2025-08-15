#!/bin/bash

# 创建初始ptau文件
snarkjs powersoftau new bn128 12 build/pot12_0000.ptau -v

# 第一次贡献（需要随机输入）
echo "请输入随机文本作为第一次贡献:"
snarkjs powersoftau contribute build/pot12_0000.ptau build/pot12_0001.ptau \
    --name="First contribution" -v

# 准备阶段2
snarkjs powersoftau prepare phase2 build/pot12_0001.ptau build/final.ptau -v

# 生成Groth16 zkey
snarkjs groth16 setup build/poseidon2.r1cs build/final.ptau build/poseidon2.zkey

# 导出验证密钥
snarkjs zkey export verificationkey build/poseidon2.zkey build/verification_key.json