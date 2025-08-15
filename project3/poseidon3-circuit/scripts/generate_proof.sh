#!/bin/bash

# 生成证明
snarkjs groth16 prove \
    build/poseidon2.zkey \
    build/witness.wtns \
    build/proof.json \
    build/public.json

# 验证证明
echo "证明验证结果:"
snarkjs groth16 verify \
    build/verification_key.json \
    build/public.json \
    build/proof.json

# 创建合约目录
mkdir -p contracts

# 生成验证合约
snarkjs zkey export solidityverifier build/poseidon2.zkey contracts/Verifier.sol

# 生成调用数据
echo "Solidity调用数据:"
snarkjs zkey export soliditycalldata build/public.json build/proof.json