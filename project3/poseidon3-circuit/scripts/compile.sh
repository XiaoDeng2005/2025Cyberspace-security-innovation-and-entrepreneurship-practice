#!/bin/bash

# 创建构建目录
mkdir -p build

# 编译电路
circom circuits/poseidon2.circom \
    --r1cs \
    --wasm \
    --sym \
    --c \
    -o build

# 生成R1CS信息
echo "R1CS信息:"
snarkjs r1cs info build/poseidon2.r1cs

# 打印约束
echo "约束数量:"
snarkjs r1cs print build/poseidon2.r1cs build/poseidon2.sym

# 导出R1CS为JSON
snarkjs r1cs export json build/poseidon2.r1cs build/poseidon2.r1cs.json