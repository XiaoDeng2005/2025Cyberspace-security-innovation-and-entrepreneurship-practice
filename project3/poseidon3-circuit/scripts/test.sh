#!/bin/bash

# 创建输入文件
echo '{"in":["123456789","987654321"]}' > build/input.json

# 生成见证
node build/poseidon2_js/generate_witness.js \
    build/poseidon2_js/poseidon2.wasm \
    build/input.json \
    build/witness.wtns

# 检查见证
echo "见证检查结果:"
snarkjs wtns check build/poseidon2.r1cs build/witness.wtns