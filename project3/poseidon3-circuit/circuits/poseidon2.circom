pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Poseidon2() {
    // 隐私输入：两个256位域元素
    signal input in[2];
    
    // 公开输出：哈希结果
    signal output out;
    
    // 使用circomlib的Poseidon组件（参数t=3）
    component hasher = Poseidon(3);
    
    // 输入连接
    hasher.inputs[0] <== 0;      // 容量字段（固定为0）
    hasher.inputs[1] <== in[0];  // 第一个输入块
    hasher.inputs[2] <== in[1];  // 第二个输入块
    
    // 输出连接
    out <== hasher.out;
}

// 主组件（公开输出out）
component main {public [out]} = Poseidon2();