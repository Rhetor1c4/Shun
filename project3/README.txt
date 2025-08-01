project3

用circom实现poseidon2哈希算法的电路。我们采用先编写程序，然后再于zkrepl在线平台上进行生成，并生成groth16证明。参数选择(n,t,d)=(256,2,5)。
poseidon2_2_5.circom为简化版的 Poseidon2 哈希函数电路实现，主要实现了：
inputs[2]：哈希输入（rate + capacity），通常只用 inputs[0]，inputs[1] 是 0；
out：输出 hash 值，即最终压缩状态的第一个元素；
c[]：Round constants，简化为常数 i + 1，每轮一个；
M[][]：MDS 矩阵，用于线性混合两个 state 值；
state0, state1：每轮中的两个状态变量，组成 state vector；
exp_state：使用分步幂运算（x^5 拆成二次运算），避免 Circom 非法高阶约束；
for r in TOTAL_ROUNDS：每轮迭代：I.加 round 常数 II.选择性地进行幂运算 III.应用 MDS 矩阵。
运行时，首先初始化状态：
state0[0] = inputs[0]
state1[0] = inputs[1] = 0
然后迭代 64 轮哈希计算（前 4 + 中间 56 + 后 4）：
全轮：对两个状态都做 S-box（x^5）；
半轮：只对 state0 做 S-box；
每轮应用 MDS 矩阵对两个状态进行线性混合；最后输出第一个状态值（rate 元素）作为哈希值。

main.circom构建了一个电路模板，将 Poseidon2 哈希结果与用户给定的 hash 进行比较。这是电路的“证明接口”，用于把私密输入和公开输入组织成可验证的证明形式。工作流程为：
用户提供：私密输入 preimage；
公开输入 hash（通常来自前期预计算）；
Poseidon2 电路对 preimage 做哈希计算；
h.out === hash 是一个强约束：电路只有当内部计算出的哈希值和外部公开的 hash 相等时，证明才成立。

poseidon2_sim.js则是一个模拟脚本，用于预计算 poseidon2_2_5.circom 电路对应的哈希值，用于验证。

22密码2班 梁钰舜 202200460175
