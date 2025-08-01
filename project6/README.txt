project6

我们实现了刘巍然老师的报告中的 google password checkup，论文 section 3.1 ，也即 Figure 2 中展示的协议。该协议允许两方（P1 和 P2）在不透露各自完整集合内容的情况下，安全地计算它们共享元素的关联值之和。
gpc.py：实现该协议的程序。主要功能/部件如下：

DDHGroup类：模拟DDH安全群（实际应用应替换为椭圆曲线）。包含：
find_generator()：生成循环群的生成元；
random_key()：生成参与方的私有密钥（k₁/k₂）；
pow(x, k)	：实现群上的模幂运算（H(x)^k）。

AdditiveHomomorphicEncryption类：模拟加法同态加密（实际需替换为Paillier等）。包含：
encrypt(value)：对数值添加噪声生成密文；
decrypt(ciphertext)：解密同态加密结果；
add(c1, c2)：实现密文同态加法。

PrivateIntersectionSum类：协议主逻辑。包含：
hash_to_group(item)：将用户ID哈希映射到群元素；
run_protocol()	：执行完整的三轮协议流程。

协议流程实现：
1. 初始化阶段：双方协商群参数（DDHGroup初始化），P₂生成同态加密密钥对；
2. Round 1 (P₁ → P₂)：P₁对每个ID计算H(vᵢ)^k₁并打乱顺序发送，隐藏P₁的原始ID，防止P₂直接获取；
3. Round 2 (P₂ → P₁)：P₂对收到的值计算H(vᵢ)^(k₁k₂)，对自己的ID计算H(wⱼ)^k₂和同态加密值AEnc(tⱼ)，双重掩码实现隐私集合求交；
4. Round 3 (P₁ → P₂)：P₁计算H(wⱼ)^(k₁k₂)并比对交集，对交集中的加密值同态求和，安全计算重合ID的统计量
5. 结果输出：返回交集大小和数值总和。

运行结果如图。我们尝试了较多用例，结果均正确。

22密码2班 梁钰舜 202200460175

