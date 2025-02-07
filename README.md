# Proxy Info

这是一个用于查询 ERC1967 代理合约信息的命令行工具。它可以获取代理合约的管理员地址和实现合约地址。

## 代理合约类型说明

本工具支持以下三种代理合约类型：

1. **TransparentProxy**
   - 输入地址：代理合约地址
   - 特点：管理员和用户使用不同的函数选择器，避免了函数冲突
   - 测试结果：成功验证了管理员（EOA）和用户的权限分离

2. **UUPS (Universal Upgradeable Proxy Standard)**
   - 输入地址：代理合约地址
   - 特点：升级逻辑在实现合约中，节省了gas
   - 测试结果：成功验证了合约升级功能

3. **BeaconProxy**
   - 输入地址：UpgradeableBeacon 地址
   - 特点：多个代理共享同一个实现地址，适合部署多个相同合约
   - 测试结果：成功验证了通过 Beacon 更新多个代理的实现

## 使用方法

```bash
# 安装
git clone https://github.com/Ray5959/Proxy-info.git
cd proxy-info
cargo install --path .

# 运行
proxy-info --proxy <代理合约地址> --rpc <RPC URL>
```

## 参数说明

- `--proxy, -p`: 代理合约地址或 Beacon 地址（必需）
  - TransparentProxy/UUPS：输入代理合约地址
  - BeaconProxy：输入 UpgradeableBeacon 地址
- `--rpc, -r`: RPC URL（可选，默认为 http://localhost:8545）

## 示例

```bash
# 查询 TransparentProxy/UUPS 代理合约
proxy-info --proxy <代理合约地址> --rpc http://localhost:8545

# 查询 BeaconProxy
proxy-info --proxy <Beacon地址> --rpc http://localhost:8545
```

