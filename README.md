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

- `--proxy, -p`: 代理合约地址或 Beacon 地址（查询合约时必需）
  - TransparentProxy/UUPS：输入代理合约地址
  - BeaconProxy：输入 UpgradeableBeacon 地址
- `--rpc, -r`: RPC URL（可选）
- `--chain-name, -n`: 链名称（可选，对应 rpc.toml 中的配置）
- `--init-config, -i`: 初始化RPC配置（可选，生成RPC配置文件模板）

## RPC 配置

工具支持两种方式配置 RPC：

1. **命令行参数**
   - 使用 `--rpc` 参数直接指定 RPC URL
   ```bash
   proxy-info -p <合约地址> -r <RPC URL>
   ```

2. **配置文件**
   - 使用 `rpc.toml` 文件管理多个链的 RPC
   - 首次运行时会自动创建配置文件模板
   - 可以为每个链配置多个备用 RPC，当主 RPC 不可用时会自动尝试其他 RPC

   配置文件示例：
   ```toml
   [ethereum]
   url = [
       "https://eth.llamarpc.com",
       "https://eth.rpc.blxrbdn.com",
   ]

   [arbitrum]
   url = [
       "https://arbitrum.llamarpc.com",
       "https://arb1.arbitrum.io/rpc",
   ]
   ```

## 使用示例

```bash
# 初始化RPC配置（生成配置文件模板）
proxy-info -i

# 使用命令行指定 RPC
proxy-info -p <代理合约地址> -r https://eth.llamarpc.com

# 使用配置文件中的 RPC（指定链名称）
proxy-info -p <代理合约地址> -n ethereum

# 查询 BeaconProxy（使用配置文件中的 Arbitrum RPC）
proxy-info -p <Beacon地址> -n arbitrum
```

如果不指定 RPC 参数，工具会：
1. 检查是否存在 `rpc.toml` 配置文件
2. 如果不存在，创建配置模板并提示编辑
3. 如果存在，使用配置文件中链的第一个可用 RPC