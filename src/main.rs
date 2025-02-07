use ethers::{
    prelude::*,
    providers::{Http, Provider},
    types::H256,
    middleware::Middleware,
};
use clap::Parser;
use eyre::Result;
use std::str::FromStr;

// 存储槽常量
const IMPLEMENTATION_SLOT: &str = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT: &str = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const BEACON_SLOT: &str = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

// 函数选择器
const AUTHORIZE_UPGRADE: &str = "5ec29272"; // _authorizeUpgrade(address)
const UPGRADE_TO: &str = "3659cfe6"; // upgradeTo(address)
const UPGRADE_TO_AND_CALL: &str = "4f1ef286"; // upgradeToAndCall(address,bytes)
const CHANGE_ADMIN: &str = "8f283970"; // changeAdmin(address)
const ADMIN: &str = "f851a440"; // admin()
const IMPLEMENTATION: &str = "5c60da1b"; // implementation()
const PROXY_FUNCTION: &str = "485cc955"; // initialize(address,bytes)

#[derive(Debug, Clone)]
enum ProxyType {
    TransparentProxy,
    ERC1967Proxy,
    BeaconProxy,
    Unknown,
}

#[derive(Debug)]
struct UpgradeFunction {
    name: String,
    location: String,
}

#[derive(Debug)]
struct ProxyInfo {
    proxy_type: ProxyType,
    code_size: usize,
    implementation_address: Option<Address>,
    admin_address: Option<Address>,
    admin_is_eoa: Option<bool>,
    beacon_address: Option<Address>,
    upgrade_functions: Vec<UpgradeFunction>,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(
        short,
        long,
        help = "代理合约地址或Beacon地址",
        long_help = "输入要查询的合约地址：\n- TransparentProxy/UUPS：输入代理合约地址\n- BeaconProxy：输入UpgradeableBeacon地址\n地址格式：0x开头的42位十六进制字符"
    )]
    proxy: String,

    #[arg(
        short,
        long,
        help = "RPC节点URL",
        long_help = "以太坊RPC节点URL，例如：\n- 本地节点：http://localhost:8545\n- Infura: https://mainnet.infura.io/v3/YOUR-PROJECT-ID",
        default_value = "http://localhost:8545"
    )]
    rpc: String,
}

// 格式化地址输出
fn format_address(addr: Address) -> String {
    format!("{:#x}", addr)
}

// 检查函数选择器是否存在于合约代码中
fn has_function_selector(code: &[u8], selector: &str) -> bool {
    let selector_bytes = hex::decode(selector).unwrap();
    let code_hex = hex::encode(code);
    code_hex.contains(&hex::encode(selector_bytes))
}

async fn analyze_proxy(
    proxy_address: Address,
    provider: &Provider<Http>,
) -> Result<ProxyInfo> {
    println!("正在分析合约：{:#x}", proxy_address);

    // 获取合约代码
    let code = match provider.get_code(proxy_address, None).await {
        Ok(code) => code,
        Err(e) => {
            println!("错误：无法获取合约代码 - {}", e);
            return Err(eyre::eyre!("无法获取合约代码"));
        }
    };
    let code_bytes = code.to_vec();
    let code_size = code_bytes.len();

    if code_size == 0 {
        println!("错误：地址不是合约");
        return Err(eyre::eyre!("地址不是合约"));
    }

    println!("合约代码大小：{} 字节", code_size);

    // 获取存储槽中的地址
    println!("正在检查存储槽...");

    let impl_slot = H256::from_str(IMPLEMENTATION_SLOT)?;
    let admin_slot = H256::from_str(ADMIN_SLOT)?;
    let beacon_slot = H256::from_str(BEACON_SLOT)?;

    let impl_storage = match provider.get_storage_at(proxy_address, impl_slot, None).await {
        Ok(storage) => storage,
        Err(e) => {
            println!("错误：无法获取实现合约存储槽 - {}", e);
            return Err(eyre::eyre!("无法获取实现合约存储槽"));
        }
    };

    let admin_storage = match provider.get_storage_at(proxy_address, admin_slot, None).await {
        Ok(storage) => storage,
        Err(e) => {
            println!("错误：无法获取管理员存储槽 - {}", e);
            return Err(eyre::eyre!("无法获取管理员存储槽"));
        }
    };

    let beacon_storage = match provider.get_storage_at(proxy_address, beacon_slot, None).await {
        Ok(storage) => storage,
        Err(e) => {
            println!("错误：无法获取信标存储槽 - {}", e);
            return Err(eyre::eyre!("无法获取信标存储槽"));
        }
    };

    // 解析地址
    let mut implementation_address = None;
    let mut admin_address = None;
    let mut admin_is_eoa = None;
    let mut beacon_address = None;
    let mut upgrade_functions = Vec::new();

    // 检查代理类型和升级函数
    let proxy_type = if !admin_storage.is_zero() {
        // TransparentProxy
        let admin = Address::from_slice(&admin_storage.as_bytes()[12..]);
        admin_address = Some(admin);
        implementation_address = Some(Address::from_slice(&impl_storage.as_bytes()[12..]));
        
        // 检查管理员是否为 EOA
        let admin_code = match provider.get_code(admin, None).await {
            Ok(code) => code,
            Err(e) => {
                println!("错误：无法获取管理员地址的代码 - {}", e);
                return Err(eyre::eyre!("无法获取管理员地址的代码"));
            }
        };
        admin_is_eoa = Some(admin_code.is_empty());
        
        // 检查代理合约中的所有函数
        if has_function_selector(&code_bytes, UPGRADE_TO) {
            upgrade_functions.push(UpgradeFunction {
                name: "upgradeTo(address)".to_string(),
                location: "代理合约".to_string(),
            });
        }
        if has_function_selector(&code_bytes, UPGRADE_TO_AND_CALL) {
            upgrade_functions.push(UpgradeFunction {
                name: "upgradeToAndCall(address,bytes)".to_string(),
                location: "代理合约".to_string(),
            });
        }
        if has_function_selector(&code_bytes, CHANGE_ADMIN) {
            upgrade_functions.push(UpgradeFunction {
                name: "changeAdmin(address)".to_string(),
                location: "代理合约".to_string(),
            });
        }
        if has_function_selector(&code_bytes, ADMIN) {
            upgrade_functions.push(UpgradeFunction {
                name: "admin()".to_string(),
                location: "代理合约".to_string(),
            });
        }
        if has_function_selector(&code_bytes, IMPLEMENTATION) {
            upgrade_functions.push(UpgradeFunction {
                name: "implementation()".to_string(),
                location: "代理合约".to_string(),
            });
        }
        ProxyType::TransparentProxy
    } else if !impl_storage.is_zero() {
        // UUPS Proxy
        implementation_address = Some(Address::from_slice(&impl_storage.as_bytes()[12..]));
        
        // 检查实现合约中的升级函数
        println!("正在检查实现合约代码...");
        let impl_code = match provider.get_code(implementation_address.unwrap(), None).await {
            Ok(code) => code,
            Err(e) => {
                println!("错误：无法获取实现合约代码 - {}", e);
                return Err(eyre::eyre!("无法获取实现合约代码"));
            }
        };
        if has_function_selector(&impl_code.to_vec(), AUTHORIZE_UPGRADE) {
            upgrade_functions.push(UpgradeFunction {
                name: "_authorizeUpgrade(address)".to_string(),
                location: "实现合约".to_string(),
            });
        }
        if has_function_selector(&impl_code.to_vec(), UPGRADE_TO) {
            upgrade_functions.push(UpgradeFunction {
                name: "upgradeTo(address)".to_string(),
                location: "实现合约".to_string(),
            });
        }
        if has_function_selector(&impl_code.to_vec(), UPGRADE_TO_AND_CALL) {
            upgrade_functions.push(UpgradeFunction {
                name: "upgradeToAndCall(address,bytes)".to_string(),
                location: "实现合约".to_string(),
            });
        }
        
        // 检查代理合约中的基本函数
        if has_function_selector(&code_bytes, PROXY_FUNCTION) {
            upgrade_functions.push(UpgradeFunction {
                name: "initialize(address,bytes)".to_string(),
                location: "代理合约".to_string(),
            });
        }
        if has_function_selector(&code_bytes, IMPLEMENTATION) {
            upgrade_functions.push(UpgradeFunction {
                name: "implementation()".to_string(),
                location: "代理合约".to_string(),
            });
        }
        ProxyType::ERC1967Proxy
    } else if !beacon_storage.is_zero() {
        // BeaconProxy
        beacon_address = Some(Address::from_slice(&beacon_storage.as_bytes()[12..]));
        
        // 检查信标合约中的升级函数
        let beacon_code = match provider.get_code(beacon_address.unwrap(), None).await {
            Ok(code) => code,
            Err(e) => {
                println!("错误：无法获取信标合约代码 - {}", e);
                return Err(eyre::eyre!("无法获取信标合约代码"));
            }
        };
        if has_function_selector(&beacon_code.to_vec(), UPGRADE_TO) {
            upgrade_functions.push(UpgradeFunction {
                name: "upgradeTo(address)".to_string(),
                location: "信标合约".to_string(),
            });
        }
        if has_function_selector(&beacon_code.to_vec(), IMPLEMENTATION) {
            upgrade_functions.push(UpgradeFunction {
                name: "implementation()".to_string(),
                location: "信标合约".to_string(),
            });
        }
        ProxyType::BeaconProxy
    } else if has_function_selector(&code_bytes, UPGRADE_TO) && has_function_selector(&code_bytes, IMPLEMENTATION) {
        // 可能是独立的信标合约
        upgrade_functions.push(UpgradeFunction {
            name: "upgradeTo(address)".to_string(),
            location: "信标合约".to_string(),
        });
        upgrade_functions.push(UpgradeFunction {
            name: "implementation()".to_string(),
            location: "信标合约".to_string(),
        });
        ProxyType::BeaconProxy
    } else {
        ProxyType::Unknown
    };

    Ok(ProxyInfo {
        proxy_type,
        code_size,
        implementation_address,
        admin_address,
        admin_is_eoa,
        beacon_address,
        upgrade_functions,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // 连接到以太坊节点
    let provider = Provider::<Http>::try_from(&args.rpc)?;

    // 解析代理地址
    let proxy_address = args.proxy.parse::<Address>()?;

    // 分析代理合约
    let proxy_info = analyze_proxy(proxy_address, &provider).await?;

    // 输出分析结果
    println!("代理合约分析结果：");
    println!("代理类型: {:?}", proxy_info.proxy_type);
    println!("代码大小: {} 字节", proxy_info.code_size);
    
    if let Some(impl_addr) = proxy_info.implementation_address {
        println!("实现合约地址: {}", format_address(impl_addr));
    }
    
    if let Some(admin_addr) = proxy_info.admin_address {
        println!("管理员地址: {}", format_address(admin_addr));
        if let Some(is_eoa) = proxy_info.admin_is_eoa {
            println!("管理员类型: {}", if is_eoa { "EOA" } else { "合约" });
        }
    }
    
    if let Some(beacon_addr) = proxy_info.beacon_address {
        println!("信标合约地址: {}", format_address(beacon_addr));
    }
    
    if !proxy_info.upgrade_functions.is_empty() {
        println!("升级函数:");
        for func in proxy_info.upgrade_functions {
            println!("  - {} [位于{}]", func.name, func.location);
        }
    } else {
        println!("未找到升级函数");
    }

    Ok(())
}