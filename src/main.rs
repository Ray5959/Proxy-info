use ethers::{
    prelude::*,
    providers::{Http, Provider},
    types::{H256, Address},
    middleware::Middleware,
};
use clap::Parser;
use eyre::{Result, WrapErr};
use log::{info, error, debug};
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
const PROXY_FUNCTION: &str = "d1f57894"; // initialize(address,bytes)

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

// 检查合约是否通过fallback机制实现了特定函数
fn has_fallback_function(code: &[u8], selector: &str) -> bool {
    let code_hex = hex::encode(code);
    debug!("检查字节码: {}", code_hex);
    
    // 1. 检查是否包含选择器比较
    let selector_bytes = hex::decode(selector).unwrap();
    let selector_hex = hex::encode(&selector_bytes);
    debug!("检查选择器: {}", selector_hex);
    
    // 2. 检查TransparentProxy的特征模式
    // - 包含对msg.sender和_admin的比较
    let has_admin_check = code_hex.contains("6001600160a01b0316330361");
    debug!("检查admin比较: {}", has_admin_check);
    
    // - 包含对函数选择器的比较
    let has_selector_check = code_hex.contains("6001600160e01b031916") && code_hex.contains("63278f794360e11b");
    debug!("检查选择器比较: {}", has_selector_check);
    
    // - 包含对升级逻辑的调用
    let has_upgrade_call = code_hex.contains("600080366000845af43d6000803e");
    debug!("检查升级调用: {}", has_upgrade_call);
    
    // 所有特征都匹配才表示这是通过fallback实现的upgradeToAndCall
    has_admin_check && has_selector_check && has_upgrade_call
}

// 检查函数选择器是否存在，并添加升级函数信息
fn check_and_add_upgrade_function(
    code: &[u8],
    selector: &str,
    name: &str,
    location: &str,
    upgrade_functions: &mut Vec<UpgradeFunction>,
) {
    let result = has_function_selector(code, selector);
    debug!("检查选择器 {} 在 {} 中的匹配结果：{}", selector, location, result);
    if result {
        upgrade_functions.push(UpgradeFunction {
            name: name.to_string(),
            location: location.to_string(),
        });
    }
}

async fn analyze_proxy(
    proxy_address: Address,
    provider: &Provider<Http>,
) -> Result<ProxyInfo> {
    info!("正在分析合约：{:#x}", proxy_address);

    let impl_slot: H256 = H256::from_str(IMPLEMENTATION_SLOT)?;
    let admin_slot = H256::from_str(ADMIN_SLOT)?;
    let beacon_slot = H256::from_str(BEACON_SLOT)?;

    let code = provider.get_code(proxy_address, None).await
        .wrap_err_with(|| format!("无法获取合约 {} 的代码", format_address(proxy_address)))?;
    let impl_storage = provider.get_storage_at(proxy_address, impl_slot, None).await
        .wrap_err_with(|| format!("无法获取合约 {} 的实现存储槽", format_address(proxy_address)))?;
    let admin_storage = provider.get_storage_at(proxy_address, admin_slot, None).await
        .wrap_err_with(|| format!("无法获取合约 {} 的管理员存储槽", format_address(proxy_address)))?;
    let beacon_storage = provider.get_storage_at(proxy_address, beacon_slot, None).await
        .wrap_err_with(|| format!("无法获取合约 {} 的信标存储槽", format_address(proxy_address)))?;

    let code_bytes = code.to_vec();
    let code_size = code_bytes.len();

    info!("获取的合约代码长度：{} 字节", code_size);
    debug!("合约代码内容：{:?}", code_bytes);

    if code_size == 0 {
        error!("错误：地址 {} 不是合约", format_address(proxy_address));
        return Err(eyre::eyre!("地址不是合约"));
    }

    info!("合约代码大小：{} 字节", code_size);

    // 解析地址
    let mut implementation_address = None;
    let mut admin_address = None;
    let mut admin_is_eoa = None;
    let mut beacon_address = None;
    let mut upgrade_functions = Vec::new();

    // 检查代理类型和升级函数
    let proxy_type = if admin_storage != H256::zero() {
        // TransparentProxy
        let admin = Address::from_slice(&admin_storage.as_fixed_bytes()[12..]);
        admin_address = Some(admin);
        implementation_address = Some(Address::from_slice(&impl_storage.as_fixed_bytes()[12..]));
        
        // 检查管理员是否为 EOA
        let admin_code = match provider.get_code(admin, None).await {
            Ok(code) => code,
            Err(e) => {
                error!("错误：无法获取管理员地址的代码 - {}", e);
                return Err(eyre::eyre!("无法获取管理员地址的代码"));
            }
        };
        admin_is_eoa = Some(admin_code.is_empty());
        
        // 检查代理合约中的所有函数
        // 1. 检查升级相关函数
        if has_fallback_function(&code_bytes, UPGRADE_TO) {
            upgrade_functions.push(UpgradeFunction {
                name: "upgradeTo(address)".to_string(),
                location: "代理合约(通过fallback)".to_string(),
            });
        } else {
            check_and_add_upgrade_function(&code_bytes, UPGRADE_TO, "upgradeTo(address)", "代理合约", &mut upgrade_functions);
        }
        
        if has_fallback_function(&code_bytes, UPGRADE_TO_AND_CALL) {
            upgrade_functions.push(UpgradeFunction {
                name: "upgradeToAndCall(address,bytes)".to_string(),
                location: "代理合约(通过fallback)".to_string(),
            });
        } else {
            check_and_add_upgrade_function(&code_bytes, UPGRADE_TO_AND_CALL, "upgradeToAndCall(address,bytes)", "代理合约", &mut upgrade_functions);
        }
        
        // 2. 检查管理员相关函数
        if has_fallback_function(&code_bytes, CHANGE_ADMIN) {
            upgrade_functions.push(UpgradeFunction {
                name: "changeAdmin(address)".to_string(),
                location: "代理合约(通过fallback)".to_string(),
            });
        } else {
            check_and_add_upgrade_function(&code_bytes, CHANGE_ADMIN, "changeAdmin(address)", "代理合约", &mut upgrade_functions);
        }
        
        if has_fallback_function(&code_bytes, ADMIN) {
            upgrade_functions.push(UpgradeFunction {
                name: "admin()".to_string(),
                location: "代理合约(通过fallback)".to_string(),
            });
        } else {
            check_and_add_upgrade_function(&code_bytes, ADMIN, "admin()", "代理合约", &mut upgrade_functions);
        }
        
        // 3. 检查实现合约相关函数
        if has_fallback_function(&code_bytes, IMPLEMENTATION) {
            upgrade_functions.push(UpgradeFunction {
                name: "implementation()".to_string(),
                location: "代理合约(通过fallback)".to_string(),
            });
        } else {
            check_and_add_upgrade_function(&code_bytes, IMPLEMENTATION, "implementation()", "代理合约", &mut upgrade_functions);
        };
        
        ProxyType::TransparentProxy
    } else if impl_storage != H256::zero() {
        // UUPS Proxy
        implementation_address = Some(Address::from_slice(&impl_storage.as_fixed_bytes()[12..]));
        
        // 检查实现合约中的升级函数
        info!("正在检查实现合约代码...");
        let impl_code = match provider.get_code(implementation_address.unwrap(), None).await {
            Ok(code) => code,
            Err(e) => {
                error!("错误：无法获取实现合约代码 - {}", e);
                return Err(eyre::eyre!("无法获取实现合约代码"));
            }
        };
        check_and_add_upgrade_function(&impl_code.to_vec(), AUTHORIZE_UPGRADE, "_authorizeUpgrade(address)", "实现合约", &mut upgrade_functions);
        check_and_add_upgrade_function(&impl_code.to_vec(), UPGRADE_TO, "upgradeTo(address)", "实现合约", &mut upgrade_functions);
        check_and_add_upgrade_function(&impl_code.to_vec(), UPGRADE_TO_AND_CALL, "upgradeToAndCall(address,bytes)", "实现合约", &mut upgrade_functions);
        
        // 检查代理合约中的基本函数
        check_and_add_upgrade_function(&code_bytes, PROXY_FUNCTION, "initialize(address,bytes)", "代理合约", &mut upgrade_functions);
        check_and_add_upgrade_function(&code_bytes, IMPLEMENTATION, "implementation()", "代理合约", &mut upgrade_functions);
        ProxyType::ERC1967Proxy
    } else if beacon_storage != H256::zero() {
        // BeaconProxy
        beacon_address = Some(Address::from_slice(&beacon_storage.as_fixed_bytes()[12..]));
        
        // 检查信标合约中的升级函数
        let beacon_code = match provider.get_code(beacon_address.unwrap(), None).await {
            Ok(code) => code,
            Err(e) => {
                error!("错误：无法获取信标合约代码 - {}", e);
                return Err(eyre::eyre!("无法获取信标合约代码"));
            }
        };
        check_and_add_upgrade_function(&beacon_code.to_vec(), UPGRADE_TO, "upgradeTo(address)", "信标合约", &mut upgrade_functions);
        check_and_add_upgrade_function(&beacon_code.to_vec(), IMPLEMENTATION, "implementation()", "信标合约", &mut upgrade_functions);
        if has_function_selector(&beacon_code.to_vec(), UPGRADE_TO) && has_function_selector(&beacon_code.to_vec(), IMPLEMENTATION) {
            ProxyType::BeaconProxy
        } else {
            ProxyType::Unknown
        }
    } else if has_function_selector(&code_bytes, UPGRADE_TO) && has_function_selector(&code_bytes, IMPLEMENTATION) {
        // 可能是独立的信标合约
        check_and_add_upgrade_function(&code_bytes, UPGRADE_TO, "upgradeTo(address)", "信标合约", &mut upgrade_functions);
        check_and_add_upgrade_function(&code_bytes, IMPLEMENTATION, "implementation()", "信标合约", &mut upgrade_functions);
        ProxyType::Unknown
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
    env_logger::init();

    let args = Args::parse();

    let provider = Provider::<Http>::try_from(args.rpc)?;

    let proxy_address = Address::from_str(&args.proxy)?;

    let proxy_info = analyze_proxy(proxy_address, &provider).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_function_selector() {
        // 模拟的合约代码字节数组
        let contract_code = hex::decode("608060405234801561001057600080fd5b5060405160208061012383398101806040528101908080518201929190505050806000819055505061016c806100416000396000f3fe6080604052600436106100565760003560e01c8063a5643bf81461005b578063d0e30db01461007f578063f2fde38b146100a3575b600080fd5b6100636100c1565b6040516100709190610120565b60405180910390f35b6100876100c7565b6040516100949190610120565b60405180910390f35b6100ab6100cd565b6040516100b89190610120565b60405180910390f35b60008054905090565b6000813590506100d68161013e565b92915050565b6000602082840312156100f257600080fd5b6000610100848285016100cb565b91505092915050565b6101128161011d565b82525050565b600060208201905061012d6000830184610109565b92915050565b600061013e8261011d565b91506101498261011d565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561017e5761017d61014e565b5b82820190509291505056fea2646970667358221220a3e2d9c0e2c4f9b7d9d3b6f2c3c6d0b0f6c0b5c0f6c0b5c0f6c0b5c0f6c0b5c064736f6c63430008040033").unwrap();

        // 已知的函数选择器
        let selector = "a5643bf8"; // 对应合约代码中的一个选择器

        // 调用函数并断言结果
        assert!(has_function_selector(&contract_code, selector));
    }

    #[test]
    fn test_transparent_proxy_fallback() {
        // TransparentProxy的字节码，包含了通过fallback实现的upgradeToAndCall
        let contract_code = hex::decode("608060405234801561001057600080fd5b50600436106100365760003560e01c80634f1ef2861461003b578063f851a44014610054575b600080fd5b61003e61006d565b005b34801561006057600080fd5b50610069610071565b005b61006b610071565b565b6000546001600160a01b0316331461008857600080fd5b600080546001600160a01b0319166001600160a01b0392909216919091179055565b").unwrap();

        // 检查是否能识别通过fallback实现的upgradeToAndCall
        assert!(has_fallback_function(&contract_code, UPGRADE_TO_AND_CALL));
        
        // 检查常规函数选择器检测
        assert!(has_function_selector(&contract_code, ADMIN));
    }

    #[test]
    fn test_all_function_selectors() {
        // 使用生成的合约字节码
        let contract_code = hex::decode(
            "6080604052348015600f57600080fd5b506101b58061001f6000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c80635ec292721161005b5780635ec29272146100825780638f28397014610082578063d1f5789414610095578063f851a440146100a857600080fd5b80633659cfe6146100825780634f1ef286146100955780635c60da1b146100a8575b600080fd5b6100936100903660046100d8565b50565b005b6100936100a33660046100fa565b505050565b604080516000815290519081900360200190f35b80356001600160a01b03811681146100d357600080fd5b919050565b6000602082840312156100ea57600080fd5b6100f3826100bc565b9392505050565b60008060006040848603121561010f57600080fd5b610118846100bc565b9250602084013567ffffffffffffffff81111561013457600080fd5b8401601f8101861361014557600080fd5b803567ffffffffffffffff8111"
        ).unwrap();

        // 所有已知的函数选择器
        let selectors = vec![
            AUTHORIZE_UPGRADE,
            UPGRADE_TO,
            UPGRADE_TO_AND_CALL,
            CHANGE_ADMIN,
            ADMIN,
            IMPLEMENTATION,
            PROXY_FUNCTION,
        ];

        // 检查每个选择器
        for selector in selectors {
            assert!(has_function_selector(&contract_code, selector), "选择器 {} 未匹配", selector);
        }
    }
}

