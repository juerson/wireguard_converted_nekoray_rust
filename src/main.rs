use base64;
use lazy_static::lazy_static;
use regex::Regex;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

// 使用 lazy_static 宏创建静态正则表达式对象，使用 lazy_static 宏可以在第一次使用正则表达式时初始化它们，以后就不需要再次编译。
lazy_static! {
    static ref IPV4_REGEX: Regex = Regex::new(r#"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"#).unwrap();
    static ref IPV6_REGEX: Regex = Regex::new(r#"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$"#).unwrap();
    static ref DOMAIN_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$").unwrap(); // 匹配所有域名，包括子域名，正则表达式只是粗略匹配，不保证域名的后缀都存在)
}

/* 检查文件是否缺少或大小为空 */
fn check_file_exist_or_zero_size(files: Vec<&str>) {
    for file in files {
        if !fs::metadata(file).is_ok() || fs::metadata(file).unwrap().len() == 0 {
            println!("找不到当前目录的{}文件，是否把文件的位置放错了？", file);
            wait_for_enter();
            std::process::exit(1);
        }
    }
}

/* 读取wireguard配置文件中的参数（选择性提取参数的值） */
fn read_wireguard_key_parameters(file: &str) -> std::collections::HashMap<String, String> {
    let contents = fs::read_to_string(file).expect("无法读取文件");
    let lines: Vec<&str> = contents.lines().collect();
    let mut wireguard_param = std::collections::HashMap::new();

    for line in lines {
        if line.starts_with("PrivateKey") {
            wireguard_param.insert(
                "PrivateKey".to_string(),
                line.replace(" ", "").replace("PrivateKey=", "").to_string(),
            );
        } else if line.starts_with("PublicKey") {
            wireguard_param.insert(
                "PublicKey".to_string(),
                line.replace(" ", "").replace("PublicKey=", "").to_string(),
            );
        } else if line.starts_with("Address") {
            // 清理行，移除空格和"Address="字符串，然后切割得到地址列表
            let cleaned_line = line.replace(" ", "").replace("Address=", "");
            let new_addresses: Vec<&str> = cleaned_line.split(',').collect();
            // 获取已经存在的地址列表，如果不存在，就用空列表代替
            let mut existing_addresses: Vec<String> = match wireguard_param.get("Address") {
                Some(val) => val.split(',').map(|s| s.to_string()).collect(),
                None => vec![],
            };
            // 将新地址添加到已经存在的地址列表中
            for new_address in new_addresses {
                existing_addresses.push(new_address.to_string());
            }
            // 存储合并后的地址列表
            wireguard_param.insert("Address".to_string(), existing_addresses.join(","));
        } else if line.starts_with("MTU") {
            wireguard_param.insert(
                "MTU".to_string(),
                line.replace(" ", "").replace("MTU=", "").to_string(),
            );
        }
    }
    wireguard_param
}

/* 将从wireguard配置文件读取到的公共密钥、私有密钥、地址写入nekoray链接中(还有其他参数没有写入) */
fn update_base_info(file_name: &str, mtu: Option<&str>) -> String {
    let param = read_wireguard_key_parameters(file_name);
    let peer_public_key = param.get("PublicKey").unwrap().trim();
    let private_key = param.get("PrivateKey").unwrap().trim();
    let addresses = param
        .get("Address")
        .unwrap()
        .split(',')
        .collect::<Vec<&str>>();
    // local_address的值相当于Wireguard的Address的值
    let local_address = match addresses.as_slice() {
        [a] => format!(r#"\"{}\""#, a), // 如果只有一个元素，就返回这个元素的复制，为其添加双引号
        addrs => {
            let strs: Vec<String> = addrs
                .iter()
                .map(|&a| format!(r#"\n    \"{}\""#, a))
                .collect();
            format!(r#"[{}\n  ]"#, strs.join(",")) // 如果有多个元素，将所有的元素用","连接起来，并在前后各加一个中括号
        }
    };
    let mtu_value = match mtu {
        Some(val) => val.trim().to_string(),
        None => param
            .get("MTU")
            .unwrap_or(&String::from("1408"))
            .trim()
            .to_string(),
    };
    let nekoray_str = r#"{"_v":0,"addr":"127.0.0.1","cmd":[""],"core":"internal","cs":"{\n  \"interface_name\": \"WARP\",\n  \"local_address\": {local_address},\n  \"mtu\": {mtu_value},\n  \"peer_public_key\": \"{peer_public_key}\",\n  \"private_key\": \"{private_key}\",\n  \"server\": \"{server}\",\n  \"server_port\": {server_port},\n  \"system_interface\": false,\n  \"tag\": \"proxy\",\n  \"type\": \"wireguard\"\n}","mapping_port":0,"name":"{name}","port":1080,"socks_port":0}"#;
    let nekoray_str_json = nekoray_str
        .replace("{local_address}", &local_address)
        .replace("{mtu_value}", &mtu_value.to_string())
        .replace("{peer_public_key}", peer_public_key)
        .replace("{private_key}", private_key);
    // nekoray_str字符串中，还有{name}、{server}、{server_port}这三项没有替换，在后面代码中才替换
    nekoray_str_json
}

/* 辅助函数 */
fn wait_for_enter() {
    print!("\n按Enter退出程序>>");
    io::stdout().flush().expect("无法刷新标准输出缓冲区");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("无法读取行");

    let _ = input.trim();
    io::stdout().flush().expect("无法刷新缓冲区");
}

/* 将Endpoint的主机地址和端口写入到nekoray链接中 */
fn generate_nekoray_node(ips_vec: Vec<String>, prefix: String, base_str: String) -> Vec<String> {
    let mut nekoray_node_vec: Vec<String> = Vec::new();
    for ip_with_port in ips_vec {
        let mut parts: Vec<&str> = Vec::new();
        if ip_with_port.starts_with('[') {
            if let Some(end_idx) = ip_with_port.find(']') {
                parts.push(&ip_with_port[1..end_idx]);
                if let Some(port_idx) = ip_with_port[end_idx + 1..].find(':') {
                    parts.push(&ip_with_port[end_idx + 2 + port_idx..]);
                }
            }
        } else if let Some(port_idx) = ip_with_port.find(':') {
            parts.push(&ip_with_port[..port_idx]);
            parts.push(&ip_with_port[port_idx + 1..]);
        } else if ip_with_port.chars().any(|c| c.is_whitespace()) { // 检查字符串中是否包含任何空白字符（空格、制表符等）, 使用char::is_whitespace方法
            let splits: Vec<&str> = ip_with_port.split_whitespace().collect();
            if splits.len() == 2 {
                for part in splits {
                    parts.push(part);
                }
            } else {
                continue;
            }
        } else {
            continue;
        }
        if parts.len() != 2 {
            continue;
        }
        let (ip, port) = (parts[0], parts[1]);
        // 不是IPv4地址、IPv6地址、域名主机的都跳过
        match ip {
            _ if IPV4_REGEX.is_match(ip) => {
                ip.parse::<Ipv4Addr>().ok();
            }
            _ if IPV6_REGEX.is_match(ip) => {
                ip.parse::<Ipv6Addr>().ok();
            }
            _ if DOMAIN_REGEX.is_match(ip) => {
                ip.parse::<String>().ok();
            }
            _ => {
                continue;
            }
        }
        // 尝试将端口解析为u16类型
        match port.parse::<u16>() {
            Ok(parsed_port) => {
                // 端口解析成功
                // 遇到ip是ipv6地址时，添加中括号
                let host_name = if ip.contains(':') {
                    format!("[{}]", ip)
                } else {
                    ip.to_string()
                };
                let node = base_str.replace(
                        "{name}",
                        &format!("{}{}:{}", prefix, host_name, parsed_port),
                    )
                    .replace("{server}", ip)
                    .replace("{server_port}", &parsed_port.to_string());
                let encoded = base64::encode(node);
                let transport_protocol = "nekoray://custom#";
                let nekoray_node = format!("{}{}", transport_protocol, encoded);
                println!("{}:{} => Nekoray链接已生成！", host_name, parsed_port);
                nekoray_node_vec.push(nekoray_node);
            }
            Err(_) => {
                // 解析失败，端口不是合法的数字
                continue;
            }
        }
    }
    return nekoray_node_vec;
}

fn main() -> std::io::Result<()> {
    let files_vec = vec!["wg-config.conf", "ip.txt", "output.txt"];
    let input_files_vec = files_vec.clone();
    check_file_exist_or_zero_size(input_files_vec[0..1].to_vec()); // 将第1、2个元素切片出来，然后将切片转换为新的向量
    println!("本程序的用途：以WireGuard配置文件的参数为基准，批量生成NekoRay链接。\n");
    let content = fs::read_to_string(files_vec[1])?;
    let mut ips_vec: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed_line = line.trim().to_string();
        if trimmed_line.is_empty() {
            continue; // 如果这一行是空的，跳过这一行
        }
        ips_vec.push(trimmed_line);
    }
    println!(
        "是否修改MTU值？输入内容为空时，就默认为配置文件的值，配置文件中没有MTU值，就使用1408；"
    );
    let mut input_mtu = String::new();
    loop {
        print!("这里输入MTU值，取值范围为1280~1500：");
        io::stdout().flush().expect("无法刷新缓冲区");
        input_mtu.clear();
        io::stdin().read_line(&mut input_mtu).expect("无法读取输入");
        input_mtu = input_mtu.trim().to_string();
        if input_mtu.is_empty() {
            break;
        }
        if let Ok(parsed) = input_mtu.parse::<i32>() {
            if (1280..=1500).contains(&parsed) {
                break;
            }
        }
    }
    let base_str = if !input_mtu.is_empty() {
        update_base_info(files_vec[0], Some(&input_mtu))
    } else {
        update_base_info(files_vec[0], None)
    };

    println!("\n{:-<85}", "");
    print!("添加节点名称或别名的前缀吗？(比如，CN)：");
    io::stdout().flush().expect("无法刷新标准输出缓冲区");
    let mut input_prefix = String::new();
    io::stdin()
        .read_line(&mut input_prefix)
        .expect("无法读取输入");
    input_prefix = input_prefix.trim().to_string();
    let prefix = if !input_prefix.is_empty() {
        format!("{}_", input_prefix)
    } else {
        String::new()
    };

    println!("{:-<85}", "");

    // 批量生成nekoray链接
    let nekoray_node_vec = generate_nekoray_node(ips_vec, prefix, base_str);
    // 检查是否生成nekoray链接
    if nekoray_node_vec.len() > 0 {
        println!("{:-<85}", "");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(files_vec[2])?;
        for nekoray_node in nekoray_node_vec {
            writeln!(file, "{}", nekoray_node)?;
        }
        file.flush()?;
        println!("生成的Nekoray链接已经写入{}文件中！", files_vec[2]);
    } else {
        println!("没有生成任何Nekoray链接！");
    }

    wait_for_enter();

    Ok(())
}
