use base64;
use lazy_static::lazy_static;
use regex::Regex;
use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

// 使用 lazy_static 宏创建静态正则表达式对象，使用 lazy_static 宏可以在第一次使用正则表达式时初始化它们，以后就不需要再次编译。
lazy_static! {
    static ref IPV4_REGEX: Regex = Regex::new(r#"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"#).unwrap();
    static ref IPV6_REGEX: Regex = Regex::new(r#"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$"#).unwrap();
    static ref DOMAIN_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$").unwrap(); // 匹配所有域名，包括子域名，正则表达式只是粗略匹配，不保证域名的后缀都存在)
}

fn check_file_exist_or_zero_size(file: &str) {
    if !fs::metadata(file).is_ok() || fs::metadata(file).unwrap().len() == 0 {
        println!("找不到当前目录的{}文件，是否把文件的位置放错了？", file);
        wait_for_enter();
        std::process::exit(1);
    }
}

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

fn wait_for_enter() {
    print!("\n按Enter键退出程序 >>");
    io::stdout().flush().expect("无法刷新标准输出缓冲区");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("无法读取行");

    // 移除输入中的换行符
    let _ = input.trim();
    io::stdout().flush().expect("无法刷新缓冲区");
}

fn main() {
    let file = "wg-config.conf";
    check_file_exist_or_zero_size(file);
    println!("本程序的用途：以WireGuard配置文件的参数为基准，生成NekoRay链接。\n");
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
        if input_mtu.is_empty()
            || (input_mtu.parse::<i32>().is_ok()
                && (1280..=1500).contains(&input_mtu.parse::<i32>().unwrap()))
        {
            break;
        }
    }
    let base_str = if !input_mtu.is_empty() {
        update_base_info(file, Some(&input_mtu))
    } else {
        update_base_info(file, None)
    };
    println!("\n{:+<120}", "");
    loop {
        let mut input_endpoint = String::new();
        let mut ip: &str;
        let mut port: &str;
        loop {
            print!("\n输入Endpoint端点(主机地址:端口号，比如162.159.192.1:2408)：");
            io::stdout().flush().expect("无法刷新标准输出缓冲区");
            input_endpoint.clear();
            io::stdin()
                .read_line(&mut input_endpoint)
                .expect("无法读取输入");
            input_endpoint = input_endpoint.trim().to_string();
            let mut parts: Vec<&str> = Vec::new();

            if input_endpoint.starts_with('[') {
                if let Some(end_idx) = input_endpoint.find(']') {
                    parts.push(&input_endpoint[1..end_idx]);
                    if let Some(port_idx) = input_endpoint[end_idx + 1..].find(':') {
                        parts.push(&input_endpoint[end_idx + 2 + port_idx..]);
                    }
                }
            } else if let Some(port_idx) = input_endpoint.find(':') {
                parts.push(&input_endpoint[..port_idx]);
                parts.push(&input_endpoint[port_idx + 1..]);
            }
            if parts.len() == 2 {
                ip = parts[0];
                port = parts[1];
                /* 变量ip是值是ipv4、ipv6、域名，而且端口是合法的就跳出死循环 */
                if IPV4_REGEX.is_match(ip) {
                    if let (Ok(_ipv4), Ok(_parsed_port)) =
                        (ip.parse::<Ipv4Addr>(), port.parse::<u16>())
                    {
                        break;
                    }
                } else if IPV6_REGEX.is_match(ip) {
                    if let (Ok(_ipv6), Ok(_parsed_port)) =
                        (ip.parse::<Ipv6Addr>(), port.parse::<u16>())
                    {
                        break;
                    }
                } else if DOMAIN_REGEX.is_match(ip) {
                    if let (Ok(_hostname), Ok(_parsed_port)) =
                        (ip.parse::<String>(), port.parse::<u16>())
                    {
                        break;
                    }
                }
            } else {
                // parts长度不是2的情况
            }
        }

        let mut input_prefix = String::new();
        print!("添加节点名称或别名的前缀吗？(比如，CN)：");
        io::stdout().flush().expect("无法刷新标准输出缓冲区");
        io::stdin()
            .read_line(&mut input_prefix)
            .expect("无法读取输入");
        input_prefix = input_prefix.trim().to_string();
        let prefix = if !input_prefix.is_empty() {
            format!("{}_", input_prefix)
        } else {
            "".to_string()
        };
        let host_name;
        // 处理地址是IPv6的情况，加一个中括号
        if ip.contains(':') {
            host_name = format!("[{}]", ip);
        } else {
            host_name = ip.to_string();
        };
        let node = base_str
            .replace("{name}", &format!("{}{}:{}", prefix, host_name, port))
            .replace("{server}", ip)
            .replace("{server_port}", port);
        let encoded = base64::encode(node);
        let transport_protocol = "nekoray://custom#";
        let nekoray_node = format!("{}{}", transport_protocol, encoded);

        println!("\n{:-<52}NekoRay节点如下:{:-<52}", "", "");
        println!("{}", nekoray_node);
        // 复制到剪贴板
        let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();
        clipboard.set_contents(nekoray_node.to_owned()).unwrap();
        println!("{:-<120}", "");
        println!("\n生成的NekoRay链接已复制到剪切板，可以黏贴到NekoBox软件中使用！记得要切换为sing-box核心。\n");
        println!("{:+<120}", "");
    }
}
