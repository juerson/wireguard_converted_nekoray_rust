#[allow(deprecated)]
extern crate base64;
use regex::Regex;
use std::fs;
use std::io::{self, Write};
use std::net::Ipv6Addr;
use std::net::Ipv4Addr;
use lazy_static::lazy_static;


// 使用 lazy_static 宏创建静态正则表达式对象，使用 lazy_static 宏可以在第一次使用正则表达式时初始化它们，以后就不需要再次编译。
lazy_static! {
    static ref IPV4_REGEX: Regex = Regex::new(r#"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"#).unwrap();
    static ref IPV6_REGEX: Regex = Regex::new(r#"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$"#).unwrap();
}

fn check_file_exist_or_zero_size(file: &str) {
    if !fs::metadata(file).is_ok() || fs::metadata(file).unwrap().len() == 0 {
		println!("我检查不到当前目录下的{}文件，是否把文件位置放错？",file);
		wait_for_enter();
        std::process::exit(1);
    }
}

fn read_wireguard_key_parameters(file: &str) -> std::collections::HashMap<String, String> {
    let mut wireguard_param = std::collections::HashMap::new();
    let contents = fs::read_to_string(file).expect("无法读取文件");
    let lines: Vec<&str> = contents.lines().collect();

    for line in lines {
        if line.starts_with("PrivateKey") {
            wireguard_param.insert("PrivateKey".to_string(), line.replace(" ", "").replace("PrivateKey=", "").to_string());
        } else if line.starts_with("PublicKey") {
            wireguard_param.insert("PublicKey".to_string(), line.replace(" ", "").replace("PublicKey=", "").to_string());
        } else if line.starts_with("Address") {
            let cleaned_line = line.replace(" ", "").replace("Address=", "");
			let addresses: Vec<&str> = cleaned_line.split(',').collect();
            wireguard_param.insert("Address".to_string(), addresses.join(",").to_string());
        } else if line.starts_with("MTU") {
            wireguard_param.insert("MTU".to_string(), line.replace(" ", "").replace("MTU=", "").to_string());
        }
    }

    wireguard_param
}

fn update_base_info(file_name: &str, mtu: Option<&str>) -> String {
    let param = read_wireguard_key_parameters(file_name);
    let peer_public_key = param.get("PublicKey").unwrap().trim();
    let private_key = param.get("PrivateKey").unwrap().trim();
    let addresses = param.get("Address").unwrap().split(',').collect::<Vec<&str>>();
    let ipv4 = addresses[0].trim();
    let ipv6 = addresses[1].trim();
    let mtu_value = mtu.unwrap_or(param.get("MTU").unwrap()).trim();
    
    let nekoray_str = r#"{"_v":0,"addr":"127.0.0.1","cmd":[""],"core":"internal","cs":"{\n  \"interface_name\": \"WARP\",\n  \"local_address\": [\n    \"{ipv4}\",\n    \"{ipv6}\"\n  ],\n  \"mtu\": {mtu_value},\n  \"peer_public_key\": \"{peer_public_key}\",\n  \"private_key\": \"{private_key}\",\n  \"server\": \"{server}\",\n  \"server_port\": {server_port},\n  \"system_interface\": false,\n  \"tag\": \"proxy\",\n  \"type\": \"wireguard\"\n}","mapping_port":0,"name":"{name}","port":1080,"socks_port":0}"#;
    let nekoray_str_json = nekoray_str
        .replace("{ipv4}", ipv4)
        .replace("{ipv6}", ipv6)
        .replace("{mtu_value}", &mtu_value.to_string())
        .replace("{peer_public_key}", peer_public_key)
        .replace("{private_key}", private_key);
	// nekoray_str字符串中，还有{name}、{server}、{server_port}这三项没有替换，在后面代码中才替换
    nekoray_str_json
}

fn wait_for_enter() {
    print!("\n按Enter回车键退出程序...");
    io::stdout().flush().expect("无法刷新标准输出缓冲区");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("无法读取行");
    
    // 移除输入中的换行符
    let _ = input.trim();

    print!("程序已退出");
    io::stdout().flush().expect("无法刷新缓冲区");
}

fn main() {
    let file = "wg-config.conf";
    check_file_exist_or_zero_size(file);
	println!("本程序可以将WARP的WireGuard配置文件的信息转为NekoRay节点！\n");
    let mut input_mut = String::new();
    loop {
        print!("是否修改MTU值(默认是配置文件中的值，可用的取值范围1280~1500)：");
        io::stdout().flush().expect("无法刷新缓冲区");
        input_mut.clear();
        io::stdin().read_line(&mut input_mut).expect("无法读取输入");
        input_mut = input_mut.trim().to_string();
        if input_mut.is_empty() || (input_mut.parse::<i32>().is_ok() && (1280..=1500).contains(&input_mut.parse::<i32>().unwrap())) {
            break;
        }
    }
    let base_str = if !input_mut.is_empty() {
		update_base_info(file, Some(&input_mut))
	} else {
		update_base_info(file, None)
	};
	println!("\n{:+<101}", "");
	loop {
		let mut input_endpoint = String::new();
		let mut ip;
		let mut port;
		loop {
			print!("\n输入优选IP(格式：162.159.192.1:2408)：");
			io::stdout().flush().expect("无法刷新标准输出缓冲区");
			input_endpoint.clear();
			io::stdin().read_line(&mut input_endpoint).expect("无法读取输入");
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
				if IPV4_REGEX.is_match(ip) {
				if let Ok(_ipv4) = ip.parse::<Ipv4Addr>() {
						break
					}
				} else if IPV6_REGEX.is_match(ip) {
					if let Ok(_ipv6) = ip.parse::<Ipv6Addr>() {
						break
					}
				}
			} else {
				
			}
		}

		let mut input_country = String::new();
		print!("添加节点名称或别名的前缀吗？(比如，CN)：");
		io::stdout().flush().expect("无法刷新标准输出缓冲区");
		io::stdin().read_line(&mut input_country).expect("无法读取输入");
		input_country = input_country.trim().to_string();
		let country = if !input_country.is_empty() {
			format!("{}_", input_country)
		} else {
			"".to_string()
		};
		let host_name;
		if ip.contains(':') {
			host_name = format!("[{}]",ip);
		} else {
			host_name = ip.to_string();
		};
		let node = base_str.replace("{name}", &format!("{}{}:{}", country, host_name, port)).replace("{server}", ip).replace("{server_port}", port);
		let encoded = base64::encode(node);
		let transport_protocol = "nekoray://custom#";
		let nekoray_node = format!("{}{}", transport_protocol, encoded);
		
		println!("\n{:-<43}NekoRay节点如下{:-<43}", "", "");
		println!("{}", nekoray_node);
		println!("{:-<101}", "");
		println!("\n节点已经生成好，将上面的NekoRay链接复制到NekoBox软件使用即可！记得要切换为sing-box核心。\n");
		println!("{:+<101}", "");
	}
}
