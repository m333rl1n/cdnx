use std::io::{Read, Write};
use std::process::exit;
use std::{error::Error, fs::File, io::{self, BufRead}};
use std::{env, vec};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use regex::Regex;
use serde_yaml::{self,  Value};
use std::net::IpAddr;
use reqwest::blocking::Client;
use std::fs::create_dir_all;
use ipnetwork::IpNetwork;
use std::sync::Arc;
use tokio;
use trust_dns_resolver::{AsyncResolver, config::{ResolverConfig, ResolverOpts}};


const IPV4_CIDR_REGEX: &str = r#"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/(3[0-2]|[1-2][0-9]|[0-9]))"#;
const CONTENT: &str = r#"Providers:
    - https://api.fastly.com/public-ip-list
    - https://www.cloudflare.com/ips-v4
    - https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips
    - https://support.maxcdn.com/hc/en-us/article_attachments/360051920551/maxcdn_ips.txt
    - https://cachefly.cachefly.net/ips/rproxy.txt
    - https://docs-be.imperva.com/api/bundle/z-kb-articles-km/page/c85245b7.html
    - http://edge.sotoon.ir/ip-list.json
    - https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json
    - https://raw.githubusercontent.com/m333rl1n/cdnx/main/static-CIDRs.txt

# default interval is 2 day
Interval: 172800

# TODO:  use custom dns server
"#;

fn check_cdn(input: &String, input_ip: &String, ports: &Vec<String>, cdn_ips: &Vec<String>) {
    if cdn_ips.contains(input_ip) {
        println!("{input}:80");
        println!("{input}:443");
    } else{
        for port in ports.iter(){
            println!("{input}:{port}")
        }
    }
}

async fn process_input(input: String, ips: Arc<Vec<String>>, ports: Arc<Vec<String>>, resolver: AsyncResolver<trust_dns_resolver::name_server::GenericConnection, trust_dns_resolver::name_server::GenericConnectionProvider<trust_dns_resolver::name_server::TokioRuntime>>) {
    match input.parse::<IpAddr>() {
        Ok(_) => {
            check_cdn(&input,&input, &ports, &ips);
        }
        Err(_) => {
            // Lookup the IP addresses associated with a name.
            if let Ok(lookup_result) = resolver.lookup_ip(&input).await{
                    let ip = lookup_result.iter().next().unwrap();
                    check_cdn(&input, &ip.to_string(), &ports, &ips)
            }
        }
    }
}

fn cidr_to_ip(list: Vec<&str>) -> Vec<String> {
    let mut ips: Vec<String> = vec![];
    for item in list.into_iter(){
        let cidr_ips: IpNetwork = item.parse().unwrap();
        for ip in cidr_ips.into_iter(){
            ips.push(ip.to_string());
        }
    }
    ips

}

fn fetch_new_data(providers: &Value, path: &Path) -> Vec<String>{
    let reg = Regex::new(IPV4_CIDR_REGEX).unwrap();
    let mut result: Vec<String> = vec![];
    eprintln!("Fetch new data...");

    for url_value in providers.as_sequence().unwrap().iter(){
        let url = url_value.as_str().unwrap();
        let client = Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
        match client.get(url).send(){
            Ok(mut response) => {
                if response.status().is_success() {
                    // Read the response body 
                    let mut body = String::new();
                    let _ = response.read_to_string(&mut body);
        
                    let cidrs = reg.captures_iter(&body);
                    for cidr in cidrs.into_iter(){
                        let ip = cidr.get(0).unwrap().as_str().to_string();
                        result.push(ip);
                    }
        
                } else {
                    eprintln!("Failed to fetch {} with status {}", url, response.status());
                }
            },
            Err(_) => eprintln!("Failed to fetch {}", url),
        }
    }

    let mut file = File::create(path).unwrap();
    for line in result.clone().into_iter(){
        let _ = file.write_all(line.as_bytes());
        let _ = file.write_all(b"\n");
    }
    cidr_to_ip(result.iter().map(|f| f.as_str()).collect())

}

fn load_cidr(path: &Path) -> Vec<String>{
    let mut buffer = String::new();
    let mut file = File::open(path).unwrap();
    let _ = file.read_to_string(&mut buffer);
    
    let data: Vec<&str> = buffer.trim().lines().collect();
    cidr_to_ip(data)
}

fn load_configs() -> Result<Vec<String>, Box<dyn Error>> {
    let home_dir = env::var("HOME").unwrap();
    let config_dir = PathBuf::from(home_dir +  "/.config/cdnx");
    let config_file_path = config_dir.join("config.yaml");
    let cidr_file_path = config_dir.join("cidr.txt");
    
    // let config_path = Path::new(&config_str);
    let mut buffer = String::new();
    let  yaml_data: serde_yaml::Value;
    let  providers: Option<&Value>;
    let mut _result: Vec<String> = vec!["jadi.net".to_string()];
    
    if config_dir.as_path().exists() && config_file_path.as_path().exists() {
        let mut file = File::open(config_file_path.as_path()).unwrap();
        let _ = file.read_to_string(&mut buffer);
        
        yaml_data  = serde_yaml::from_str(&buffer).unwrap();
        providers = Some(yaml_data.get("Providers").unwrap());

        let interval = match yaml_data.get("Interval"){
            Some(value)=> value.as_u64().unwrap_or(172800),
            _ => 172800,
        };
        
        if cidr_file_path.as_path().exists() {
            let now = SystemTime::now();
            // only works on linux ext4 file systems
            let modified_time = cidr_file_path.metadata().unwrap().modified().unwrap();
            let gap = now.duration_since(modified_time).unwrap();
            
            if gap.as_secs() < interval {
                Ok(load_cidr(cidr_file_path.as_path()))
            }else{
                Ok(fetch_new_data(&providers.unwrap(), &cidr_file_path))
            }
            
        }else{
            Ok(fetch_new_data(&providers.unwrap(), &cidr_file_path))

        }
        
    } else {
        //create "~/.config/cdnx"

        let _ = create_dir_all(config_dir);

        let mut file = File::create(config_file_path.as_path()).unwrap();
        let _ = file.write_all(CONTENT.as_bytes());

        yaml_data = serde_yaml::from_str(&CONTENT).unwrap();
        providers = Some(yaml_data.get("Providers").unwrap());

        Ok(fetch_new_data(&providers.unwrap(), &cidr_file_path))
    }
    
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <port1,port2,port3,...>", args[0]);
        exit(0);
    }

    let resolver_config = ResolverConfig::default();
    let resolver_opts = ResolverOpts::default();
    let resolver = AsyncResolver::tokio(resolver_config, resolver_opts)?;
    
    let mut ports: Vec<String> = vec![];
    for p in  args[1].split(',').into_iter(){
        ports.push(p.to_owned())
    }
    let ports: Arc<Vec<String>> = Arc::from(ports);
    let ips: Arc<Vec<String>> = Arc::from(load_configs()?);
    let mut handles = vec![];
    let stdin_lock = io::stdin().lock();

    for line in stdin_lock.lines() {
       
        let port_copy = ports.clone();
        let ips_copy = ips.clone();
        let domain = line?;
        let resolver_clone = resolver.clone();

        let handle = tokio::spawn(process_input(domain, ips_copy, port_copy, resolver_clone));

        // Store the task handle in the vector
        handles.push(handle);
    }
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
