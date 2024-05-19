use std::io::{Read, Write};
use std::process::exit;
use std::{error::Error, fs::File,fs::create_dir_all, io::{self, BufRead}};
use std::env;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use regex::Regex;
use serde_yaml::{self,  Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::channel;
use std::net::IpAddr;
use reqwest::Client;
use ipnetwork::IpNetwork;
use std::sync::Arc;
use tokio;
use trust_dns_resolver::{AsyncResolver, config::{ResolverConfig, ResolverOpts}};
use clap::{Arg, Command, ArgAction};

// ANSI escape codes
const BLUE: &str = "\x1b[34m"; 
const RED: &str = "\x1b[31m"; 
const YELLOW: &str = "\x1b[33m"; 
const RESET: &str = "\x1b[0m"; 

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

# TODO:  use custom DNS server
"#;


fn logger(color: &str, sign: &str, msg: &str) {
    writeln!(io::stderr(), "[{}{}{RESET}] {}", color, sign, msg).unwrap();
}

macro_rules! error { ($msg:expr) => {logger(RED, "#", &$msg)}; }
macro_rules! info { ($msg:expr) => {logger(BLUE, "+", &$msg)}; }
macro_rules! warn { ($msg:expr) => {logger(YELLOW, "!", &$msg)}; }


async fn process_input(input: String, ips: Arc<Vec<String>>, ports: Arc<Vec<String>>, resolver: AsyncResolver<trust_dns_resolver::name_server::GenericConnection, trust_dns_resolver::name_server::GenericConnectionProvider<trust_dns_resolver::name_server::TokioRuntime>>, append: bool) -> () {
    let this_ip = match input.parse::<IpAddr>() {
        Ok(_ip) => {
            input.clone()
        }
        Err(_) => {
            // Lookup the IP addresses associated with a name.
            match resolver.lookup_ip(&input).await{
                Ok(lookup_result) =>   lookup_result.iter().next().unwrap().to_string(),
                Err(_) => "".to_owned()
            }
            
        }
    };
    if this_ip.trim().len() == 0{
        ()
    }
    let allow_print_ports = ports.len() != 0;
    
    if ips.contains(&this_ip) {

        if allow_print_ports && append {
            println!("{input}:80");
            println!("{input}:443");
        }
    } else{
        if !allow_print_ports{
            println!("{input}");
        }else{
            for port in ports.iter(){
                println!("{input}:{port}")
            }
        }
    }
}

/// Convert a list of CIDRs to a of IPs
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

/// Fetch new CIDRs from providers
async fn fetch_new_data(providers: &Value, path: &Path) -> Vec<String>{
    let reg = Regex::new(IPV4_CIDR_REGEX).unwrap();
    let mut result: Vec<String> = vec![];
    info!("Fetch new data...");
    let mut handles = vec![];
    let (cx, mut rx) = channel(100);
    let client = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();

    for url_value in providers.as_sequence().unwrap().iter(){
        let url = url_value.as_str().unwrap().to_string();
        let r = reg.clone();
        let cx_clone = cx.clone();
        let client_clone = client.clone();
        let handle = tokio::spawn(
             async move{
                match client_clone.get(url.clone()).send().await{
                    Ok(response) => {
                        if response.status().is_success() {
                            // Read the response body 
                            let body = response.text().await.unwrap();
                            // Find CIDRs with regex in response body
                            let cidrs = r.captures_iter(&body);
                            for cidr in cidrs.into_iter(){
                                let c = cidr.get(0).unwrap().as_str().to_string();
                                cx_clone.send(c).await.unwrap();

                            }
                        } else {
                            warn!(format!("Failed to fetch {} with status {}", url, response.status()));
                        }
                    },
                    Err(_) => warn!(format!("Failed to fetch {url}")),
                }
                // drop(cx_clone);
            }
        );
        handles.push(handle);
    }
    
    drop(cx);

    while let Some(i) = rx.recv().await {
        result.push(i);
    } 
    
    if result.len() == 0 {
        error!("Could't fetch any CIDR :(");
        exit(1);
    }

    let mut file = tokio::fs::File::create(path).await.unwrap();
    for i in result.clone().iter(){
        let _ = file.write_all(format!("{i}\n").as_bytes()).await;
    }
    cidr_to_ip(result.iter().map(|f| f.as_str()).collect())

}

/// Read CIDRs from "~/.config/cdnx/cidr.txt" and return list of IPs
fn load_cidr(path: &Path) -> Vec<String>{
    let mut buffer = String::new();
    let mut file = File::open(path).unwrap();
    let _ = file.read_to_string(&mut buffer);
    
    let data: Vec<&str> = buffer.trim().lines().collect();
    cidr_to_ip(data)
}

async fn load_configs() -> Result<Vec<String>, Box<dyn Error>> {
    let config_dir = PathBuf::from(env::var("HOME").unwrap() +  "/.config/cdnx");
    let config_file_path = config_dir.join("config.yaml");
    let cidr_file_path = config_dir.join("cidr.txt");
    
    let mut buffer = String::new();
    let yaml_data: serde_yaml::Value;
    let providers: Option<&Value>;
    let mut _result: Vec<String> = vec![];
    
    // if "~/.config/cdnx" and "~/.config/cdnx/config.yaml" exists
    if config_dir.as_path().exists() && config_file_path.as_path().exists() {
        // open "~/.config/cdnx/config.yaml" and read its data
        let mut file = File::open(config_file_path.as_path()).unwrap();
        let _ = file.read_to_string(&mut buffer);
        
        // parse YAML data 
        yaml_data  = serde_yaml::from_str(&buffer).unwrap();
        providers = Some(yaml_data.get("Providers").unwrap());

        // get Interval value and if not exists use default 172800s
        let interval = match yaml_data.get("Interval"){
            Some(value)=> value.as_u64().unwrap_or(172800),
            _ => 172800,
        };
        
        // if "~/.config/cdnx/cidr.txt" exists
        if cidr_file_path.as_path().exists() {
            let now = SystemTime::now();
            // only works on linux ext4 file systems; TODO: write last update in "~/.config/cdnx/config.yaml"
            let modified_time = cidr_file_path.metadata().unwrap().modified().unwrap();
            // calculate time passed from last update
            let gap = now.duration_since(modified_time).unwrap();
            
            // if time passed from last update was lower than 2 days
            if gap.as_secs() < interval {
                // load CIDRs from "~/.config/cdnx/cidr.txt"
                Ok(load_cidr(cidr_file_path.as_path()))
            }else{
                // fetch new data from providers
                Ok(fetch_new_data(&providers.unwrap(), &cidr_file_path).await)
            }
            
        }else{
            // fetch new data from providers
            Ok(fetch_new_data(&providers.unwrap(), &cidr_file_path).await)

        }
        
    } else {
        //create "~/.config/cdnx"
        let _ = create_dir_all(config_dir);
        // create "~/.config/cdnx/config.yaml" and write default value
        let mut file = File::create(config_file_path.as_path()).unwrap();
        let _ = file.write_all(CONTENT.as_bytes());
        
        // parse default YAML data and get providers list
        yaml_data = serde_yaml::from_str(&CONTENT).unwrap();
        providers = Some(yaml_data.get("Providers").unwrap());
        
        // fetch new data from providers
        Ok(fetch_new_data(&providers.unwrap(), &cidr_file_path).await)
    }
    
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let app = Command::new("cdnx")
    .arg(Arg::new("ports")
        .help("Comma-sperated ports (e.g 80,443,8000)")
        .value_delimiter(',')
    )
    .arg(Arg::new("append")
        .short('a')
        .help("Append CDN hosts")
        .action(ArgAction::SetTrue)
    ).get_matches();

    let mut ports: Vec<String> = Vec::new();
    let append = app.clone().get_flag("append");

    if let Some(p) = app.get_many::<String>("ports"){
        ports = p.collect::<Vec<_>>().iter().map(|f| f.to_string()).collect();
    }

    let resolver_config = ResolverConfig::default();
    let resolver_opts = ResolverOpts::default();
    let resolver = AsyncResolver::tokio(resolver_config, resolver_opts)?;
    
    let ports: Arc<Vec<String>> = Arc::from(ports.clone());
    let ips: Arc<Vec<String>> = Arc::from(load_configs().await?);
    let mut handles = vec![];
    let stdin_lock = io::stdin().lock();

    for line in stdin_lock.lines() {
        let port_copy = ports.clone();
        let ips_copy = ips.clone();
        let domain = line?;
        let resolver_clone = resolver.clone();

        let handle = tokio::spawn(process_input(domain, ips_copy, port_copy, resolver_clone, append));

        // Store the task handle in the vector
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
