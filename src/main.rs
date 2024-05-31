use clap::Parser;
use regex::Regex;
use reqwest::Client;
use serde_yaml::{self, Value};
use std::env;
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{error::Error, fs::create_dir_all, fs::File};
use tokio;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::channel;
use tokio::task::JoinSet;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    AsyncResolver,
};

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

#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    /// Comma-sperated ports (e.g 80,443,8000)
    ports: Option<String>,

    /// Number of threads
    #[arg(short, default_value_t = 100)]
    thread: usize,

    /// Append CDN hosts
    #[arg(short, default_value_t = false)]
    append: bool,

    /// Do not print any message
    #[arg(short, default_value_t = false)]
    quit: bool,
}

fn logger(color: &str, sign: &str, msg: &str) {
    writeln!(io::stderr(), "[{}{}{RESET}] {}", color, sign, msg).unwrap();
}

macro_rules! error {
    ($msg:expr) => {
        logger(RED, "#", &$msg)
    };
}
macro_rules! info {
    ($msg:expr) => {
        logger(BLUE, "+", &$msg)
    };
}
macro_rules! warn {
    ($msg:expr) => {
        logger(YELLOW, "!", &$msg)
    };
}

/// Fetch new CIDRs from providers
async fn fetch_new_data(providers: &Value, path: &Path, quit: bool) -> Result<(), Box<dyn Error>> {
    let reg = Regex::new(IPV4_CIDR_REGEX).unwrap();
    if !quit{
        info!("Fetch new data...");
    }
    let mut handles = vec![];
    let (cx, mut rx) = channel(100);
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    for url_value in providers.as_sequence().unwrap().iter() {
        let url = url_value.as_str().unwrap().to_string();
        let r = reg.clone();
        let cx_clone = cx.clone();
        let client_clone = client.clone();

        let handle = tokio::spawn(async move {
            match client_clone.get(url.clone()).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        // Read the response body
                        let body = response.text().await.unwrap();
                        // Find CIDRs with regex in response body
                        let cidrs = r.captures_iter(&body);
                        for cidr in cidrs.into_iter() {
                            let c = cidr.get(0).unwrap().as_str().to_string();
                            cx_clone.send(c).await.unwrap();
                        }

                        if !quit {
                            info!(format!("{url} DONE"));
                        }
                    } else {
                        if !quit {
                            warn!(format!(
                                "Failed to fetch {} with status {}",
                                url,
                                response.status()
                            ));
                        }
                    }
                }
                Err(_) => {
                    if !quit {
                        warn!(format!("Failed to fetch {url}"))
                    }
                }
            }
        });
        handles.push(handle);
    }

    let mut file: tokio::fs::File = tokio::fs::File::create(path).await.unwrap();
    let mut is_err = true;
    drop(cx);
    while let Some(i) = rx.recv().await {
        is_err = false;
        let _ = file.write_all(format!("{i}\n").as_bytes()).await;
    }

    if is_err {
        error!("Could't fetch any CIDR :(");
        exit(1);
    }

    Ok(())
}

async fn check_updates(quit: bool) -> Result<(), Box<dyn Error>> {
    let config_dir = PathBuf::from(env::var("HOME").unwrap() + "/.config/cdnx");
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
        yaml_data = serde_yaml::from_str(&buffer).unwrap();
        providers = Some(yaml_data.get("Providers").unwrap());

        // get Interval value and if not exists use default 172800s
        let interval = match yaml_data.get("Interval") {
            Some(value) => value.as_u64().unwrap_or(172800),
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
            if gap.as_secs() > interval {
                // fetch new data from providers
                fetch_new_data(&providers.unwrap(), &cidr_file_path, quit).await?;
            }
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
        fetch_new_data(&providers.unwrap(), &cidr_file_path, quit).await?;
    }
    Ok(())
}

fn is_cdn(cidrs: &Vec<String>, ip: &str) -> bool {
    for cidr_str in cidrs {
        if let Ok((network_ip, prefix_len)) = parse_cidr(&cidr_str) {
            if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                let is_in_range = is_ip_in_cidr(ip, network_ip, prefix_len);
                if is_in_range {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format".into());
    }

    let ip = Ipv4Addr::from_str(parts[0])?;
    let prefix_len: u8 = parts[1].parse()?;

    if prefix_len > 32 {
        return Err("Prefix length must be between 0 and 32".into());
    }

    Ok((ip, prefix_len))
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

fn is_ip_in_cidr(ip: Ipv4Addr, network_ip: Ipv4Addr, prefix_len: u8) -> bool {
    let ip_u32 = ipv4_to_u32(ip);
    let network_ip_u32 = ipv4_to_u32(network_ip);
    let netmask_u32 = !0u32 << (32 - prefix_len);
    (ip_u32 & netmask_u32) == (network_ip_u32 & netmask_u32)
}

fn read_cidrs() -> Vec<String> {
    let path = PathBuf::from(env::var("HOME").unwrap() + "/.config/cdnx").join("cidr.txt");

    let mut buffer = String::new();
    let mut file = File::open(path).unwrap();
    let _ = file.read_to_string(&mut buffer);

    let data: Vec<String> = buffer
        .trim()
        .lines()
        .map(|l| l.trim().to_string())
        .collect();
    data
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut ports: Vec<String> = Vec::new();
    let append = args.append;
    let max_concurrent = args.thread;

    if let Some(p) = args.ports {
        ports = p.split(',').map(|p| p.to_string()).collect();
    }
    let allow_print_ports = ports.len() != 0;

    let resolver_config = ResolverConfig::default();
    let resolver_opts = ResolverOpts::default();
    let resolver = Arc::from(AsyncResolver::tokio(resolver_config, resolver_opts)?);

    check_updates(args.quit).await?;
    let ip_ranges: Arc<Vec<String>> = Arc::from(read_cidrs());

    let stdin_lock = io::stdin().lock();
    let mut join_set = JoinSet::new();

    for line in stdin_lock.lines() {
        let domain = line?;
        let resolver_tmp = resolver.clone();
        let ip_ranges_tmp = ip_ranges.clone();
        let ports_tmp = ports.clone();

        while join_set.len() >= max_concurrent {
            join_set.join_next().await.unwrap().unwrap();
        }

        join_set.spawn(async move {
            let this_ip = match domain.parse::<IpAddr>() {
                Ok(__) => domain.clone(),
                Err(_) => match resolver_tmp
                    .ipv4_lookup(&(domain.clone().trim_end_matches('.').to_owned() + "."))
                    .await
                {
                    Ok(lookup_result) => lookup_result.iter().next().unwrap().to_string(),
                    Err(_) => "".to_string(),
                },
            };
            if this_ip.is_empty() {
                return ();
            }
            let is_this_cdn = is_cdn(&ip_ranges_tmp, &this_ip);

            if !allow_print_ports && ((is_this_cdn && append) || (!is_this_cdn)) {
                println!("{domain}");
                return ();
            }

            if is_this_cdn && append {
                println!("{domain}:80");
                println!("{domain}:443");
                return ();
            }
            if !is_this_cdn {
                for port in ports_tmp.iter() {
                    println!("{domain}:{port}")
                }
            }
        });
    }

    while let Some(output) = join_set.join_next().await {
        output.unwrap();
    }

    Ok(())
}
