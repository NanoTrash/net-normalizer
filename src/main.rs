use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Deserialize)]
struct InputData {
    networks: Option<Vec<String>>,
    ips: Option<Vec<String>>,
}

#[derive(Serialize)]
struct OutputData {
    networks: Vec<String>,
    ips: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
struct Range {
    start: u32,
    end: u32,
}

// -------------------- utils --------------------

fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

fn net_to_range(net: IpNet) -> Option<Range> {
    match net {
        IpNet::V4(n) => Some(Range {
            start: ip_to_u32(n.network()),
            end: ip_to_u32(n.broadcast()),
        }),
        _ => None,
    }
}

fn merge_ranges(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range> = Vec::new();

    for r in ranges {
        if let Some(last) = merged.last_mut() {
            if r.start <= last.end + 1 {
                last.end = last.end.max(r.end);
            } else {
                merged.push(r);
            }
        } else {
            merged.push(r);
        }
    }

    merged
}

fn range_to_cidrs(range: Range) -> Vec<IpNet> {
    let mut result = Vec::new();
    let mut start = range.start;
    let end = range.end;

    while start <= end {
        let max_size = start.trailing_zeros();
        let mut prefix = 32 - max_size;

        // корректировка, чтобы не выйти за диапазон
        while start + (1u32 << (32 - prefix)) - 1 > end {
            prefix += 1;
        }

        let prefix_u8: u8 = prefix
            .try_into()
            .expect("prefix out of range");

        let net = IpNet::new(u32_to_ip(start).into(), prefix_u8)
            .expect("invalid CIDR");

        result.push(net);

        start += 1u32 << (32 - prefix);
    }

    result
}

// -------------------- core --------------------

fn process(input: InputData) -> OutputData {
    let nets_input = input.networks.unwrap_or_default();
    let ips_input = input.ips.unwrap_or_default();

    // parse networks
    let nets: Vec<IpNet> = nets_input
        .iter()
        .filter_map(|n| n.parse::<IpNet>().ok())
        .collect();

    // dedup networks
    let mut net_set = HashSet::new();
    let nets: Vec<IpNet> = nets.into_iter().filter(|n| net_set.insert(*n)).collect();

    // convert to ranges
    let ranges: Vec<Range> = nets.into_iter().filter_map(net_to_range).collect();

    // merge
    let merged_ranges = merge_ranges(ranges);

    // back to CIDR
    let mut final_nets = Vec::new();
    for r in merged_ranges {
        final_nets.extend(range_to_cidrs(r));
    }

    // parse IPs
    let ips: Vec<IpAddr> = ips_input
        .iter()
        .filter_map(|ip| ip.parse().ok())
        .collect();

    // filter IPs covered by networks
    let mut filtered_ips: Vec<IpAddr> = ips
        .into_iter()
        .filter(|ip| !final_nets.iter().any(|n| n.contains(ip)))
        .collect();

    // dedup IPs
    let mut ip_set = HashSet::new();
    filtered_ips.retain(|ip| ip_set.insert(*ip));

    OutputData {
        networks: final_nets.iter().map(|n| n.to_string()).collect(),
        ips: filtered_ips.iter().map(|ip| ip.to_string()).collect(),
    }
}

// -------------------- entry --------------------

fn main() {
    let args: Vec<String> = env::args().collect();

    let input_json = if args.len() == 1 {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer).unwrap();
        buffer
    } else if args.len() == 2 {
        std::fs::read_to_string(&args[1]).unwrap()
    } else {
        eprintln!("Usage:");
        eprintln!("  tool <input.json>");
        eprintln!("  cat input.json | tool");
        return;
    };

    let input: InputData = serde_json::from_str(&input_json).unwrap();
    let output = process(input);

    let json = serde_json::to_string_pretty(&output).unwrap();
    println!("{}", json);
}