//! IP Network Deduplicator & Filter with Blacklist Support
//!
//! Usage:
//!   ./net-normalizer                    # stdin input
//!   ./net-normalizer input.json         # file input
//!   ./net-normalizer input.json restricted.json  # with blacklist

use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::process;

// -------------------- Types --------------------

#[derive(Deserialize, Debug, Clone)]
struct InputData {
    #[serde(default)]
    networks: Option<Vec<String>>,
    #[serde(default)]
    ips: Option<Vec<String>>,
}

#[derive(Serialize, Debug)]
struct OutputData {
    networks: Vec<String>,
    ips: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Range {
    start: u32,
    end: u32,
}

// -------------------- Errors --------------------

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    Parse(String),
    InvalidInput(String),
}

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self { AppError::Io(e) }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "IO error: {e}"),
            AppError::Parse(s) => write!(f, "Parse error: {s}"),
            AppError::InvalidInput(s) => write!(f, "Invalid input: {s}"),
        }
    }
}

type Result<T> = std::result::Result<T, AppError>;

// -------------------- Utils: IP conversions --------------------

#[inline]
fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

#[inline]
fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

fn net_to_range(net: &Ipv4Net) -> Option<Range> {
    Some(Range {
        start: ip_to_u32(net.network()),
         end: ip_to_u32(net.broadcast()),
    })
}

// -------------------- Core: Range merging --------------------

fn merge_ranges(mut ranges: Vec<Range>) -> Vec<Range> {
    if ranges.is_empty() {
        return Vec::new();
    }

    ranges.sort_unstable_by_key(|r| (r.start, r.end));
    let mut merged = Vec::with_capacity(ranges.len());
    let mut current = ranges[0];

    for &r in &ranges[1..] {
        if r.start == 0 || r.start.saturating_sub(1) <= current.end {
            current.end = current.end.max(r.end);
        } else {
            merged.push(current);
            current = r;
        }
    }
    merged.push(current);
    merged
}

// -------------------- Core: Range subtraction (FIXED) --------------------

fn subtract_ranges(input: Vec<Range>, restricted: Vec<Range>) -> Vec<Range> {
    if restricted.is_empty() {
        return input;
    }
    if input.is_empty() {
        return Vec::new();
    }

    let mut result = input;
    let mut restricted = restricted;

    // Сортируем restricted
    restricted.sort_unstable_by_key(|r| r.start);

    for restr in restricted {
        let mut new_result = Vec::new();

        for range in result {
            // Нет пересечения
            if restr.end < range.start || restr.start > range.end {
                new_result.push(range);
                continue;
            }

            // Полное покрытие (диапазон полностью удаляется)
            if restr.start <= range.start && restr.end >= range.end {
                continue;
            }

            // Частичное пересечение слева (restr закрывает начало range)
            if restr.start <= range.start && restr.end < range.end {
                let new_start = restr.end.saturating_add(1);
                if new_start <= range.end {
                    new_result.push(Range { start: new_start, end: range.end });
                }
                continue;
            }

            // Частичное пересечение справа (restr закрывает конец range)
            if restr.start > range.start && restr.end >= range.end {
                let new_end = restr.start.saturating_sub(1);
                if new_end >= range.start {
                    new_result.push(Range { start: range.start, end: new_end });
                }
                continue;
            }

            // Restricted внутри (диапазон разбивается на два)
            if restr.start > range.start && restr.end < range.end {
                let left_end = restr.start.saturating_sub(1);
                let right_start = restr.end.saturating_add(1);

                if left_end >= range.start {
                    new_result.push(Range { start: range.start, end: left_end });
                }
                if right_start <= range.end {
                    new_result.push(Range { start: right_start, end: range.end });
                }
                continue;
            }

            // Fallback
            new_result.push(range);
        }

        result = new_result;
        if result.is_empty() {
            break;
        }
    }

    result
}

// -------------------- Core: Range to minimal CIDRs --------------------

fn range_to_cidrs(range: Range) -> Vec<IpNet> {
    let mut result = Vec::new();
    let mut start = range.start as u64;
    let end = range.end as u64;

    while start <= end {
        let max_prefix = 32u32.saturating_sub(start.trailing_zeros() as u32);
        let mut prefix = max_prefix;

        while prefix < 32 {
            let block_size = 1u64 << (32 - prefix);
            if start + block_size - 1 <= end {
                break;
            }
            prefix += 1;
        }

        let network = u32_to_ip(start as u32);
        if let Ok(net) = IpNet::new(IpAddr::V4(network), prefix as u8) {
            result.push(net);
        }

        let block_size = 1u64 << (32 - prefix);
        start = start.saturating_add(block_size);

        if block_size == 0 { break; }
    }

    result
}

// -------------------- Core: IP filtering --------------------

fn ip_in_nets(ip: &IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

// -------------------- Parse networks helper --------------------

fn parse_networks(nets_input: &[String], label: &str) -> Result<Vec<Ipv4Net>> {
    let mut valid_nets = Vec::with_capacity(nets_input.len());
    for (idx, s) in nets_input.iter().enumerate() {
        match s.parse::<IpNet>() {
            Ok(IpNet::V4(net)) => valid_nets.push(net),
            Ok(IpNet::V6(_)) => {
                eprintln!("warn: skipping IPv6 {label} at index {idx}: {s}");
            }
            Err(e) => {
                return Err(AppError::InvalidInput(
                    format!("{label}[{idx}] '{s}': {e}")
                ));
            }
        }
    }

    let mut seen_nets = HashSet::with_capacity(valid_nets.len());
    let unique_nets: Vec<Ipv4Net> = valid_nets
    .into_iter()
    .filter(|n| seen_nets.insert(*n))
    .collect();

    Ok(unique_nets)
}

// -------------------- Parse IPs helper --------------------

fn parse_ips(ips_input: &[String], label: &str) -> Result<Vec<IpAddr>> {
    let mut valid_ips = Vec::with_capacity(ips_input.len());
    for (idx, s) in ips_input.iter().enumerate() {
        match s.parse::<IpAddr>() {
            Ok(ip) => valid_ips.push(ip),
            Err(e) => {
                return Err(AppError::InvalidInput(
                    format!("{label}[{idx}] '{s}': {e}")
                ));
            }
        }
    }
    Ok(valid_ips)
}

// -------------------- Main processing --------------------

fn process(input: InputData, restricted: Option<InputData>) -> Result<OutputData> {
    let nets_input = input.networks.unwrap_or_default();
    let ips_input = input.ips.unwrap_or_default();

    // Parse allowed networks
    let unique_nets = parse_networks(&nets_input, "network")?;

    // Convert to ranges & merge
    let ranges: Vec<Range> = unique_nets.iter().filter_map(|n| net_to_range(n)).collect();
    let merged_allowed = merge_ranges(ranges);

    // Subtract restricted networks (if provided)
    let final_ranges = if let Some(restr) = &restricted {
        let restr_nets_input = restr.networks.clone().unwrap_or_default();
        let restr_unique = parse_networks(&restr_nets_input, "restricted network")?;

        let restr_ranges: Vec<Range> = restr_unique.iter().filter_map(|n| net_to_range(n)).collect();
        let merged_restricted = merge_ranges(restr_ranges);

        subtract_ranges(merged_allowed, merged_restricted)
    } else {
        merged_allowed
    };

    // Convert back to CIDR
    let final_nets: Vec<IpNet> = final_ranges
    .into_iter()
    .flat_map(range_to_cidrs)
    .collect();

    // Parse allowed IPs
    let valid_ips = parse_ips(&ips_input, "ip")?;

    // Build restricted IP set
    let restricted_ip_set: HashSet<IpAddr> = restricted
    .as_ref()
    .map(|r| {
        let ips = r.ips.clone().unwrap_or_default();
        ips.iter().filter_map(|s| s.parse::<IpAddr>().ok()).collect()
    })
    .unwrap_or_default();

    // Filter IPs: keep if NOT in final_nets AND NOT in restricted_ip_set
    let mut filtered: Vec<IpAddr> = valid_ips
    .into_iter()
    .filter(|ip| {
        !ip_in_nets(ip, &final_nets) && !restricted_ip_set.contains(ip)
    })
    .collect();

    // Deduplicate IPs
    let mut seen_ips = HashSet::with_capacity(filtered.len());
    filtered.retain(|ip| seen_ips.insert(*ip));

    // Sort for deterministic output
    let mut network_strings: Vec<String> = final_nets.iter().map(|n| n.to_string()).collect();
    let mut ip_strings: Vec<String> = filtered.iter().map(|ip| ip.to_string()).collect();

    network_strings.sort();
    ip_strings.sort();

    Ok(OutputData {
        networks: network_strings,
       ips: ip_strings,
    })
}

// -------------------- I/O handling (FIXED) --------------------

fn read_input(args: &[String]) -> Result<(String, Option<String>)> {
    // args[0] = program path, args[1] = first real argument
    match args.len() {
        1 => {
            // No arguments → read from stdin
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer).map_err(AppError::Io)?;
            Ok((buffer, None))
        }
        2 => {
            // One argument → could be stdin|prog restricted.json OR prog input.json
            // Check if stdin has data (non-blocking check not possible, assume file)
            let input_json = std::fs::read_to_string(&args[1]).map_err(AppError::Io)?;
            Ok((input_json, None))
        }
        3 => {
            // Two arguments → input.json restricted.json
            let input_json = std::fs::read_to_string(&args[1]).map_err(AppError::Io)?;
            let restricted_json = std::fs::read_to_string(&args[2]).map_err(AppError::Io)?;
            Ok((input_json, Some(restricted_json)))
        }
        _ => Err(AppError::InvalidInput(
            "usage: net-normalizer [input.json] [restricted.json]".into()
        )),
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let (input_json, restricted_json) = read_input(&args)?;

    if input_json.trim().is_empty() {
        return Err(AppError::InvalidInput("empty input".into()));
    }

    let input: InputData = serde_json::from_str(&input_json)
    .map_err(|e| AppError::Parse(format!("input JSON: {e}")))?;

    let restricted: Option<InputData> = if let Some(restr) = restricted_json {
        if restr.trim().is_empty() {
            None
        } else {
            Some(serde_json::from_str(&restr)
            .map_err(|e| AppError::Parse(format!("restricted JSON: {e}")))?
            )
        }
    } else {
        None
    };

    let output = process(input, restricted)?;

    let json = serde_json::to_string(&output)
    .map_err(|e| AppError::Parse(format!("output JSON: {e}")))?;

    println!("{json}");
    Ok(())
}

// -------------------- Entry point --------------------

fn main() {
    let mut stderr = io::stderr();

    match run() {
        Ok(()) => process::exit(0),
        Err(e) => {
            let _ = writeln!(stderr, "error: {e}");
            let code = match e {
                AppError::InvalidInput(_) => 2,
                _ => 1,
            };
            process::exit(code);
        }
    }
}

// -------------------- Tests --------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subtract_ranges_split() {
        let input = vec![Range { start: 100, end: 200 }];
        let restricted = vec![Range { start: 150, end: 160 }];

        let result = subtract_ranges(input, restricted);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], Range { start: 100, end: 149 });
        assert_eq!(result[1], Range { start: 161, end: 200 });
    }

    #[test]
    fn test_subtract_ranges_full_overlap() {
        let input = vec![Range { start: 100, end: 200 }];
        let restricted = vec![Range { start: 50, end: 250 }];

        let result = subtract_ranges(input, restricted);

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_subtract_ranges_no_overlap() {
        let input = vec![Range { start: 100, end: 200 }];
        let restricted = vec![Range { start: 300, end: 400 }];

        let result = subtract_ranges(input, restricted);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Range { start: 100, end: 200 });
    }

    #[test]
    fn test_merge_adjacent_ranges() {
        let ranges = vec![
            Range { start: 1, end: 10 },
            Range { start: 11, end: 20 },
        ];
        let merged = merge_ranges(ranges);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0], Range { start: 1, end: 20 });
    }

    #[test]
    fn test_ip_to_u32_roundtrip() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let n = ip_to_u32(ip);
        let ip2 = u32_to_ip(n);
        assert_eq!(ip, ip2);
    }
}
