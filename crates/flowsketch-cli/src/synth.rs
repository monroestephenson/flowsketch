//! `flowsketch synth`: reproducible synthetic pcap traces containing
//! background traffic, heavy talkers, and scanners — so replay, examples,
//! and benchmarks work without real captures.

use std::fs::File;
use std::io::BufWriter;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context, Result};

use flowsketch_core::hash::SplitMixRng;
use flowsketch_pcap::PcapWriter;

pub struct SynthOptions {
    pub packets: u64,
    pub scanners: u32,
    pub heavy_talkers: u32,
    pub duration_secs: u64,
    pub seed: u64,
    pub full_payload: bool,
    pub ipv6_percent: u8,
}

pub fn run(out: &Path, options: SynthOptions) -> Result<()> {
    let SynthOptions {
        packets,
        scanners,
        heavy_talkers,
        duration_secs,
        seed,
        full_payload,
        ipv6_percent,
    } = options;
    let file = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let writer = BufWriter::new(file);
    let mut w = if full_payload {
        PcapWriter::new_full_payload(writer)
    } else {
        PcapWriter::new(writer)
    }
    .context("cannot write pcap header")?;
    let mut rng = SplitMixRng::new(seed);

    let base_ts: u64 = 1_700_000_000_000_000_000;
    let span_nanos = duration_secs * 1_000_000_000;

    // Traffic mix: ~70% background, ~20% heavy talkers, ~10% scanners.
    let scanner_ips: Vec<Ipv4Addr> = (0..scanners)
        .map(|i| Ipv4Addr::new(10, 66, 0, (i + 1) as u8))
        .collect();
    let heavy_pairs: Vec<(Ipv4Addr, Ipv4Addr)> = (0..heavy_talkers)
        .map(|i| {
            (
                Ipv4Addr::new(10, 1, 1, (i + 10) as u8),
                Ipv4Addr::new(10, 2, 2, (i + 10) as u8),
            )
        })
        .collect();
    let scan_ports = [22u16, 80, 443, 5432, 6379];

    let mut scan_counter: u64 = 0;
    for i in 0..packets {
        // Timestamps advance monotonically with light jitter.
        let ts = base_ts + (i * span_nanos) / packets.max(1) + rng.next_u64() % 1_000_000;
        let roll = rng.next_u64() % 100;
        // Preserve byte-for-byte deterministic legacy traces when the new
        // option is left at its zero default by not consuming another RNG
        // value in that case.
        let use_ipv6 = ipv6_percent != 0 && rng.next_u64() % 100 < u64::from(ipv6_percent);

        if roll < 10 && !scanner_ips.is_empty() {
            // Scanner: one source sweeping many distinct destinations.
            let scanner_index = (rng.next_u64() % scanner_ips.len() as u64) as usize;
            let src_v4 = scanner_ips[scanner_index];
            scan_counter += 1;
            let dst_v4 = Ipv4Addr::new(
                10,
                (100 + (scan_counter >> 16) % 100) as u8,
                ((scan_counter >> 8) & 0xFF) as u8,
                (scan_counter & 0xFF) as u8,
            );
            let (src, dst) = if use_ipv6 {
                (
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001,
                        0x0db8,
                        0x0066,
                        0,
                        0,
                        0,
                        0,
                        (scanner_index + 1) as u16,
                    )),
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001,
                        0x0db8,
                        0x0100,
                        ((scan_counter >> 32) & 0xffff) as u16,
                        ((scan_counter >> 16) & 0xffff) as u16,
                        (scan_counter & 0xffff) as u16,
                        0,
                        1,
                    )),
                )
            } else {
                (IpAddr::V4(src_v4), IpAddr::V4(dst_v4))
            };
            let port = scan_ports[(rng.next_u64() % scan_ports.len() as u64) as usize];
            w.write_tcp_packet(
                ts,
                src,
                dst,
                40_000 + (rng.next_u64() % 20_000) as u16,
                port,
                0x02, // SYN
                60,
            )?;
        } else if roll < 30 && !heavy_pairs.is_empty() {
            // Heavy talker: large flows between fixed pairs.
            let pair_index = (rng.next_u64() % heavy_pairs.len() as u64) as usize;
            let (src_v4, dst_v4) = heavy_pairs[pair_index];
            let (src, dst) = if use_ipv6 {
                (
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001,
                        0x0db8,
                        1,
                        1,
                        0,
                        0,
                        0,
                        (pair_index + 10) as u16,
                    )),
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001,
                        0x0db8,
                        2,
                        2,
                        0,
                        0,
                        0,
                        (pair_index + 10) as u16,
                    )),
                )
            } else {
                (IpAddr::V4(src_v4), IpAddr::V4(dst_v4))
            };
            w.write_tcp_packet(
                ts,
                src,
                dst,
                33_000,
                443,
                0x18, // PSH|ACK
                1_200 + (rng.next_u64() % 200) as u32,
            )?;
        } else {
            // Background: modest flows between a moderate host population.
            let src = Ipv4Addr::new(
                10,
                9,
                (rng.next_u64() % 32) as u8,
                (rng.next_u64() % 250 + 1) as u8,
            );
            let dst = Ipv4Addr::new(
                10,
                8,
                (rng.next_u64() % 8) as u8,
                (rng.next_u64() % 250 + 1) as u8,
            );
            let (src, dst) = if use_ipv6 {
                (
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001,
                        0x0db8,
                        9,
                        rng.next_u64() as u16,
                        rng.next_u64() as u16,
                        0,
                        0,
                        1,
                    )),
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001,
                        0x0db8,
                        8,
                        rng.next_u64() as u16,
                        rng.next_u64() as u16,
                        0,
                        0,
                        1,
                    )),
                )
            } else {
                (IpAddr::V4(src), IpAddr::V4(dst))
            };
            if rng.next_u64() % 4 == 0 {
                w.write_udp_packet(
                    ts,
                    src,
                    dst,
                    50_000 + (rng.next_u64() % 10_000) as u16,
                    53,
                    80,
                )?;
            } else {
                w.write_tcp_packet(
                    ts,
                    src,
                    dst,
                    40_000 + (rng.next_u64() % 20_000) as u16,
                    if rng.next_u64() % 2 == 0 { 443 } else { 80 },
                    0x18,
                    200 + (rng.next_u64() % 800) as u32,
                )?;
            }
        }
    }

    println!(
        "wrote {} packets over {duration_secs}s to {} ({} scanner(s), {} heavy pair(s), {ipv6_percent}% IPv6, seed {seed})",
        w.packets_written(),
        out.display(),
        scanners,
        heavy_talkers,
    );
    Ok(())
}
