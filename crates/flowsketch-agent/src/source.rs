//! Capture sources: pcap replay (portable; demos and tests) and AF_PACKET
//! live capture (Linux raw socket; requires CAP_NET_RAW).

use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use flowsketch_core::FlowEvent;
use flowsketch_pcap::PcapReader;
#[cfg(target_os = "linux")]
use flowsketch_pcap::{linktype, parse_packet};

use crate::config::SourceConfig;
#[cfg(target_os = "linux")]
use crate::offer_event;
use crate::state::PublishedState;
use crate::AgentError;

#[cfg(target_os = "linux")]
const AF_PACKET_STATS_INTERVAL: Duration = Duration::from_secs(1);

pub fn capture_loop(
    source: SourceConfig,
    tx: SyncSender<FlowEvent>,
    state: Arc<PublishedState>,
) -> Result<(), AgentError> {
    let result = match source {
        SourceConfig::Pcap { path } => pcap_loop(&path, &tx, &state),
        SourceConfig::AfPacket { interface } => af_packet_loop(&interface, &tx, &state),
    };
    if let Err(e) = &result {
        *state.source_error.lock().unwrap() = Some(e.to_string());
    }
    result
}

fn pcap_loop(
    path: &std::path::Path,
    tx: &SyncSender<FlowEvent>,
    state: &PublishedState,
) -> Result<(), AgentError> {
    let file = std::fs::File::open(path)
        .map_err(|e| AgentError::Source(format!("cannot open {}: {e}", path.display())))?;
    let mut reader = PcapReader::new(std::io::BufReader::new(file))
        .map_err(|e| AgentError::Source(e.to_string()))?;
    let mut packet_buf = Vec::with_capacity(2048);
    while let Some(event) = reader
        .next_event_into(&mut packet_buf)
        .map_err(|e| AgentError::Source(e.to_string()))?
    {
        state.packets_seen.fetch_add(1, Ordering::Relaxed);
        // File replay has no liveness constraint: block (backpressure)
        // rather than drop, so results cover the whole trace. Live capture
        // (af_packet) uses the non-blocking drop-and-count path instead.
        if tx.send(event).is_err() {
            break; // engine gone
        }
    }
    Ok(())
}

/// AF_PACKET live capture. Linux only; other platforms return a clear
/// configuration/runtime error.
#[cfg(target_os = "linux")]
fn af_packet_loop(
    interface: &str,
    tx: &SyncSender<FlowEvent>,
    state: &PublishedState,
) -> Result<(), AgentError> {
    let sock = AfPacketSocket::open(interface)?;
    let mut buf = vec![0u8; 65_536];
    let mut last_statistics = Instant::now();
    loop {
        let len = match sock.recv(&mut buf) {
            Ok(0) => continue,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // SO_RCVTIMEO wakes an idle capture loop so kernel drops do
                // not remain invisible until another packet arrives.
                if last_statistics.elapsed() >= AF_PACKET_STATS_INTERVAL {
                    record_packet_statistics(&sock, state, interface)?;
                    last_statistics = Instant::now();
                }
                continue;
            }
            Err(e) => return Err(AgentError::Source(format!("recv on {interface}: {e}"))),
        };
        state.packets_seen.fetch_add(1, Ordering::Relaxed);
        if last_statistics.elapsed() >= AF_PACKET_STATS_INTERVAL {
            record_packet_statistics(&sock, state, interface)?;
            last_statistics = Instant::now();
        }
        if let Some(mut event) = parse_packet(linktype::ETHERNET, &buf[..len]) {
            event.ts_nanos = now_nanos();
            if event.bytes == 0 {
                event.bytes = len as u32;
            }
            if !offer_event(tx, event, state) {
                return Ok(());
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn record_packet_statistics(
    sock: &AfPacketSocket,
    state: &PublishedState,
    interface: &str,
) -> Result<(), AgentError> {
    let stats = sock
        .statistics()
        .map_err(|e| AgentError::Source(format!("PACKET_STATISTICS on {interface}: {e}")))?;
    state
        .kernel_dropped_packets
        .fetch_add(stats.tp_drops as u64, Ordering::Relaxed);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn af_packet_loop(
    interface: &str,
    _tx: &SyncSender<FlowEvent>,
    _state: &PublishedState,
) -> Result<(), AgentError> {
    Err(AgentError::Source(format!(
        "af_packet source ({interface}) is only supported on Linux"
    )))
}

#[cfg(target_os = "linux")]
fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Thin RAII wrapper over a bound AF_PACKET socket.
#[cfg(target_os = "linux")]
struct AfPacketSocket {
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl AfPacketSocket {
    fn open(interface: &str) -> Result<Self, AgentError> {
        use std::os::fd::FromRawFd;

        // ETH_P_ALL in network byte order (htons), as socket(2) and
        // sockaddr_ll.sll_protocol both expect a 16-bit big-endian value.
        let proto_be: u16 = 0x0003u16.to_be();
        // SAFETY: plain socket(2) call; the fd is checked and wrapped in
        // OwnedFd immediately so it cannot leak.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto_be as i32) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(AgentError::Source(format!(
                "cannot open AF_PACKET socket (need CAP_NET_RAW / root): {err}"
            )));
        }
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

        let ifname = std::ffi::CString::new(interface)
            .map_err(|_| AgentError::Source("interface name contains NUL".into()))?;
        // SAFETY: if_nametoindex reads a valid NUL-terminated string.
        let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        if ifindex == 0 {
            return Err(AgentError::Source(format!(
                "unknown interface {interface:?}"
            )));
        }

        // SAFETY: sockaddr_ll is zero-initialized then populated; bind reads
        // exactly size_of::<sockaddr_ll>() bytes from it.
        let rc = unsafe {
            let mut addr: libc::sockaddr_ll = std::mem::zeroed();
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_protocol = proto_be;
            addr.sll_ifindex = ifindex as i32;
            libc::bind(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(AgentError::Source(format!(
                "cannot bind to {interface}: {err}"
            )));
        }
        let socket = AfPacketSocket { fd };
        socket
            .set_receive_timeout(AF_PACKET_STATS_INTERVAL)
            .map_err(|e| {
                AgentError::Source(format!("cannot set receive timeout on {interface}: {e}"))
            })?;
        Ok(socket)
    }

    fn set_receive_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        let seconds: libc::time_t = timeout.as_secs().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "receive timeout is too large",
            )
        })?;
        let microseconds: libc::suseconds_t = timeout.subsec_micros().into();
        let timeout = libc::timeval {
            tv_sec: seconds,
            tv_usec: microseconds,
        };
        // SAFETY: setsockopt reads exactly one initialized timeval from the
        // valid pointer for the duration of the call.
        let rc = unsafe {
            libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&self.fd),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: recv writes at most buf.len() bytes into a valid buffer.
        let n = unsafe {
            libc::recv(
                std::os::fd::AsRawFd::as_raw_fd(&self.fd),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Read and reset the kernel's per-socket AF_PACKET counters. Linux
    /// accumulates `tp_drops` when the socket receive queue overflows before
    /// userspace can call `recv`.
    fn statistics(&self) -> std::io::Result<libc::tpacket_stats> {
        let mut stats = libc::tpacket_stats {
            tp_packets: 0,
            tp_drops: 0,
        };
        let mut len = std::mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes to the correctly typed
        // stats buffer and updates the valid socklen_t pointer.
        let rc = unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&self.fd),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut stats as *mut libc::tpacket_stats as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            Err(std::io::Error::last_os_error())
        } else if len < std::mem::size_of::<libc::tpacket_stats>() as libc::socklen_t {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "short PACKET_STATISTICS response",
            ))
        } else {
            Ok(stats)
        }
    }
}
