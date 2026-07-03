//! Capture sources: pcap replay (portable; demos and tests) and AF_PACKET
//! live capture (Linux raw socket; requires CAP_NET_RAW).

use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use flowsketch_core::FlowEvent;
use flowsketch_pcap::{linktype, parse_packet, PcapReader};

use crate::config::SourceConfig;
use crate::state::PublishedState;
use crate::{offer_event, AgentError};

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
    while let Some(event) = reader
        .next_event()
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

/// AF_PACKET live capture. Compiled on unix; returns a clear error on
/// other platforms.
#[cfg(unix)]
fn af_packet_loop(
    interface: &str,
    tx: &SyncSender<FlowEvent>,
    state: &PublishedState,
) -> Result<(), AgentError> {
    let sock = AfPacketSocket::open(interface)?;
    let mut buf = vec![0u8; 65_536];
    loop {
        let len = match sock.recv(&mut buf) {
            Ok(0) => continue,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(AgentError::Source(format!("recv on {interface}: {e}"))),
        };
        state.packets_seen.fetch_add(1, Ordering::Relaxed);
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

#[cfg(not(unix))]
fn af_packet_loop(
    interface: &str,
    _tx: &SyncSender<FlowEvent>,
    _state: &PublishedState,
) -> Result<(), AgentError> {
    Err(AgentError::Source(format!(
        "af_packet source ({interface}) is only supported on Linux"
    )))
}

#[cfg(unix)]
fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Thin RAII wrapper over a bound AF_PACKET socket.
#[cfg(unix)]
struct AfPacketSocket {
    fd: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl AfPacketSocket {
    fn open(interface: &str) -> Result<Self, AgentError> {
        use std::os::fd::FromRawFd;

        let eth_p_all: u16 = 0x0003; // ETH_P_ALL
                                     // SAFETY: plain socket(2) call; the fd is checked and wrapped in
                                     // OwnedFd immediately so it cannot leak.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (eth_p_all as u32).to_be() as i32,
            )
        };
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
            addr.sll_protocol = (eth_p_all as u32).to_be() as u16;
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
        Ok(AfPacketSocket { fd })
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
}
