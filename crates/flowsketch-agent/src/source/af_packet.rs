//! Linux AF_PACKET capture backed by a TPACKET_V3 memory-mapped receive ring.
//!
//! All shared-memory pointer handling is isolated here. Kernel-owned blocks
//! are read only after an acquire load observes `TP_STATUS_USER`, and every
//! claimed block is returned with a release store to `TP_STATUS_KERNEL`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use libc::tpacket_versions::TPACKET_V3;

use crate::AgentError;

const FRAME_SIZE_BYTES: u32 = 2_048;
const POLL_TIMEOUT_MS: libc::c_int = 1_000;

#[derive(Debug, Clone, Copy)]
pub(super) struct RingSettings {
    pub block_size_bytes: u32,
    pub block_count: u32,
    pub retire_timeout_ms: u32,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PacketStatistics {
    pub packets: u32,
    pub drops: u32,
    pub queue_freezes: u32,
}

/// A bound AF_PACKET socket and its TPACKET_V3 receive ring.
pub(super) struct AfPacketSocket {
    // The mapping must be released before the socket is closed. Rust drops
    // struct fields in declaration order, so keep `ring` before `fd`.
    ring: PacketRing,
    fd: OwnedFd,
}

impl AfPacketSocket {
    pub(super) fn open(interface: &str, settings: RingSettings) -> Result<Self, AgentError> {
        // A zero socket protocol keeps capture disabled until bind(2) selects
        // the requested interface. Opening with ETH_P_ALL here would briefly
        // admit packets from every interface while the ring is configured.
        // sockaddr_ll.sll_protocol expects ETH_P_ALL in network byte order.
        let proto_be: u16 = 0x0003u16.to_be();
        // SAFETY: plain socket(2) call; the fd is checked and immediately
        // wrapped in OwnedFd so every later error path closes it.
        let raw_fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        if raw_fd < 0 {
            let err = io::Error::last_os_error();
            return Err(AgentError::Source(format!(
                "cannot open AF_PACKET socket (need CAP_NET_RAW / root): {err}"
            )));
        }
        // SAFETY: raw_fd was returned uniquely by socket(2) and is nonnegative.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let version: libc::c_int = TPACKET_V3 as libc::c_int;
        set_option(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_VERSION,
            &version,
        )
        .map_err(|e| AgentError::Source(format!("cannot enable TPACKET_V3: {e}")))?;

        // PACKET_RX_RING requires each block to be aligned to the host page
        // size. Config validation handles the supported range; this runtime
        // check gives a useful error on kernels with an unusual page size.
        // SAFETY: sysconf has no pointer arguments or memory side effects.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 || settings.block_size_bytes as u64 % page_size as u64 != 0 {
            return Err(AgentError::Source(format!(
                "AF_PACKET ring block size {} is not a multiple of host page size {}",
                settings.block_size_bytes, page_size
            )));
        }

        let ring_bytes = u64::from(settings.block_size_bytes)
            .checked_mul(u64::from(settings.block_count))
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| AgentError::Source("AF_PACKET ring size overflows usize".into()))?;
        let frame_count = ring_bytes
            .checked_div(FRAME_SIZE_BYTES as usize)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| AgentError::Source("AF_PACKET frame count overflows u32".into()))?;
        let request = libc::tpacket_req3 {
            tp_block_size: settings.block_size_bytes,
            tp_block_nr: settings.block_count,
            tp_frame_size: FRAME_SIZE_BYTES,
            tp_frame_nr: frame_count,
            tp_retire_blk_tov: settings.retire_timeout_ms,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        set_option(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_RX_RING,
            &request,
        )
        .map_err(|e| {
            AgentError::Source(format!(
                "cannot allocate {}-byte TPACKET_V3 receive ring: {e}",
                ring_bytes
            ))
        })?;

        // SAFETY: PACKET_RX_RING configured a mapping of exactly ring_bytes
        // for this fd. MAP_SHARED is required for kernel/userspace ownership
        // handoff; no executable mapping is requested.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(AgentError::Source(format!(
                "cannot mmap TPACKET_V3 receive ring: {}",
                io::Error::last_os_error()
            )));
        }
        let Some(base) = NonNull::new(mapping.cast::<u8>()) else {
            // A mapping at address zero is technically valid but cannot be
            // represented by NonNull. Release it and fail without panicking.
            // SAFETY: mapping and ring_bytes came directly from mmap above.
            let _ = unsafe { libc::munmap(mapping, ring_bytes) };
            return Err(AgentError::Source(
                "cannot represent a TPACKET_V3 ring mapped at address zero".into(),
            ));
        };
        let ring = PacketRing {
            base,
            len: ring_bytes,
            block_size: settings.block_size_bytes as usize,
            block_count: settings.block_count as usize,
            current_block: 0,
        };
        let socket = AfPacketSocket { ring, fd };
        socket.bind(interface, proto_be)?;
        Ok(socket)
    }

    fn bind(&self, interface: &str, proto_be: u16) -> Result<(), AgentError> {
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
                self.fd.as_raw_fd(),
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(AgentError::Source(format!(
                "cannot bind to {interface}: {}",
                io::Error::last_os_error()
            )))
        }
    }

    pub(super) fn ring_bytes(&self) -> usize {
        self.ring.len
    }

    pub(super) fn ring_blocks(&self) -> usize {
        self.ring.block_count
    }

    pub(super) fn block_size_bytes(&self) -> usize {
        self.ring.block_size
    }

    /// Wait for and drain one kernel-owned block. `None` is an idle poll
    /// timeout; `Some(false)` means the visitor requested shutdown.
    pub(super) fn poll_block(
        &mut self,
        mut visit: impl FnMut(&[u8], u64) -> bool,
    ) -> io::Result<Option<bool>> {
        let block = self.ring.current_block_ptr();
        // SAFETY: block points into self.ring's live mmap and the returned
        // reference cannot outlive this mutable borrow of the socket.
        let status = unsafe { block_status(block) };
        if status.load(Ordering::Acquire) & libc::TP_STATUS_USER == 0 {
            let mut pollfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd points to one initialized descriptor for the
            // duration of poll(2).
            let rc = unsafe { libc::poll(&mut pollfd, 1, POLL_TIMEOUT_MS) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            if rc == 0 {
                return Ok(None);
            }
            if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::other(format!(
                    "AF_PACKET poll returned revents=0x{:x}",
                    pollfd.revents
                )));
            }
            if status.load(Ordering::Acquire) & libc::TP_STATUS_USER == 0 {
                // Another block can make the descriptor readable just before
                // the current block is retired. Re-poll without touching
                // kernel-owned memory.
                return Ok(None);
            }
        }

        let _release = BlockRelease { status };
        // SAFETY: TP_STATUS_USER was observed with acquire ordering, so the
        // kernel will not mutate the block until BlockRelease returns it.
        let version = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*block).version)) };
        if version != TPACKET_V3 as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected packet-ring block version {version}"),
            ));
        }
        // SAFETY: TP_STATUS_USER was observed with acquire ordering. The
        // kernel owns the layout and does not mutate this block again until
        // userspace releases it below.
        let header = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*block).hdr.bh1)) };
        let block_len = header.blk_len as usize;
        let first_packet = header.offset_to_first_pkt as usize;
        if block_len < std::mem::size_of::<libc::tpacket_block_desc>()
            || block_len > self.ring.block_size
            || first_packet > block_len
            || header.num_pkts as usize
                > block_len / std::mem::size_of::<libc::tpacket3_hdr>().max(1)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TPACKET_V3 block bounds",
            ));
        }

        let block_base = block.cast::<u8>();
        let mut packet_offset = first_packet;
        let mut keep_running = true;
        for packet_index in 0..header.num_pkts as usize {
            let header_end = packet_offset
                .checked_add(std::mem::size_of::<libc::tpacket3_hdr>())
                .filter(|&end| end <= block_len)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated TPACKET_V3 header")
                })?;
            let packet_header = unsafe {
                std::ptr::read_unaligned(block_base.add(packet_offset).cast::<libc::tpacket3_hdr>())
            };
            if packet_header.tp_snaplen > packet_header.tp_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TPACKET_V3 snapshot length exceeds packet length",
                ));
            }
            let data_start = packet_offset
                .checked_add(packet_header.tp_mac as usize)
                .filter(|&start| start >= header_end && start <= block_len)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid TPACKET_V3 data offset")
                })?;
            let data_end = data_start
                .checked_add(packet_header.tp_snaplen as usize)
                .filter(|&end| end <= block_len)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated TPACKET_V3 packet")
                })?;
            if packet_header.tp_nsec >= 1_000_000_000 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid TPACKET_V3 nanosecond timestamp",
                ));
            }
            // SAFETY: the checked range lies wholly in the mmap block and is
            // immutable until BlockRelease returns ownership to the kernel.
            let bytes = unsafe {
                std::slice::from_raw_parts(block_base.add(data_start), data_end - data_start)
            };
            let timestamp_nanos = u64::from(packet_header.tp_sec)
                .saturating_mul(1_000_000_000)
                .saturating_add(u64::from(packet_header.tp_nsec));
            keep_running = visit(bytes, timestamp_nanos);
            if !keep_running {
                break;
            }

            if packet_index + 1 < header.num_pkts as usize {
                let next = packet_header.tp_next_offset as usize;
                if next < std::mem::size_of::<libc::tpacket3_hdr>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid TPACKET_V3 next-packet offset",
                    ));
                }
                packet_offset = packet_offset.checked_add(next).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "TPACKET_V3 offset overflow")
                })?;
            }
        }
        self.ring.current_block = (self.ring.current_block + 1) % self.ring.block_count;
        Ok(Some(keep_running))
    }

    /// Read and reset the kernel's per-socket TPACKET_V3 counters.
    pub(super) fn statistics(&self) -> io::Result<PacketStatistics> {
        let mut stats = libc::tpacket_stats_v3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };
        let mut len = std::mem::size_of::<libc::tpacket_stats_v3>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes to the correctly typed
        // stats buffer and updates the valid socklen_t pointer.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut stats as *mut libc::tpacket_stats_v3 as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else if len < std::mem::size_of::<libc::tpacket_stats_v3>() as libc::socklen_t {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short TPACKET_V3 PACKET_STATISTICS response",
            ))
        } else {
            Ok(PacketStatistics {
                packets: stats.tp_packets,
                drops: stats.tp_drops,
                queue_freezes: stats.tp_freeze_q_cnt,
            })
        }
    }
}

struct PacketRing {
    base: NonNull<u8>,
    len: usize,
    block_size: usize,
    block_count: usize,
    current_block: usize,
}

impl PacketRing {
    fn current_block_ptr(&self) -> *mut libc::tpacket_block_desc {
        // SAFETY: current_block is always reduced modulo block_count and the
        // mapping contains block_count blocks of exactly block_size bytes.
        unsafe {
            self.base
                .as_ptr()
                .add(self.current_block * self.block_size)
                .cast::<libc::tpacket_block_desc>()
        }
    }
}

impl Drop for PacketRing {
    fn drop(&mut self) {
        // SAFETY: base and len are the exact values returned to/from mmap.
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast::<libc::c_void>(), self.len) };
    }
}

struct BlockRelease<'a> {
    status: &'a AtomicU32,
}

impl Drop for BlockRelease<'_> {
    fn drop(&mut self) {
        self.status.store(libc::TP_STATUS_KERNEL, Ordering::Release);
    }
}

unsafe fn block_status<'a>(block: *mut libc::tpacket_block_desc) -> &'a AtomicU32 {
    // SAFETY: the caller guarantees that block belongs to a live mmap and
    // remains valid for 'a. Every ring block starts at page alignment, and
    // block_status is a naturally aligned u32 in the kernel UAPI header.
    unsafe { &*std::ptr::addr_of_mut!((*block).hdr.bh1.block_status).cast::<AtomicU32>() }
}

fn set_option<T>(
    fd: libc::c_int,
    level: libc::c_int,
    option: libc::c_int,
    value: &T,
) -> io::Result<()> {
    // SAFETY: setsockopt reads exactly size_of::<T>() initialized bytes from
    // value for the duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            value as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
