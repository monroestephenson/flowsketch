//! Linux CPU-affinity helpers for the long-lived capture thread.

use std::io;

pub(crate) fn pin_current_thread(cpu: usize) -> io::Result<()> {
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "CPU {cpu} is outside Linux CPU_SETSIZE {}",
                libc::CPU_SETSIZE
            ),
        ));
    }

    // SAFETY: cpu_set_t is an integer bitset. CPU_ZERO/CPU_SET initialize and
    // update it within CPU_SETSIZE, checked above. sched_setaffinity reads the
    // fully initialized structure for the calling thread only (pid 0).
    let result = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cpu_outside_linux_set() {
        let error = pin_current_thread(libc::CPU_SETSIZE as usize).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
