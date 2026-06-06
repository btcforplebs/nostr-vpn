use std::{io, mem, thread};

use tokio::sync::mpsc;

pub(crate) fn spawn_linux_route_change_monitor() -> Option<mpsc::Receiver<()>> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        eprintln!(
            "daemon: failed to open Linux netlink route monitor socket: {}",
            io::Error::last_os_error()
        );
        return None;
    }

    let groups = (libc::RTMGRP_LINK
        | libc::RTMGRP_IPV4_IFADDR
        | libc::RTMGRP_IPV6_IFADDR
        | libc::RTMGRP_IPV4_ROUTE
        | libc::RTMGRP_IPV6_ROUTE) as u32;
    let mut addr = unsafe { mem::zeroed::<libc::sockaddr_nl>() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0;
    addr.nl_groups = groups;
    let bind_result = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bind_result < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        eprintln!("daemon: failed to bind Linux netlink route monitor: {error}");
        return None;
    }

    let (tx, rx) = mpsc::channel(1);
    let spawn_result = thread::Builder::new()
        .name("nvpn-linux-route-monitor".to_string())
        .spawn(move || {
            let _fd = LinuxRouteMonitorFd(fd);
            let mut buf = [0_u8; 8192];
            loop {
                let read = unsafe {
                    libc::recv(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0)
                };
                if read < 0 {
                    eprintln!(
                        "daemon: Linux netlink route monitor read failed: {}",
                        io::Error::last_os_error()
                    );
                    break;
                }
                if read == 0 {
                    continue;
                }
                match tx.try_send(()) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
                    Err(mpsc::error::TrySendError::Closed(())) => break,
                }
            }
        });

    match spawn_result {
        Ok(_) => Some(rx),
        Err(error) => {
            unsafe {
                libc::close(fd);
            }
            eprintln!("daemon: failed to spawn Linux netlink route monitor: {error}");
            None
        }
    }
}

struct LinuxRouteMonitorFd(libc::c_int);

impl Drop for LinuxRouteMonitorFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}
