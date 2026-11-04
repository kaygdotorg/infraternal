//! Bridges an SSH command's exclusive stdin/stdout pipes without idle polling (D255).
//!
//! When infraternal runs as an SSH command, its stdin and stdout are the pipes
//! carrying the protocol. [`Stdio`] duplicates them, marks the copies
//! close-on-exec so no child process (manager, shim) inherits them, makes them
//! non-blocking and waits for readiness through the event loop, so no timer or
//! thread polls them.

use infraternal_shim::readiness::Registration;
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    unistd::{dup, read, write},
};
use std::{io, os::fd::OwnedFd};

/// Each direction has one owner; no shell or shim inherits these pipe copies.
pub struct Stdio {
    /// The command's standard input, watched for readability.
    input: Registration<OwnedFd>,
    /// The command's standard output, watched for writability.
    output: Registration<OwnedFd>,
}
impl Stdio {
    /// Duplicate only the SSH command's standard pipes and watch readiness.
    /// # Errors
    /// Refuses invalid descriptors or platforms whose pipes cannot be watched.
    pub fn inherited() -> io::Result<Self> {
        Ok(Self {
            input: watched(dup(io::stdin()).map_err(io::Error::from)?)?,
            output: watched(dup(io::stdout()).map_err(io::Error::from)?)?,
        })
    }
}
/// Make `fd` close-on-exec and non-blocking, then register it for readiness events.
fn watched(fd: OwnedFd) -> io::Result<Registration<OwnedFd>> {
    // dup does not preserve CLOEXEC. Subsequent manager/shim children must
    // never retain the bridge's trusted protocol descriptors.
    fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(io::Error::from)?;
    let flags = fcntl(&fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    // The SSH command exclusively owns the open pipe descriptions. Nonblocking
    // applies to all duplicates; no unrelated process uses these descriptions.
    fcntl(
        &fd,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(io::Error::from)?;
    Registration::new(fd)
}
/// Byte channel over the pipes. `read` returns 0 at end of input; `write` sends
/// the whole buffer or fails (a zero-length write is `WriteZero`).
impl infraternal_plugin_api::channel::Channel for Stdio {
    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.input.readable().await?;
            if let Ok(result) = ready.try_io(|fd| read(fd, bytes).map_err(io::Error::from)) {
                return result;
            }
        }
    }
    async fn write(&self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut ready = self.output.writable().await?;
            if let Ok(result) = ready.try_io(|fd| write(fd, bytes).map_err(io::Error::from)) {
                let count = result?;
                if count == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                bytes = &bytes[count..];
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Real pipe readiness and descriptor isolation preserve the trusted bridge boundary.
    use super::*;
    use infraternal_plugin_api::channel::Channel;

    #[tokio::test]
    async fn pipes_preserve_bytes_and_do_not_escape_into_child_exec() {
        let (input, sender) = nix::unistd::pipe().unwrap();
        let (receiver, output) = nix::unistd::pipe().unwrap();
        let channel = Stdio {
            input: watched(input).unwrap(),
            output: watched(output).unwrap(),
        };
        for fd in [channel.input.get_ref(), channel.output.get_ref()] {
            let flags = fcntl(fd, FcntlArg::F_GETFD).unwrap();
            assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
        }
        let payload = b"\0\xff\x1b[31m\r\n";
        write(&sender, payload).unwrap();
        let mut actual = [0; 10];
        let count = channel.read(&mut actual).await.unwrap();
        assert_eq!(&actual[..count], payload);
        channel.write(payload).await.unwrap();
        let count = read(&receiver, &mut actual).unwrap();
        assert_eq!(&actual[..count], payload);
    }
}
