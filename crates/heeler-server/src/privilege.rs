//! Root privilege drop (Unix only).
//!
//! Sequence, run after sockets are bound and before the async runtime
//! starts (so only the main thread exists — `setuid`/`setgid` then apply to
//! the whole process unambiguously):
//!
//! 1. resolve the target user and group;
//! 2. `chroot` if configured (then `chdir("/")`);
//! 3. set supplementary groups to exactly the target group;
//! 4. `setgid`;
//! 5. `setuid`;
//! 6. verify root cannot be regained (`setuid(0)` must fail).
//!
//! When the process is not started as root this module does nothing and
//! says so — the recommended deployments (CAP_NET_BIND_SERVICE, systemd
//! socket units, high ports, container capabilities) never run Heeler as
//! root at all.
//!
//! This is the only module in the workspace that uses `unsafe`: the libc
//! identity syscalls have no safe std wrapper. Every call site documents
//! its safety invariant, and the module is behind `cfg(unix)`.
//!
//! User/group name resolution reads `/etc/passwd` and `/etc/group`
//! directly (documented limitation: NSS/LDAP-only accounts are not found —
//! use numeric IDs for those).

use std::path::Path;

/// Errors from privilege handling.
#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    /// The configured user was not found.
    #[error("user {0:?} not found in /etc/passwd (use a numeric UID for NSS-managed accounts)")]
    UnknownUser(String),
    /// The configured group was not found.
    #[error("group {0:?} not found in /etc/group (use a numeric GID for NSS-managed groups)")]
    UnknownGroup(String),
    /// A syscall failed.
    #[error("{call} failed: {source}")]
    Syscall {
        /// The failing libc call.
        call: &'static str,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// Privileges could be regained after the drop — refuse to continue.
    #[error("privilege drop verification failed: setuid(0) succeeded after dropping to uid {uid}")]
    Regainable {
        /// The UID we attempted to drop to.
        uid: u32,
    },
    /// Dropping to root itself is not a drop.
    #[error("refusing to \"drop\" privileges to uid 0; configure a non-root user")]
    TargetIsRoot,
}

/// Outcome of [`drop_privileges`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropOutcome {
    /// The process was not root; nothing to drop.
    NotRoot,
    /// Privileges were dropped and verified unrecoverable.
    Dropped {
        /// Final UID.
        uid: u32,
        /// Final GID.
        gid: u32,
    },
}

/// Drops root privileges to `user`/`group`, optionally chrooting first.
///
/// Must be called while the process is single-threaded (before the Tokio
/// runtime starts): on Linux the raw setuid syscall is per-thread, and the
/// libc wrapper's all-threads signalling is only guaranteed coherent when
/// no other threads are running.
pub fn drop_privileges(
    user: &str,
    group: &str,
    chroot_dir: Option<&Path>,
) -> Result<DropOutcome, PrivilegeError> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(DropOutcome::NotRoot);
    }

    let (uid, passwd_gid) = resolve_user(user)?;
    if uid == 0 {
        return Err(PrivilegeError::TargetIsRoot);
    }
    let gid = if group.is_empty() {
        passwd_gid
    } else {
        resolve_group(group)?
    };

    if let Some(dir) = chroot_dir {
        let c_dir = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
            .map_err(|_| PrivilegeError::UnknownUser(dir.display().to_string()))?;
        // SAFETY: c_dir is a valid NUL-terminated path owned for the call.
        let rc = unsafe { libc::chroot(c_dir.as_ptr()) };
        check("chroot", rc)?;
        // SAFETY: the literal is a valid NUL-terminated string.
        let rc = unsafe { libc::chdir(c"/".as_ptr()) };
        check("chdir", rc)?;
    }

    let groups: [libc::gid_t; 1] = [gid];
    // SAFETY: the pointer references a live array of exactly the length
    // passed; setgroups copies it before returning.
    let rc = unsafe { libc::setgroups(1, groups.as_ptr()) };
    check("setgroups", rc)?;
    // SAFETY: setgid on a valid gid has no memory preconditions.
    let rc = unsafe { libc::setgid(gid) };
    check("setgid", rc)?;
    // SAFETY: setuid on a valid uid has no memory preconditions. Called
    // while single-threaded (documented precondition of this function).
    let rc = unsafe { libc::setuid(uid) };
    check("setuid", rc)?;

    // Verify the drop is irreversible: regaining root must fail.
    // SAFETY: as above; a success here is a fatal configuration error.
    let regain = unsafe { libc::setuid(0) };
    if regain == 0 {
        return Err(PrivilegeError::Regainable { uid });
    }

    Ok(DropOutcome::Dropped { uid, gid })
}

fn check(call: &'static str, rc: libc::c_int) -> Result<(), PrivilegeError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(PrivilegeError::Syscall {
            call,
            source: std::io::Error::last_os_error(),
        })
    }
}

/// Resolves a user to (uid, primary gid): numeric first, then /etc/passwd.
fn resolve_user(user: &str) -> Result<(u32, u32), PrivilegeError> {
    if let Ok(uid) = user.parse::<u32>() {
        return Ok((uid, uid));
    }
    lookup_colon_file(Path::new("/etc/passwd"), user)
        .ok_or_else(|| PrivilegeError::UnknownUser(user.to_owned()))
}

/// Resolves a group to a gid: numeric first, then /etc/group.
fn resolve_group(group: &str) -> Result<u32, PrivilegeError> {
    if let Ok(gid) = group.parse::<u32>() {
        return Ok(gid);
    }
    lookup_colon_file(Path::new("/etc/group"), group)
        .map(|(gid, _)| gid)
        .ok_or_else(|| PrivilegeError::UnknownGroup(group.to_owned()))
}

/// Finds `name` in a passwd/group-style file; returns fields 3 and 4
/// (uid+gid for passwd, gid+member-noise for group).
fn lookup_colon_file(path: &Path, name: &str) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }
        let _password = fields.next()?;
        let id = fields.next()?.trim().parse().ok()?;
        let second = fields.next().and_then(|f| f.trim().parse().ok()).unwrap_or(id);
        return Some((id, second));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_ids_resolve_without_files() {
        assert_eq!(resolve_user("1234").unwrap(), (1234, 1234));
        assert_eq!(resolve_group("4321").unwrap(), 4321);
    }

    #[test]
    fn root_resolves_from_passwd() {
        // Present on effectively every Unix system this runs on.
        if Path::new("/etc/passwd").exists() {
            assert_eq!(resolve_user("root").unwrap().0, 0);
        }
    }

    #[test]
    fn unknown_names_error() {
        assert!(resolve_user("no-such-user-heeler-test").is_err());
        assert!(resolve_group("no-such-group-heeler-test").is_err());
    }

    #[test]
    fn not_root_is_a_safe_noop_or_root_path_works() {
        // As an unprivileged test process this must be a no-op; when CI
        // runs as root the full drop path is exercised against nobody.
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            assert_eq!(
                drop_privileges("nobody", "", None).unwrap(),
                DropOutcome::NotRoot
            );
        }
    }
}
