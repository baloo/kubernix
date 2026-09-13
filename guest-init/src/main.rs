//! The outer initramfs' entire `/init` — see `Cargo.toml`'s doc comment for
//! why this exists at all (giving the guest's eventual root a real parent
//! mount, which `pivot_root` requires and the kernel's own anonymous initial
//! root can never have).
//!
//! `/root.img` (an EROFS image, read-only) already ships every mountpoint
//! the real `/init` needs pre-created empty (`/dev`, `/proc`, `/sys`, ...) --
//! see `nix/guest-vm.nix`'s `rootImg` -- since nothing downstream of this
//! binary can `mkdir` a new one once it's chrooted into a read-only root.
//!
//! Every step here is a single syscall with no fallback path: this binary
//! has exactly one job, run exactly once, with nothing yet in place to
//! recover from a failure partway through — so `die` on the first error
//! rather than attempting anything cleverer.

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::process::exit;

/// Not (reliably) in every version of the `libc` crate — defined directly
/// from `<linux/loop.h>` so this doesn't depend on one that has them. Cast
/// with `as _` at each `ioctl` call site rather than typed here: musl's
/// `ioctl()` takes its request argument as `c_int`, glibc's as `c_ulong`,
/// and this binary is only ever actually built for musl (via `pkgsStatic`)
/// but should still `cargo build`/`clippy` cleanly on a plain glibc host.
const LOOP_CONFIGURE: i32 = 0x4C0A;
const LOOP_CTL_GET_FREE: i32 = 0x4C82;
const LO_FLAGS_READ_ONLY: u32 = 1;
const LO_NAME_SIZE: usize = 64;
const LO_KEY_SIZE: usize = 32;

/// Mirrors the kernel's `struct loop_info64`. Only `lo_flags` is ever set
/// below; the rest exists so this struct's layout — and therefore
/// `LoopConfig`'s — matches what `LOOP_CONFIGURE` actually reads. All-zero
/// is a valid value for every field here, which is what lets `main` below
/// build one with `mem::zeroed()` rather than a 64-element array literal
/// (arrays past 32 elements have no `#[derive(Default)]`).
#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; LO_NAME_SIZE],
    lo_crypt_name: [u8; LO_NAME_SIZE],
    lo_encrypt_key: [u8; LO_KEY_SIZE],
    lo_init: [u64; 2],
}

/// Mirrors the kernel's `struct loop_config`, the one-ioctl replacement for
/// the older `LOOP_SET_FD` + `LOOP_SET_STATUS64` pair.
#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}

fn die(what: &str) -> ! {
    let err = std::io::Error::last_os_error();
    eprintln!("guest-init: {what}: {err}");
    exit(1);
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no interior NUL")
}

/// The same packing `glibc`'s `makedev()` uses for major/minor values this
/// small (both well under 256) — the extended-range terms of the real
/// formula are all multiplied by zero here, so this is exactly equivalent
/// for the two device numbers this binary ever constructs.
fn makedev(major: u32, minor: u32) -> libc::dev_t {
    ((major as libc::dev_t) << 8) | (minor as libc::dev_t)
}

fn mkdir(path: &str) {
    if unsafe { libc::mkdir(cstr(path).as_ptr(), 0o755) } != 0 {
        let err = std::io::Error::last_os_error();
        // The kernel's own initial rootfs setup already creates `/dev`
        // itself (for the early console node), before `/init` ever runs --
        // nothing else this creates should legitimately already exist, but
        // tolerating it here rather than only for that one caller is the
        // same idempotent behavior for the same reason.
        if err.kind() != std::io::ErrorKind::AlreadyExists {
            die(&format!("mkdir {path}"));
        }
    }
}

fn mknod(path: &str, mode: libc::mode_t, dev: libc::dev_t) {
    if unsafe { libc::mknod(cstr(path).as_ptr(), mode, dev) } != 0 {
        die(&format!("mknod {path}"));
    }
}

fn open(path: &str, flags: libc::c_int) -> libc::c_int {
    let fd = unsafe { libc::open(cstr(path).as_ptr(), flags) };
    if fd < 0 {
        die(&format!("open {path}"));
    }
    fd
}

fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: Option<&str>) {
    let data_c = data.map(cstr);
    let data_ptr = data_c
        .as_ref()
        .map_or(std::ptr::null(), |d| d.as_ptr() as *const c_void);
    if unsafe {
        libc::mount(
            cstr(source).as_ptr(),
            cstr(target).as_ptr(),
            cstr(fstype).as_ptr(),
            flags,
            data_ptr,
        )
    } != 0
    {
        die(&format!("mount {fstype} on {target}"));
    }
}

fn main() {
    // `/dev` does not exist yet — nothing has mounted `devtmpfs` (that is
    // the real `/init`'s job, once we exec into it) — so the two device
    // nodes the loop setup below needs are created here by hand, using
    // their well-known fixed numbers rather than discovering them through
    // `sysfs`, which would itself need mounting first for no real benefit.
    mkdir("/dev");
    // Misc major (10), minor 237: stable in practice across kernel versions,
    // and what every other early-boot tool (dracut, busybox, systemd)
    // hardcodes for exactly this reason rather than looking it up.
    mknod("/dev/loop-control", libc::S_IFCHR | 0o600, makedev(10, 237));

    let ctl_fd = open("/dev/loop-control", libc::O_RDWR);
    let loop_num = unsafe { libc::ioctl(ctl_fd, LOOP_CTL_GET_FREE as _) };
    if loop_num < 0 {
        die("LOOP_CTL_GET_FREE");
    }
    unsafe { libc::close(ctl_fd) };

    let loop_path = format!("/dev/loop{loop_num}");
    mknod(
        &loop_path,
        libc::S_IFBLK | 0o600,
        makedev(7, loop_num as u32),
    );

    let backing_fd = open("/root.img", libc::O_RDONLY);
    let loop_fd = open(&loop_path, libc::O_RDONLY);

    // SAFETY: every field of `LoopConfig`/`LoopInfo64` is a plain integer or
    // byte array — all-zero is a valid value for all of them.
    let mut config: LoopConfig = unsafe { std::mem::zeroed() };
    config.fd = backing_fd as u32;
    config.info.lo_flags = LO_FLAGS_READ_ONLY;
    if unsafe {
        libc::ioctl(
            loop_fd,
            LOOP_CONFIGURE as _,
            &mut config as *mut _ as *mut c_void,
        )
    } != 0
    {
        die("LOOP_CONFIGURE");
    }
    unsafe { libc::close(backing_fd) };

    mkdir("/target");
    mount(&loop_path, "/target", "erofs", libc::MS_RDONLY, None);
    unsafe { libc::close(loop_fd) };

    if unsafe { libc::chroot(cstr("/target").as_ptr()) } != 0 {
        die("chroot /target");
    }
    if unsafe { libc::chdir(cstr("/").as_ptr()) } != 0 {
        die("chdir /");
    }

    // Whatever argv the kernel handed *this* process as PID 1 is exactly
    // what the real init should see too; `execv` keeps the current
    // environment as-is, so there is nothing to reconstruct for either.
    let argv: Vec<CString> = std::env::args().map(|a| cstr(&a)).collect();
    let mut argv_ptrs: Vec<*const c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    unsafe { libc::execv(cstr("/init").as_ptr(), argv_ptrs.as_ptr()) };
    die("execv /init");
}
