use std::{mem, io, fs};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use std::collections::HashSet;
use std::sync::RwLock;

extern crate libc;
use libc::{dlsym, getpid, pthread_self};

#[macro_use]
extern crate lazy_static;

// Waiting for next release of libc with libc::RTLD_NEXT
#[cfg(target_os = "freebsd")]
const RTLD_NEXT: *mut libc::c_void = -1isize as *mut libc::c_void;

#[cfg(not(target_os = "freebsd"))]
const RTLD_NEXT: *mut libc::c_void = libc::RTLD_NEXT;

macro_rules! wrap {
    {
        $(
            fn $($name:ident),+ : $args:tt -> $ret_n:ident : $ret_t:ty $code:block
        )*
    } => {
        $( $( wrap!(@expanded $name $args -> $ret_n : $ret_t $code); )+ )*
    };

    (@expanded $name:ident($( $arg_n:ident : $arg_t:ty ),*) -> $ret_n:ident : $ret_t:ty $code:block) => {
        #[no_mangle]
        pub extern "C" fn $name($( $arg_n: $arg_t ),*) -> $ret_t {
            unsafe {
                let name_cstr = CString::new(stringify!($name)).unwrap();
                let orig_fn: extern fn($( $arg_t ),*) -> $ret_t = mem::transmute(dlsym(RTLD_NEXT, name_cstr.as_ptr()));
                let $ret_n = orig_fn($( $arg_n ),*);
                $code;
                $ret_n
            }
        }
    };
}

thread_local! {
    static LOG_FILE: File = unsafe {
        if let Err(err) = fs::create_dir("/tmp/intercepts") {
            if err.kind() != io::ErrorKind::AlreadyExists {
                panic!("Failed to create /tmp/intercepts: {:?}", err);
            }
        }
        File::create(format!("/tmp/intercepts/{}.{}.log", getpid(), pthread_self())).unwrap()
    };

    static BEGUN_AT: Instant = Instant::now();
}

lazy_static! {
    static ref RELEVANT_FILE_DESCRIPTORS: RwLock<HashSet<c_int>> = RwLock::new(HashSet::new());
}

fn log(info: String) {
    let time = BEGUN_AT.with(|time| Instant::now().duration_since(*time));
    LOG_FILE.with(|mut log_file| {
        writeln!(log_file, "{:05}.{:08} {}", time.as_secs(), time.subsec_nanos(), info).unwrap();
    });
}

fn log_op(op: &str, path: &str, info: String) -> bool {
    if !path.starts_with("/tmp") || path[4..].starts_with("/intercepts") {
        return false;
    }
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    log(format!("{} {} {}, errno {}", op, path, info, errno));
    true
}

unsafe fn stat_info(buf: *mut libc::stat, ret: c_int) -> String {
    format!("-> mode {} uid {} gid {} size {} -> {}", (*buf).st_mode, (*buf).st_uid, (*buf).st_gid, (*buf).st_size, ret)
}

#[cfg(not(target_os = "freebsd"))]
unsafe fn stat64_info(buf: *mut libc::stat64, ret: c_int) -> String {
    format!("-> mode {} uid {} gid {} size {} -> {}", (*buf).st_mode, (*buf).st_uid, (*buf).st_gid, (*buf).st_size, ret)
}

unsafe fn c_str<'a>(ptr: *const c_char) -> &'a str {
    CStr::from_ptr(ptr).to_str().unwrap()
}

wrap! {
    fn open:(path: *const c_char, flags: c_int, mode: c_int) -> ret: c_int {
        if log_op("open", c_str(path), format!("(flags: {}, mode: {}) -> {}", flags, mode, ret)) && ret > 0 {
            RELEVANT_FILE_DESCRIPTORS.write().unwrap().insert(ret);
        }
    }

    fn close:(fd: c_int) -> ret: c_int {
        if ret == 0 {
            if RELEVANT_FILE_DESCRIPTORS.write().unwrap().remove(&ret) {
                log(format!("close {} -> 0", fd));
            }
        }
    }

    fn mkdir:(path: *const c_char, mode: c_int) -> ret: c_int {
        log_op("mkdir", c_str(path), format!("(mode: {}) -> {}", mode, ret));
    }

    fn symlink:(target: *const c_char, linkpath: *const c_char) -> ret: c_int {
        log_op("symlink", c_str(linkpath), format!("-> {} -> {}", c_str(target), ret));
    }

    fn __xstat:(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> ret: c_int {
        log_op("stat", c_str(path), stat_info(buf, ret));
    }

    fn stat:(path: *const c_char, buf: *mut libc::stat) -> ret: c_int {
        log_op("stat", c_str(path), stat_info(buf, ret));
    }

    fn __lxstat:(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> ret: c_int {
        log_op("lstat", c_str(path), stat_info(buf, ret));
    }

    fn lstat:(path: *const c_char, buf: *mut libc::stat) -> ret: c_int {
        log_op("lstat", c_str(path), stat_info(buf, ret));
    }

    fn __fxstat:(ver: c_int, fd: c_int, buf: *mut libc::stat) -> ret: c_int {
        if RELEVANT_FILE_DESCRIPTORS.read().unwrap().contains(&fd) {
            log(format!("fstat {} {}", fd, stat_info(buf, ret)));
        }
    }

    fn fstat:(fd: c_int, buf: *mut libc::stat) -> ret: c_int {
        if RELEVANT_FILE_DESCRIPTORS.read().unwrap().contains(&fd) {
            log(format!("fstat {} {}", fd, stat_info(buf, ret)));
        }
    }
}

#[cfg(target_pointer_width = "64")]
#[cfg(not(target_os = "freebsd"))]
wrap! {
    fn __xstat64:(ver: c_int, path: *const c_char, buf: *mut libc::stat64) -> ret: c_int {
        log_op("stat64", c_str(path), stat64_info(buf, ret));
    }

    fn stat64:(path: *const c_char, buf: *mut libc::stat64) -> ret: c_int {
        log_op("stat64", c_str(path), stat64_info(buf, ret));
    }

    fn __lxstat64:(ver: c_int, path: *const c_char, buf: *mut libc::stat64) -> ret: c_int {
        log_op("lstat64", c_str(path), stat64_info(buf, ret));
    }

    fn lstat64:(path: *const c_char, buf: *mut libc::stat64) -> ret: c_int {
        log_op("lstat64", c_str(path), stat64_info(buf, ret));
    }

    fn __fxstat64:(ver: c_int, fd: c_int, buf: *mut libc::stat64) -> ret: c_int {
        if RELEVANT_FILE_DESCRIPTORS.read().unwrap().contains(&fd) {
            log(format!("fstat {} {}", fd, stat64_info(buf, ret)));
        }
    }

    fn fstat64:(fd: c_int, buf: *mut libc::stat64) -> ret: c_int {
        if RELEVANT_FILE_DESCRIPTORS.read().unwrap().contains(&fd) {
            log(format!("fstat {} {}", fd, stat64_info(buf, ret)));
        }
    }
}
