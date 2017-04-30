use std::{mem, io, fs};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

extern crate libc;
use libc::{dlsym, getpid, pthread_self};

macro_rules! wrap {
    {
        $(
            fn $name:ident($( $arg_n:ident : $arg_t:ty ),*) -> $ret_n:ident : $ret_t:ty $code:block
        )*
    } => {
        $(
            #[no_mangle]
            pub extern "C" fn $name($( $arg_n: $arg_t ),*) -> $ret_t {
                unsafe {
                    let name_cstr = CString::new(stringify!($name)).unwrap();
                    let orig_fn: extern fn($( $arg_t ),*) -> $ret_t = mem::transmute(dlsym(libc::RTLD_NEXT, name_cstr.as_ptr()));
                    let $ret_n = orig_fn($( $arg_n ),*);
                    $code;
                    $ret_n
                }
            }
        )*
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

fn log_op(op: &str, path: &str, info: String) {
    if !path.starts_with("/tmp") { return }
    if path[4..].starts_with("/intercepts") { return }
    LOG_FILE.with(|mut log_file| {
        let time = BEGUN_AT.with(|time| Instant::now().duration_since(*time));
        writeln!(log_file, "{:05}.{:08} {} {} {}", time.as_secs(), time.subsec_nanos(), op, path, info).unwrap();
    });
}

unsafe fn c_str<'a>(ptr: *const c_char) -> &'a str {
    CStr::from_ptr(ptr).to_str().unwrap()
}

wrap! {
    fn open(path: *const c_char, flags: i32, mode: i32) -> ret: i32 {
        log_op("open", c_str(path), format!("(flags: {}, mode: {}) -> {}", flags, mode, ret));
    }

    fn mkdir(path: *const c_char, mode: i32) -> ret: i32 {
        log_op("mkdir", c_str(path), format!("(mode: {}) -> {}", mode, ret));
    }

    fn symlink(target: *const c_char, linkpath: *const c_char) -> ret: i32 {
        log_op("symlink", c_str(linkpath), format!("-> {} -> {}", c_str(target), ret));
    }
}
