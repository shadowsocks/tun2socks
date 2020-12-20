#![cfg(any(target_os = "linux", target_os = "macos"))]

extern crate libc;
#[macro_use]
extern crate ioctl_sys;
extern crate mio;

mod sys;
pub use sys::*;
