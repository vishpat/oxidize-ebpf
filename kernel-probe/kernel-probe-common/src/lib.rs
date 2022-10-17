#![no_std]

use aya_bpf::cty::{c_uchar, c_uint};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileData {
    pub pid: c_uint,
    pub pgid: c_uint,
    pub uid: c_uint,
    pub d_parent: [c_uchar; 32usize],
    pub name: [c_uchar; 32usize],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileData {}
