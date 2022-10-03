#![no_std]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BinaryName {
    pub name: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BinaryName {}
