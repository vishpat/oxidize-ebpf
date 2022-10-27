#![no_std]
pub const IP_PROTO: u16 = 0x0800;
pub const TCP_PROTO: u8 = 0x6;
pub const ICMP_PROTO: u8 = 0x1;
pub const UDP_PROTO: u8 = 0x11;

pub const TCP_PROG_IDX: u32 = 0;
pub const UDP_PROG_IDX: u32 = 1;
pub const ICMP_PROG_IDX: u32 = 2;