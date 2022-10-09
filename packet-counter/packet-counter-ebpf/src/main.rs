#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

mod vmlinux;
use vmlinux::{ethhdr, iphdr};
use packet_counter_common::{IP_PROTO, TCP_PROTO, UDP_PROTO};
use aya_bpf::{
    macros::socket_filter,
    programs::SkBuffContext,
};
use aya_bpf::{macros::{map}, maps::HashMap};
use memoffset::offset_of;
use core::mem;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

#[map(name = "COUNTERS")]  
static mut COUNTERS: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(3, 0);


fn increment_counter(proto: u8) {
    let mut counter = unsafe { COUNTERS.get(&proto).unwrap_or(&0) };
    let new_count = *counter + 1;
    unsafe { COUNTERS.insert(&proto, &new_count, 0).unwrap() };
}

#[socket_filter(name="packet_counter")]
pub fn packet_counter(_ctx: SkBuffContext) -> i64 {
    let eth_proto = u16::from_be(_ctx.load(offset_of!(ethhdr, h_proto)).unwrap());
    let ip_proto = _ctx.load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol)).unwrap();

    if eth_proto != IP_PROTO {
        return 0;
    }

    match ip_proto {
        TCP_PROTO => increment_counter(TCP_PROTO),
        ICMP_PROTO => increment_counter(ICMP_PROTO),
        UDP_PROTO => increment_counter(UDP_PROTO),
        _ => {}
    } 
    
    return 0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
