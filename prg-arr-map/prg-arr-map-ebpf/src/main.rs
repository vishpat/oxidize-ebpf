#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]


mod vmlinux;
use vmlinux::{ethhdr, iphdr};
use aya_bpf::{macros::map};
use aya_bpf::{maps::{HashMap, ProgramArray}};
use aya_bpf::{
    macros::socket_filter,
    programs::SkBuffContext,
};

#[map(name = "COUNTERS")]  
static mut COUNTERS: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(3, 0);


#[map(name = "JUMP_TABLE")]
static mut JUMP_TABLE: ProgramArray = 
    ProgramArray::with_max_entries(10, 0);

#[socket_filter(name="process_icmp")]
pub fn process_icmp(_ctx: SkBuffContext) -> i64 {
    return 0
}

#[socket_filter(name="process_tcp")]
pub fn process_tcp(_ctx: SkBuffContext) -> i64 {
    return 0
}

#[socket_filter(name="process_udp")]
pub fn process_udp(_ctx: SkBuffContext) -> i64 {
    return 0
}

#[socket_filter(name="prg_arr_map")]
pub fn prg_arr_map(_ctx: SkBuffContext) -> i64 {
    return 0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
