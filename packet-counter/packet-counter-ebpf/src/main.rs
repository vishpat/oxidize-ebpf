#![no_std]
#![no_main]

use aya_bpf::{
    macros::socket_filter,
    programs::SkBuffContext,
};

use aya_log_ebpf::info;

#[socket_filter(name="packet_counter")]
pub fn packet_counter(_ctx: SkBuffContext) -> i64 {
    info!(&_ctx, "packet received");
    return 0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
