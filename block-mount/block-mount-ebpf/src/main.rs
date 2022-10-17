#![no_std]
#![no_main]

use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[kprobe(name="block_mount")]
pub fn block_mount(ctx: ProbeContext) -> u32 {
    match try_block_mount(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_mount(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function open_ctree called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
