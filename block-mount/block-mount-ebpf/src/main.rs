#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_override_return, macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

const ENOMEM: i32 = -12;
#[kprobe(name = "block_mount")]
pub fn block_mount(ctx: ProbeContext) -> u32 {
    match try_block_mount(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_mount(
    ctx: ProbeContext,
) -> Result<u32, u32> {
    info!(&ctx, "function open_ctree called");
    unsafe {
        bpf_override_return(ctx.regs, ENOMEM as u64)
    };
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
