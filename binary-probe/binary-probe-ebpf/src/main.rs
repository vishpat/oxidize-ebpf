#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_get_current_comm,
    helpers::bpf_get_current_pid_tgid,
    macros::{uprobe, uretprobe},
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe(name="binary_probe")]
pub fn binary_probe(ctx: ProbeContext) -> u32 {
    match try_binary_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_binary_probe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "Rename function enter");
    Ok(0)
}

#[uretprobe(name="binary_retprobe")]
pub fn binary_retprobe(ctx: ProbeContext) -> u32 {
    match try_binary_retprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_binary_retprobe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "Rename function return");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
