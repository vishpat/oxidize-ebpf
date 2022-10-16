#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_ktime_get_ns,
    helpers::bpf_get_current_pid_tgid,
    macros::{uprobe, uretprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[map(name = "SENDFILE")]  
static mut SENDFILE: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(1024, 0);


#[uprobe(name="binary_probe")]
pub fn binary_probe(ctx: ProbeContext) -> u32 {
    match try_binary_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_binary_probe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "Sendfile function enter");
    let pid = bpf_get_current_pid_tgid() as u32;
    let current_time = unsafe { bpf_ktime_get_ns() };
    unsafe {SENDFILE.insert(&pid, &current_time, 0).unwrap() };
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
    info!(&ctx, "Sendfile function return");
    let pid = bpf_get_current_pid_tgid() as u32;
    let start_time = unsafe {SENDFILE.get(&pid).unwrap_or(&0) };
    let end_time = unsafe {bpf_ktime_get_ns()};
    let duration = end_time - start_time;
    info!(&ctx, "Sendfile duration: for pid {} : {} nsecs", pid, duration);
    unsafe {SENDFILE.remove(&pid).unwrap()}; 
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
