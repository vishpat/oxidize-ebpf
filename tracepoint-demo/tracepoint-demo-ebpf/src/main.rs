#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_long,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint(name = "tracepoint_demo")]
pub fn tracepoint_demo(ctx: TracePointContext) -> c_long {
    match try_tracepoint_demo(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint_demo(ctx: TracePointContext) -> Result<c_long, c_long> {
    const FILENAME_OFFSET: usize = 16;
    let filename_addr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET)? };
    let mut buf = [0u8; 128];

    // read the filename
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            filename_addr as *const u8,
            &mut buf,
        )?)
    };

    if filename.len() < 512 {
        // log the filename
        info!(&ctx, "{}", filename);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
