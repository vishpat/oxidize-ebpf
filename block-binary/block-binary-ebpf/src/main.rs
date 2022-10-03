#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;
use vmlinux::task_struct;

#[lsm(name = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32 {
    match try_task_alloc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_task_alloc(ctx: LsmContext) -> Result<i32, i32> {
    let task: *const task_struct = unsafe { ctx.arg::<*const task_struct>(0) as *const task_struct };
    let name = unsafe {&(*task).comm};
    const BUF_SIZE: usize = 16;
    let mut buffer: [u8; BUF_SIZE] = [0u8; BUF_SIZE];

    let mut i: usize = 0;
    for c in name.iter() {
        buffer[i] = *c as u8;
        i += 1;
    }

    info!(&ctx, "lsm hook task_alloc called {}", unsafe {
        core::str::from_utf8_unchecked(&buffer)
    });

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
