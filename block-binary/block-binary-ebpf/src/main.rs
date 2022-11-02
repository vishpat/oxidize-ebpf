#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use block_binary_common::BinaryName;
use vmlinux::task_struct;

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<BinaryName, u32> =
    HashMap::<BinaryName, u32>::with_max_entries(
        16, 0,
    );

#[lsm(name = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32 {
    match try_task_alloc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn block_binary(binary_name: &BinaryName) -> bool {
    unsafe { BLOCKLIST.get(binary_name).is_some() }
}

fn try_task_alloc(
    ctx: LsmContext,
) -> Result<i32, i32> {
    let task: *const task_struct = unsafe {
        ctx.arg::<*const task_struct>(0)
            as *const task_struct
    };

    let name = unsafe { &(*task).comm };
    let mut binary_name: BinaryName =
        BinaryName { name: [0; 16] };

    let mut i: usize = 0;
    for c in name.iter() {
        binary_name.name[i] = *c as u8;
        i += 1;
    }
    let block = block_binary(&binary_name);
    if block {
        return Err(-1);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
