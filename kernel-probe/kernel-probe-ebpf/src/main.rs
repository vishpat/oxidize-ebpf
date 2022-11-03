#![no_std]
#![no_main]

use aya_bpf::{
    cty::{c_uchar, c_uint},
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read,
    },
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use kernel_probe_common::FileData;
use vmlinux::{dentry, inode, kuid_t, path};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<FileData> =
    PerfEventArray::<FileData>::with_max_entries(
        1024, 0,
    );

#[kprobe(name = "kernel_probe")]
pub fn kernel_probe(ctx: ProbeContext) -> u32 {
    match unsafe { try_kernel_probe(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_kernel_probe(
    ctx: ProbeContext,
) -> Result<u32, u32> {
    let path: *const path = ctx.arg(0).ok_or(1u32)?;
    let dentry: *const dentry =
        bpf_probe_read(&(*path).dentry)
            .map_err(|_| 1u32)?;
    let inode: *const inode =
        bpf_probe_read(&(*dentry).d_inode)
            .map_err(|_| 1u32)?;
    let k_uid: kuid_t =
        bpf_probe_read(&(*inode).i_uid)
            .map_err(|_| 1u32)?;
    let i_uid: c_uint = bpf_probe_read(&k_uid.val)
        .map_err(|_| 1u32)?;
    let d_iname: [c_uchar; 32usize] =
        bpf_probe_read(&(*dentry).d_iname)
            .map_err(|_| 1u32)?;
    let d_parent: *const dentry =
        bpf_probe_read(&(*dentry).d_parent)
            .map_err(|_| 1u32)?;
    let d_parent_name: [c_uchar; 32usize] =
        bpf_probe_read(&(*d_parent).d_iname)
            .map_err(|_| 1u32)?;
    let pgid =
        (bpf_get_current_pid_tgid() >> 32) as u32;
    let pid = bpf_get_current_pid_tgid() as u32;

    if i_uid == 0 {
        return Ok(0);
    }

    let file_data = FileData {
        pid: pid,
        pgid: pgid,
        uid: i_uid,
        d_parent: d_parent_name,
        name: d_iname,
    };

    EVENTS.output(&ctx, &file_data, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
