#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

mod vmlinux;
use vmlinux::{ethhdr, iphdr};
use core::mem;
use memoffset::offset_of;
use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_bpf::{macros::{map}, maps::HashMap};
use aya_log_ebpf::info;

pub const IP_PROTO: u16 = 0x0800;
pub const TCP_PROTO: u8 = 0x6;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[map(name = "BLOCKED_IPS")]  
static mut BLOCKED_IPS: HashMap<u32, u8> =
    HashMap::<u32, u8>::with_max_entries(1024, 0);

#[xdp(name="firewall")]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn try_firewall(ctx: XdpContext) -> Result<u32, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
   
    // Without the boundary check, the eBPF verification will fail
    if start + ETH_HDR_LEN > end {
        return Err(xdp_action::XDP_PASS);
    }

    let eth_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto)).unwrap() });
    if eth_proto != IP_PROTO {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Without the boundary check, the eBPF verification will fail
    if start + ETH_HDR_LEN + mem::size_of::<iphdr>() > end {
        return Err(xdp_action::XDP_PASS);
    }

    let src_addr = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr)).unwrap() });
    if unsafe {BLOCKED_IPS.get(&src_addr).is_some()} {
        return Ok(xdp_action::XDP_DROP);
    } 

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
