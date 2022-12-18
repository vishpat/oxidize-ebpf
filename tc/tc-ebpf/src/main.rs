#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

mod vmlinux;
use vmlinux::{ethhdr, iphdr};
use core::mem;
use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;
use memoffset::offset_of;

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_PROTOCOL: u8 = 0x06;
const TCP_DST_PORT_OFFSET: usize = ETH_HDR_LEN + IP_HDR_LEN + 2;

#[classifier(name="tc")]
pub fn tc(ctx: TcContext) -> i32 {
    match try_tc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc(mut ctx: TcContext) -> Result<i32, i32> {

    let eth_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    if eth_proto != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let protocol = u8::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(iphdr, protocol))
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if protocol != TCP_PROTOCOL {
        return Ok(TC_ACT_PIPE);
    }

    let dst_port = u16::from_be(
        ctx.load(TCP_DST_PORT_OFFSET)
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if dst_port != 8080 {
        return Ok(TC_ACT_PIPE);
    }

    info!(&ctx, "TCP packet to port 8080");

    ctx.store(TCP_DST_PORT_OFFSET, &8081u16.to_be(), 0)
        .map_err(|_| TC_ACT_PIPE)?;
    
    ctx.l4_csum_replace(TCP_DST_PORT_OFFSET, 
        8080u16.to_be() as u64, 
        8081u16.to_be() as u64, 2)
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
