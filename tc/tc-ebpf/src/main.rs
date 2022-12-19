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

const HTTP_PORT: u16 = 8080;
const HTTP_NAT_PORT: u16 = 8081;

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_PROTOCOL: u8 = 0x06;
const TCP_SRC_PORT_OFFSET: usize = ETH_HDR_LEN + IP_HDR_LEN;
const TCP_DST_PORT_OFFSET: usize = ETH_HDR_LEN + IP_HDR_LEN + 2;
const TCP_CHECKSUM_OFFSET: usize = ETH_HDR_LEN + IP_HDR_LEN + 16;

#[classifier(name="tc_ingress")]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_ingress(mut ctx: TcContext) -> Result<i32, i32> {

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

    if dst_port != HTTP_PORT {
        return Ok(TC_ACT_PIPE);
    }

    info!(&ctx, "ingress TCP packet with dst port {}", dst_port);

    ctx.l4_csum_replace(TCP_CHECKSUM_OFFSET, 
        HTTP_PORT.to_be() as u64, 
        HTTP_NAT_PORT.to_be() as u64, 2)
        .map_err(|_| TC_ACT_PIPE)?;

    ctx.store(TCP_DST_PORT_OFFSET, &HTTP_NAT_PORT.to_be(), 0)
        .map_err(|_| TC_ACT_PIPE)?;
  
    info!(&ctx, "Updated dst port to {}", HTTP_NAT_PORT);
    Ok(0)
}

#[classifier(name="tc_egress")]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_egress(mut ctx: TcContext) -> Result<i32, i32> {

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

    let src_port = u16::from_be(
        ctx.load(TCP_SRC_PORT_OFFSET)
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if src_port != HTTP_NAT_PORT {
        return Ok(TC_ACT_PIPE);
    }

    info!(&ctx, "egress TCP packet with src port {}", src_port);

    ctx.l4_csum_replace(TCP_CHECKSUM_OFFSET, 
        HTTP_NAT_PORT.to_be() as u64, 
        HTTP_PORT.to_be() as u64, 2)
        .map_err(|_| TC_ACT_PIPE)?;


    ctx.store(TCP_SRC_PORT_OFFSET, &HTTP_PORT.to_be(), 0)
        .map_err(|_| TC_ACT_PIPE)?;
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
