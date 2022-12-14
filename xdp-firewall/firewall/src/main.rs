use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use simplelog::{
    ColorChoice, ConfigBuilder, LevelFilter,
    TermLogger, TerminalMode,
};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s3")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/firewall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!(
            "failed to initialize eBPF logger: {}",
            e
        );
    }

    let mut blocked_ips: HashMap<_, u32, u8> =
        HashMap::try_from(
            bpf.map_mut("BLOCKED_IPS")?,
        )?;
    let mut blocked_ip = Ipv4Addr::new(192, 168, 0, 1);
    blocked_ips.insert(u32::from(blocked_ip), 1, 0)?;

    blocked_ip = Ipv4Addr::new(192, 168, 0, 2);
    blocked_ips.insert(u32::from(blocked_ip), 1, 0)?;

    let program: &mut Xdp = bpf
        .program_mut("firewall")
        .unwrap()
        .try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
