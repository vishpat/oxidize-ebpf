extern crate libc;
use aya::maps::HashMap;
use aya::programs::SocketFilter;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use packet_counter_common::{
    ICMP_PROTO, TCP_PROTO, UDP_PROTO,
};
use simplelog::{
    ColorChoice, ConfigBuilder, LevelFilter,
    TermLogger, TerminalMode,
};
use std::net::TcpStream;
use tokio::signal;

const ETH_P_ALL: u16 = 0x0003;

#[derive(Debug, Parser)]
struct Opt {}

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/packet-counter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/packet-counter"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!(
            "failed to initialize eBPF logger: {}",
            e
        );
    }

    let mut counters: HashMap<_, u8, u32> =
        HashMap::try_from(bpf.map_mut("COUNTERS")?)?;

    let client = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            ETH_P_ALL.to_be() as i32,
        )
    };
    let prog: &mut SocketFilter = bpf
        .program_mut("packet_counter")
        .unwrap()
        .try_into()?;
    prog.load()?;
    prog.attach(client)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    println!(
        "TCP: {}",
        counters.get(&TCP_PROTO, 0).unwrap_or(0)
    );
    println!(
        "UDP: {}",
        counters.get(&UDP_PROTO, 0).unwrap_or(0)
    );
    println!(
        "ICMP: {}",
        counters.get(&ICMP_PROTO, 0).unwrap_or(0)
    );

    Ok(())
}
