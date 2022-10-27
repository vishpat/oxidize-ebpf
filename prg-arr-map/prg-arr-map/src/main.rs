use aya::{include_bytes_aligned, Bpf};
use aya::maps::HashMap;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use aya::programs::SocketFilter;
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use prg_arr_map_common::{ICMP_PROTO, TCP_PROTO, UDP_PROTO};

#[derive(Debug, Parser)]
struct Opt {
    
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
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/prg-arr-map"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/prg-arr-map"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let mut counters: HashMap<_, u8, u32> = HashMap::try_from(bpf.map_mut("COUNTERS")?)?;

    let client = TcpStream::connect("127.0.0.1:1234")?;
    let prog: &mut SocketFilter = bpf.program_mut("prg_arr_map").unwrap().try_into()?;
    prog.load()?;
    prog.attach(client.as_raw_fd())?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    println!("TCP: {}", counters.get(&TCP_PROTO, 0).unwrap_or(0));
    println!("UDP: {}", counters.get(&UDP_PROTO, 0).unwrap_or(0));
    println!("ICMP: {}", counters.get(&ICMP_PROTO, 0).unwrap_or(0));

    Ok(())
}
