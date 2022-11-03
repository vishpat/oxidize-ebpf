use aya::maps::HashMap;
use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use simplelog::{
    ColorChoice, ConfigBuilder, LevelFilter,
    TermLogger, TerminalMode,
};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
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
        "../../target/bpfel-unknown-none/debug/binary-probe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/binary-probe"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!(
            "failed to initialize eBPF logger: {}",
            e
        );
    }
    let mut _counters: HashMap<_, u32, u64> =
        HashMap::try_from(bpf.map_mut("SENDFILE")?)?;

    let program: &mut UProbe = bpf
        .program_mut("binary_probe")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(
        Some("sendfile"),
        0,
        "libc",
        opt.pid.try_into()?,
    )?;

    let program: &mut UProbe = bpf
        .program_mut("binary_retprobe")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(
        Some("sendfile"),
        0,
        "libc",
        opt.pid.try_into()?,
    )?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
