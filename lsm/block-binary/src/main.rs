use aya::maps::HashMap;
use aya::{include_bytes_aligned, Bpf};
use aya::{programs::Lsm, Btf};
use aya_log::BpfLogger;
use block_binary_common::BinaryName;
use clap::Parser;
use log::{info, warn};
use simplelog::{ColorChoice, 
    ConfigBuilder, 
    LevelFilter, 
    TermLogger, 
    TerminalMode};
use tokio::signal;

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
        "../../target/bpfel-unknown-none/debug/block-binary"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/block-binary"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("task_alloc").unwrap().try_into()?;
    info!("Loading task_alloc program");
    program.load("task_alloc", &btf)?;
    program.attach()?;

    let mut blocklist: HashMap<_, BinaryName, u32> = 
        HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;

    let progs = vec!["node", "apt"];

    for prog in progs.iter() {
        let mut binary_name: BinaryName = 
            BinaryName { name: [0; 16] };
        binary_name.name[..prog.len()].copy_from_slice(&prog.as_bytes());
        blocklist.insert(binary_name, 1, 1)?;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
