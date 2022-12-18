use aya::programs::{
    tc, SchedClassifier, TcAttachType,
};
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
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tc"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tc"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!(
            "failed to initialize eBPF logger: {}",
            e
        );
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let mut program: &mut SchedClassifier =
        bpf.program_mut("tc_ingress").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, TcAttachType::Ingress)?;

    program = bpf.program_mut("tc_egress").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, TcAttachType::Egress)?;



    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
