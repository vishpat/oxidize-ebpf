use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use kernel_probe_common::FileData;
use log::{info, warn};
use simplelog::{
    ColorChoice, ConfigBuilder, LevelFilter,
    TermLogger, TerminalMode,
};
use std::str::from_utf8;
use tokio::{signal, task};

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
        "../../target/bpfel-unknown-none/debug/kernel-probe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/kernel-probe"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!(
            "failed to initialize eBPF logger: {}",
            e
        );
    }
    let program: &mut KProbe = bpf
        .program_mut("kernel_probe")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("vfs_open", 0)?;

    let mut perf_array =
        AsyncPerfEventArray::try_from(
            bpf.map_mut("EVENTS")?,
        )?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf
                    .read_events(&mut buffers)
                    .await
                    .unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr()
                        as *const FileData;
                    let data = unsafe {
                        ptr.read_unaligned()
                    };
                    println!(
                        "file_data: pid: {}, pgid: {}, uid: {}, path: {} ",
                        data.pid,
                        data.pgid,
                        data.uid,
                        format!(
                            "{}/{}",
                            from_utf8(&data.d_parent).unwrap(),
                            from_utf8(&data.name).unwrap()
                        )
                    );
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
