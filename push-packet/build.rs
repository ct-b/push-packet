#[cfg(feature = "build-ebpf")]
fn build_packages() -> anyhow::Result<()> {
    use anyhow::{Context as _, anyhow};
    use aya_build::Toolchain;
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "push-packet-ebpf")
        .ok_or_else(|| anyhow!("push-packet-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "build-ebpf")]
    build_packages()?;
    Ok(())
}
