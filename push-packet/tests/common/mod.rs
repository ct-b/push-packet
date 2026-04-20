use std::{process::Command, thread::JoinHandle};

use nix::sched::{CloneFlags, setns};

fn ip(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        return Err(format!(
            "ip {args:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(())
}

fn ip_ns(ns: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let mut full: Vec<&str> = vec!["netns", "exec", ns, "ip"];
    full.extend_from_slice(args);
    ip(&full)
}

fn cleanup(ns: &str, v2: &str) {
    let _ = Command::new("ip").args(["netns", "del", ns]).output();
    let _ = Command::new("ip").args(["link", "del", v2]).output();
}

pub struct VethHarness {
    ns: String,
    v1: String,
    v2: String,
}

impl VethHarness {
    const PREFIX: &str = "pp-test";
    const V1_IP: &str = "10.0.2.1";
    const V2_IP: &str = "10.0.2.2";
    const PREFIX_LEN: u8 = 24;

    pub fn namespace(&self) -> &str {
        &self.ns
    }
    pub fn veth_1(&self) -> &str {
        &self.v1
    }
    pub fn veth_2(&self) -> &str {
        &self.v2
    }
    pub fn veth_1_ip(&self) -> &str {
        Self::V1_IP
    }
    pub fn veth_2_ip(&self) -> &str {
        Self::V2_IP
    }

    /// Spawns a thread with the namespace set. The namespace is required for XDP to catch the
    /// packets
    pub fn spawn_in_namespapce<F, R>(&self, f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let ns = self.ns.clone();
        std::thread::spawn(move || {
            let ns_fd = std::fs::File::open(format!("/var/run/netns/{ns}")).unwrap();
            setns(&ns_fd, CloneFlags::CLONE_NEWNET).unwrap();
            f()
        })
    }

    /// Build a veth pair + netns, run `test`, tear down on drop.
    pub fn run<F>(test: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnOnce(&VethHarness) -> Result<(), Box<dyn std::error::Error>>,
    {
        let v = Self {
            ns: format!("{}-ns", Self::PREFIX),
            v1: format!("{}-v1", Self::PREFIX),
            v2: format!("{}-v2", Self::PREFIX),
        };
        let v1_cidr = format!("{}/{}", Self::V1_IP, Self::PREFIX_LEN);
        let v2_cidr = format!("{}/{}", Self::V2_IP, Self::PREFIX_LEN);

        cleanup(&v.ns, &v.v2);

        ip(&["netns", "add", &v.ns])?;
        ip(&["link", "add", &v.v1, "type", "veth", "peer", "name", &v.v2])?;
        ip(&["link", "set", &v.v1, "netns", &v.ns])?;
        ip_ns(&v.ns, &["link", "set", "lo", "up"])?;
        ip_ns(&v.ns, &["addr", "add", &v1_cidr, "dev", &v.v1])?;
        ip_ns(&v.ns, &["link", "set", &v.v1, "up"])?;
        ip(&["link", "set", &v.v2, "up"])?;
        ip(&["addr", "add", &v2_cidr, "dev", &v.v2])?;

        test(&v)
    }
}

impl Drop for VethHarness {
    fn drop(&mut self) {
        cleanup(&self.ns, &self.v2);
    }
}
