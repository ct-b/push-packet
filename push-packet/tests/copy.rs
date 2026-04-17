use std::{net::UdpSocket, process::Command, time::Duration};

use nix::sched::{CloneFlags, setns};
use push_packet::{
    Tap,
    rules::{Action, Rule},
};

struct VethHarness {
    ns: &'static str,
    v1: &'static str,
    v2: &'static str,
    v1_addr: &'static str,
    v2_addr: &'static str,
}

impl VethHarness {
    fn run(
        &self,
        func: impl Fn(&VethHarness) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.teardown();
        let res = match self.setup() {
            Ok(_) => func(self),
            Err(err) => Err(err),
        };
        let _ = self.teardown();
        res
    }

    fn cmd(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let out = Command::new(args[0]).args(&args[1..]).output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("command {:?} failed: {}", args, stderr.trim()).into());
        }
        Ok(())
    }

    fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        Self::cmd(&["ip", "netns", "add", self.ns])?;
        Self::cmd(&[
            "ip", "link", "add", self.v1, "type", "veth", "peer", "name", self.v2,
        ])?;
        Self::cmd(&["ip", "link", "set", self.v1, "netns", self.ns])?;
        Self::cmd(&[
            "ip", "netns", "exec", self.ns, "ip", "link", "set", "lo", "up",
        ])?;
        Self::cmd(&[
            "ip",
            "netns",
            "exec",
            self.ns,
            "ip",
            "addr",
            "add",
            self.v1_addr,
            "dev",
            self.v1,
        ])?;
        Self::cmd(&[
            "ip", "netns", "exec", self.ns, "ip", "link", "set", self.v1, "up",
        ])?;
        Self::cmd(&["ip", "link", "set", self.v2, "up"])?;
        Self::cmd(&["ip", "addr", "add", self.v2_addr, "dev", self.v2])?;

        let _ = Command::new("iptables")
            .args(["-I", "INPUT", "-i", self.v2, "-j", "ACCEPT"])
            .output();
        Ok(())
    }

    fn teardown(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-i", self.v2, "-j", "ACCEPT"])
            .output();
        let _ = Command::new("ip").args(["netns", "del", self.ns]).output();
        let _ = Command::new("ip").args(["link", "del", self.v2]).output();
        Ok(())
    }
}

#[test]
fn copy_packets() -> Result<(), Box<dyn std::error::Error>> {
    let h = VethHarness {
        ns: "pp-copy-ns",
        v1: "pp-copy-v1",
        v2: "pp-copy-v2",
        v1_addr: "10.0.2.1/24",
        v2_addr: "10.0.2.2/24",
    };
    h.run(|h| {
        let mut tap = Tap::new(h.v2)?.with_rule(
            Rule::builder()
                .source_cidr(h.v1_addr)
                .action(Action::Copy { take: None }),
        )?;

        tap.start()?;

        let mut rx = tap.copy_rx()?;

        let ns = h.ns.to_string();
        let sender = std::thread::spawn(move || {
            let ns_fd = std::fs::File::open(format!("/var/run/netns/{ns}")).unwrap();
            setns(&ns_fd, CloneFlags::CLONE_NEWNET).unwrap();

            std::thread::sleep(Duration::from_millis(100));
            let sock = UdpSocket::bind("10.0.2.1:666").unwrap();
            for packet in ["test1", "test2"] {
                sock.send_to(packet.as_bytes(), "10.0.2.2:999").unwrap();
            }
        });

        let mut count = 0;
        while count < 2 {
            if let Some(packet) = rx.recv() {
                count += 1;
                println!("Received packet: {} bytes", packet.len());
            }
        }

        sender.join().expect("sender panicked");
        Ok(())
    })
}
