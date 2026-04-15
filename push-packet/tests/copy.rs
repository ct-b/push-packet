use std::{net::UdpSocket, process::Command, time::Duration};

use push_packet::{
    Tap,
    rules::{Action, Rule},
};
const V1_NAME: &str = "pp-veth-1";
const V2_NAME: &str = "pp-veth-2";
const V1_ADDR: &str = "10.0.0.1/24";
const V2_ADDR: &str = "10.0.0.2/24";
fn setup_veth() -> Result<(), Box<dyn std::error::Error>> {
    Command::new("ip")
        .args([
            "link", "add", V1_NAME, "type", "veth", "peer", "name", V2_NAME,
        ])
        .status()?;
    Command::new("ip")
        .args(["link", "set", V1_NAME, "up"])
        .status()?;
    Command::new("ip")
        .args(["link", "set", V2_NAME, "up"])
        .status()?;
    Command::new("ip")
        .args(["addr", "add", V1_ADDR, "dev", V1_NAME])
        .status()?;
    Command::new("ip")
        .args(["addr", "add", V2_ADDR, "dev", V2_NAME])
        .status()?;
    Ok(())
}

fn teardown_veth() -> Result<(), Box<dyn std::error::Error>> {
    Command::new("ip").args(["link", "del", V1_NAME]).status()?;
    Ok(())
}

fn harness(
    func: impl Fn() -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let res = match setup_veth() {
        Ok(_) => func(),
        Err(err) => Err(err),
    };
    match teardown_veth() {
        Ok(_) => {}
        Err(_) => println!("Failed to tear down veth pair"),
    }
    res
}

#[test]
fn copy_packets() -> Result<(), Box<dyn std::error::Error>> {
    harness(|| {
        // Create a tap
        let mut tap = Tap::new(V2_NAME)?.with_rule(
            Rule::builder()
                .source_cidr(V1_ADDR)
                .action(Action::Copy { take: None }),
        )?;

        // Start the tap
        tap.start()?;

        let mut rx = tap.copy_rx()?;

        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let sock = UdpSocket::bind("10.0.0.1:666").unwrap();
            for packet in ["test1", "test2"] {
                sock.send_to(packet.as_bytes(), "10.0.0.2:999").unwrap();
            }
        });

        let mut count = 0;
        while count < 2 {
            if let Some(packet) = rx.recv() {
                count += 1;
                println!("Received packet: {} bytes", (*packet).len());
            }
        }

        Ok(())
    })
}
