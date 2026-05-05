mod common;
use std::{net::UdpSocket, time::Duration};

use push_packet::{
    Tap,
    rules::{Action, Rule},
};
use serial_test::serial;

use crate::common::VethHarness;

#[serial]
#[test]
#[ignore]
fn copy_packets() -> Result<(), Box<dyn std::error::Error>> {
    VethHarness::run(|harness| {
        let mut tap = Tap::builder(harness.veth_2())
            .rule(
                Rule::builder()
                    .source_cidr(harness.veth_1_ip())
                    .action(Action::Copy { take: None }),
            )
            .build()?;
        let mut rx = tap.copy_receiver()?;

        let src = format!("{}:3000", harness.veth_1_ip());
        let dst = format!("{}:3000", harness.veth_2_ip());
        let sender = harness.spawn_in_namespapce(move || {
            std::thread::sleep(Duration::from_millis(10));
            let sock = UdpSocket::bind(src).unwrap();
            for packet in ["test1", "test2"] {
                sock.send_to(packet.as_bytes(), &dst).unwrap();
            }
        });

        let mut count = 0;
        while count < 2 {
            if rx.recv().is_ok() {
                count += 1;
            }
        }
        sender.join().expect("sender panicked");
        Ok(())
    })
}
