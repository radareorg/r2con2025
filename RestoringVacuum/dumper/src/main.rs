use serialport::SerialPort;
use std::io::{self, Write};
use std::time::Duration;

fn wait_for_prompt(port: &mut dyn SerialPort, prompt: &[u8]) -> io::Result<()> {
    let mut buffer = [0u8; 1024];
    let mut received = Vec::new();

    loop {
        match port.read(&mut buffer) {
            Ok(n) => {
                received.extend_from_slice(&buffer[..n]);
                if received.ends_with(prompt) {
                    return Ok(());
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e),
        }
    }
}

fn main() {
    let port_name = "/dev/ttyUSB0"; // Change as needed
    let baud_rate = 115200;

    let mut port = serialport::new(port_name, baud_rate)
        .timeout(Duration::from_millis(1000))
        .open()
        .expect("Failed to open port");

    let chunk_size = 0x10000;
    let total_sectors = 0x72A000; // Approx 3.6 GiB
    let addr = 0x42000000;

    let mut sector = 0;
    let mut packet_count = 0;

    while sector < total_sectors {
        let read_cmd = format!(
            "mmc read 0x{:X} 0x{:X} 0x{:X}\r\n",
            addr, sector, chunk_size
        );
        let write_cmd = format!(
            "usb write 0x{:X} 0x{:X} 0x{:X}\r\n",
            addr, sector, chunk_size
        );

        println!("Sending: {}", read_cmd.trim());
        port.write_all(read_cmd.as_bytes()).expect("Write failed");
        wait_for_prompt(&mut *port, b"=> ").expect("Did not receive U-Boot prompt after read");

        std::thread::sleep(Duration::from_millis(50));

        println!("Sending: {}", write_cmd.trim());
        port.write_all(write_cmd.as_bytes()).expect("Write failed");
        wait_for_prompt(&mut *port, b"=> ").expect("Did not receive U-Boot prompt after write");

        std::thread::sleep(Duration::from_millis(50));

        sector += chunk_size;
        packet_count += 1;

        println!("R/W iteration count is: {}", packet_count);
        if packet_count % 200 == 0 {
            println!("Maximum R/W count reached, resetting USB peripheral...");
            let reset_cmd = "usb reset\r\n";
            println!("Sending: {}", reset_cmd.trim());
            port.write_all(reset_cmd.as_bytes()).expect("Write failed");
            wait_for_prompt(&mut *port, b"=> ")
                .expect("Did not receive U-Boot prompt after usb reset");
        }
    }

    println!("Done.");
}
