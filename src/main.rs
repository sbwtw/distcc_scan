
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate minilzo;

use std::net::{TcpStream, Ipv4Addr, SocketAddrV4};
use std::io::{Write, Read};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver};
use std::thread;

use minilzo::compress;
use minilzo::decompress;

trait IncAddr {
    fn inc(&self, mask: u32) -> Option<Ipv4Addr>;
}

impl IncAddr for Ipv4Addr {
    fn inc(&self, mask: u32) -> Option<Ipv4Addr> {
        let bits = self.octets();
        let shift = 32 - mask;
        let mask = (0xffffffff >> shift) << shift;
        let num = (bits[0] as u32) << 24 |
                  (bits[1] as u32) << 16 |
                  (bits[2] as u32) << 8  |
                  (bits[3] as u32);

        let next = num + 1;
        if next & mask == num & mask {
            Some(next.into())
        } else {
            None
        }
    }
}

fn num_to_hex(num: u32) -> String {
    let mut r = String::with_capacity(8);
    let mut num = num;

    while num != 0 {
        let c = (num % 16) as u8;
        num /= 16;

        match c {
            c @ 0...9 => r.insert(0, ('0' as u8 + c) as char),
            c @ 10...15 => r.insert(0, ('a' as u8 + c - 10) as char),
            _ => unreachable!(),
        }
    }

    // fill to 8 character
    for _ in r.len()..8 {
        r.insert(0, '0');
    }

    r
}

fn generate_addr(base: Ipv4Addr, mask: u32) -> Receiver<Ipv4Addr> {
    let (tx, rx) = channel();

    thread::spawn(move || {
        let mut ip = base;
        loop {
            tx.send(ip).unwrap();

            if let Some(r) = ip.inc(mask) {
                ip = r;
            } else {
                break;
            }
        }
    });

    rx
}

fn scan(ip: Ipv4Addr, mask: u32) -> Receiver<Ipv4Addr> {

    let rx = Arc::new(Mutex::new(generate_addr(ip, mask)));
    let (dst_tx, dst_rx) = channel();

    for i in 0..3 {
        let rx = rx.clone();
        let tx = dst_tx.clone();
        thread::spawn(move || {

            loop {
                let ip = match rx.lock().unwrap().recv() {
                    Ok(ip) => ip,
                    _ => break,
                };

                info!("scan with thread {} for ip {:?}", i, ip);
                if test_live(ip) { tx.send(ip).unwrap(); }
            }
        });
    }

    dst_rx
}

fn test_live(ip: Ipv4Addr) -> bool {

    let data = "\n    int b(){   int a=0;    return a;} \n\n int c () { int aaa=0; return aaa;}       \
                /*  aaa aa aa aa */";
    let compressed = compress(data.as_bytes()).unwrap();

    // println!("{:?}", compressed);
    // println!("{:?}", String::from_utf8_lossy(&compressed).unwrap());

    // println!("Hello, world! -###{:?}###-", compressed);

    let test = "DIST00000002ARGC00000005ARGV00000003g++ARGV00000002-cARGV00000002-oARGV00000001aARGV000000051.\
                cppDOTI";
    let r = num_to_hex(compressed.len() as u32);
    let mut stream = match TcpStream::connect(SocketAddrV4::new(ip, 3632)) {
        Ok(s) => s,
        _ => return false,
    };

    stream.write(test.as_bytes());
    stream.write(r.as_bytes());
    stream.write(&compressed);

    let mut buf = [0; 1024];
    let r = stream.read(&mut buf);
    // println!("{:?}", r);
    // for i in buf.iter() {
        // print!("{}", *i as char);
    // }

    true
}

fn main() {

    env_logger::init().unwrap();

    let rx = scan(Ipv4Addr::new(127, 0, 0, 0), 30);
    while let Ok(r) = rx.recv() {
        println!("{:?}", r);
    }
}

#[test]
fn test_num_to_hex() {
    let r = num_to_hex(15);
    assert_eq!(r, "0000000f");

    let r = num_to_hex(0);
    assert_eq!(r, "00000000");

    let r = num_to_hex(123);
    assert_eq!(r, "0000007b");

    let r = num_to_hex(4294967295);
    assert_eq!(r, "ffffffff");
}

#[test]
fn test_ipaddr_inc() {
    let addr = "127.0.0.0".parse::<Ipv4Addr>().unwrap();
    assert_eq!(addr.inc(31), Some("127.0.0.1".parse().unwrap()));

    let addr = "127.0.0.255".parse::<Ipv4Addr>().unwrap();
    assert_eq!(addr.inc(24), None);

    let addr = "127.0.0.255".parse::<Ipv4Addr>().unwrap();
    assert_eq!(addr.inc(23), Some("127.0.1.0".parse().unwrap()));
}