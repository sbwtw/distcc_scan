
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate minilzo;
extern crate clap;
#[macro_use]
extern crate lazy_static;

use std::net::{TcpStream, Ipv4Addr, SocketAddrV4};
use std::io::{Write, Read};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::process::{Command, Stdio};
use minilzo::compress;
use clap::{App, Arg};

lazy_static!{
    static ref TEST_PACKAGE: Vec<u8> = {
        let head = b"DIST00000002ARGC00000005ARGV00000003g++ARGV00000002-cARGV00000002-oARGV00000001aARGV000000051.cppDOTI";
        let data = b"\n    int b(){   int a=0;    return a;} \n\n int c () { int aaa=0; return aaa;}       /*  aaa aa aa aa */";
        let mut compressed = compress(data).unwrap();
        let len_hex = num_to_hex(compressed.len() as u32);

        let mut package: Vec<u8> = vec![];
        package.append(&mut head.to_vec());
        package.append(&mut len_hex.as_bytes().to_vec());
        package.append(&mut compressed);

        package
    };
}

trait IncAddr {
    fn inc(&self, mask: u32) -> Option<Ipv4Addr>;
}

impl IncAddr for Ipv4Addr {
    fn inc(&self, mask_bits: u32) -> Option<Ipv4Addr> {
        let bits = self.octets();
        let num = (bits[0] as u32) << 24 | (bits[1] as u32) << 16 | (bits[2] as u32) << 8 |
                  (bits[3] as u32);

        let next = num + 1;
        if next & mask_bits == num & mask_bits {
            Some(next.into())
        } else {
            None
        }
    }
}

struct Distcc<R> {
    rdr: R,
    version: usize,
}

enum SectionContent {
    Length(usize),
    Content(Vec<u8>),
}

enum SectionType {
    Length,
    Content,
}

impl<R: Read> Distcc<R> {
    fn new(rdr: R) -> Distcc<R> {
        Distcc {
            rdr: rdr,
            version: 0,
        }
    }

    fn verify_package(&mut self) -> bool {

        // let mut buf = [0; 1024];
        // self.rdr.read(&mut buf);

        // for c in buf.iter() {
        //     print!("{}", *c as char);
        // }

        if let Some(SectionContent::Length(len)) = self.match_section("DONE", SectionType::Length) {
            info!("got done section, version is {}", len);
        } else {
            return false;
        }

        if let Some(SectionContent::Length(stat)) =
            self.match_section("STAT", SectionType::Length) {
            info!("got stat section, status is {}", stat);
        } else {
            return false;
        }

        true
    }

    fn match_section<T: AsRef<str>>(&mut self,
                                    section: T,
                                    sec_type: SectionType)
                                    -> Option<SectionContent> {

        let mut section_buf = [0; 4];
        let mut size = [0; 8];

        if let Ok(r) = self.rdr.read(&mut section_buf) {
            if r != 4 || &section_buf[..] != section.as_ref().as_bytes() {
                return None;
            }
        } else {
            return None;
        }

        if let Ok(r) = self.rdr.read(&mut size) {
            if r != 8 {
                return None;
            }
        } else {
            return None;
        }

        let len = match hex_to_num(&size) {
            Ok(num) => num,
            _ => return None,
        };

        match sec_type {
            SectionType::Length => Some(SectionContent::Length(len)),
            SectionType::Content => {
                let mut buf = Vec::<u8>::with_capacity(len);
                if self.rdr.read_exact(&mut buf).is_ok() {
                    Some(SectionContent::Content(buf))
                } else {
                    None
                }
            }
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
            c @ 0...9 => r.insert(0, (b'0' + c) as char),
            c @ 10...15 => r.insert(0, (b'a' + c - 10) as char),
            _ => unreachable!(),
        }
    }

    // fill to 8 character
    for _ in r.len()..8 {
        r.insert(0, '0');
    }

    r
}

fn hex_to_num(array: &[u8]) -> Result<usize, ()> {
    if array.len() != 8 {
        return Err(());
    }

    let mut num = 0;
    let mut pow = 1;
    for i in array.iter().rev() {

        let n = match i {
            n @ &b'0'...b'9' => (n - b'0') as usize,
            n @ &b'a'...b'f' => (n - b'a') as usize + 10,
            _ => return Err(()),
        };

        num += pow * n;
        pow *= 16;
    }

    Ok(num)
}

fn generate_addr(base: Ipv4Addr, mask: u32) -> Receiver<Ipv4Addr> {
    let (tx, rx) = channel();
    let shift = 32 - mask;
    let mask = (0xffffffff >> shift) << shift;

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

    for i in 0..10 {
        let rx = rx.clone();
        let tx = dst_tx.clone();
        thread::spawn(move || loop {
            let ip = match rx.lock().unwrap().recv() {
                Ok(ip) => ip,
                _ => break,
            };

            info!("scan with thread {} for ip {:?}", i, ip);
            if test_live(ip) {
                tx.send(ip).unwrap();
            }
        });
    }

    dst_rx
}

fn test_live(ip: Ipv4Addr) -> bool {

    let ips = ip.octets();
    let ip_str = format!("{}.{}.{}.{}", ips[0], ips[1], ips[2], ips[3]);
    // ping test
    let status = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("1")
        .arg(ip_str)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if !status.success() {
        return false;
    }

    let mut stream = match TcpStream::connect(SocketAddrV4::new(ip, 3632)) {
        Ok(s) => s,
        _ => return false,
    };

    stream.set_nodelay(true).unwrap();
    stream.write(&*TEST_PACKAGE).unwrap();
    stream.flush().unwrap();

    let mut distcc = Distcc::new(&mut stream);
    distcc.verify_package()
}

fn main() {

    env_logger::init().unwrap();

    let matches = App::new("distcc_scan")
        .author("sbw <sbw@sbw.so>")
        .version("0.0.0")
        .about("distcc service finder")
        .arg(Arg::with_name("ip").takes_value(true).required(true).help("specifiction ip range"))
        .get_matches();

    let ip_info: Vec<&str> = matches.value_of("ip").unwrap().split('/').collect();
    assert_eq!(ip_info.len(), 2, "ip range error.");
    let ip: Ipv4Addr = ip_info[0].parse().unwrap();
    let mask: u32 = ip_info[1].parse().unwrap();

    let rx = scan(ip, mask);
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
fn test_hex_to_num() {
    assert_eq!(hex_to_num("00000000".as_ref()), Ok(0));
    assert_eq!(hex_to_num("0000000f".as_ref()), Ok(15));
    assert_eq!(hex_to_num("0000007b".as_ref()), Ok(123));
    assert_eq!(hex_to_num("ffffffff".as_ref()), Ok(4294967295));

    assert_eq!(hex_to_num("0000000".as_ref()), Err(()));
    assert_eq!(hex_to_num("000000000".as_ref()), Err(()));
}

#[test]
fn test_ipaddr_inc() {
    let addr = "127.0.0.0".parse::<Ipv4Addr>().unwrap();
    assert_eq!(addr.inc(0xfffffffe), Some("127.0.0.1".parse().unwrap()));

    let addr = "127.0.0.255".parse::<Ipv4Addr>().unwrap();
    assert_eq!(addr.inc(0xffffff00), None);

    let addr = "127.0.0.255".parse::<Ipv4Addr>().unwrap();
    assert_eq!(addr.inc(0xfffffe00), Some("127.0.1.0".parse().unwrap()));
}

#[test]
fn test_generate_ip() {
    let rx = generate_addr(Ipv4Addr::new(127, 0, 0, 0), 31);
    assert_eq!(rx.recv().unwrap(), Ipv4Addr::new(127, 0, 0, 0));
    assert_eq!(rx.recv().unwrap(), Ipv4Addr::new(127, 0, 0, 1));
    assert!(rx.recv().is_err());
}
