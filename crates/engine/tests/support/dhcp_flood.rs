//! A DHCP storm for the engine (tests and the `dhcp_round` bench): a HAL
//! whose DHCP server socket yields DISCOVERs from MACs never seen and
//! answers each OFFER with the REQUEST, and storages that count (or really
//! sync) what the server writes.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use corerouter_engine::{ConfigStorage, MemoryStorage, Slot, StorageError};
use corerouter_hal::dhcp_server::{DhcpServerPort, DhcpUplink, Heard, ReplyTo};
use corerouter_hal::{DynamicChange, Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::{Config, IfName};

/// A BOOTREQUEST of type `kind` from `mac` (RFC 2131 §2), with option 50
/// and 54 when given.
pub fn request(
    kind: u8,
    mac: [u8; 6],
    xid: u32,
    requested: Option<Ipv4Addr>,
    server: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut m = vec![0u8; 240];
    m[0] = 1;
    m[1] = 1;
    m[2] = 6;
    m[4..8].copy_from_slice(&xid.to_be_bytes());
    m[28..34].copy_from_slice(&mac);
    m[236..240].copy_from_slice(&[99, 130, 83, 99]);
    m.extend_from_slice(&[53, 1, kind]);
    if let Some(ip) = requested {
        m.push(50);
        m.push(4);
        m.extend_from_slice(&ip.octets());
    }
    if let Some(ip) = server {
        m.push(54);
        m.push(4);
        m.extend_from_slice(&ip.octets());
    }
    // Option 12: a name of its own (`h` + the MAC's last three bytes).
    let name = format!("h{:02x}{:02x}{:02x}", mac[3], mac[4], mac[5]);
    m.push(12);
    m.push(name.len() as u8);
    m.extend_from_slice(name.as_bytes());
    m.push(255);
    m
}

pub fn mac_of(n: u32) -> [u8; 6] {
    let [a, b, c, d] = n.to_be_bytes();
    [0x02, 0xf1, a, b, c, d]
}

#[derive(Default)]
pub struct Flood {
    /// Next new client.
    pub next: u32,
    /// New clients (DISCOVERs) per `tick`.
    pub per_tick: u32,
    /// Every `recv` returns a new client's DISCOVER (an endless storm).
    pub endless: bool,
    pub inbox: VecDeque<Heard>,
    pub recv_calls: u64,
    pub sent: u64,
    pub acks: u64,
    /// What the relay's uplink hears next (servers' replies).
    pub uplink: VecDeque<Heard>,
    /// Each ACK is answered by the same REQUEST again (clients renewing
    /// in a loop: journal lines without new records).
    pub echo_acks: bool,
}

impl Flood {
    fn discover(&mut self) -> Heard {
        let mac = mac_of(self.next);
        let h = Heard {
            payload: request(1, mac, self.next, None, None),
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::BROADCAST,
            src_mac: mac,
            to_server: true,
        };
        self.next = self.next.wrapping_add(1);
        h
    }
}

pub type Shared = Arc<Mutex<Flood>>;

struct FloodPort(Shared);

impl DhcpServerPort for FloodPort {
    fn mac(&self) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, 0xfe]
    }

    fn tick(&mut self, _now_unix: u64) {
        let mut f = self.0.lock().unwrap();
        for _ in 0..f.per_tick {
            let h = f.discover();
            f.inbox.push_back(h);
        }
    }

    fn recv(&mut self) -> Result<Option<Heard>, HalError> {
        let mut f = self.0.lock().unwrap();
        f.recv_calls += 1;
        if f.endless {
            return Ok(Some(f.discover()));
        }
        Ok(f.inbox.pop_front())
    }

    fn send(&mut self, payload: &[u8], _src: Ipv4Addr, _to: ReplyTo) -> Result<(), HalError> {
        let mut f = self.0.lock().unwrap();
        f.sent += 1;
        let Ok(m) = corerouter_proto_dhcp::v4::decode(payload) else {
            return Ok(());
        };
        let kind = u8::from(m.kind);
        if kind == 5 {
            f.acks += 1;
        }
        match kind {
            2 | 5 if kind == 2 || f.echo_acks => {
                // OFFER: the client takes it (SELECTING); an ACK echoed.
                let mac = m.chaddr;
                f.inbox.push_back(Heard {
                    payload: request(3, mac, m.xid, Some(m.yiaddr), m.server_id),
                    src: Ipv4Addr::UNSPECIFIED,
                    dst: Ipv4Addr::BROADCAST,
                    src_mac: mac,
                    to_server: true,
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn describe(&self) -> String {
        "flood".into()
    }
}

/// The virtual lab, with the flood as the DHCP server's socket.
pub struct FloodHal {
    pub inner: VirtualHal,
    pub flood: Shared,
}

impl FloodHal {
    pub fn new(flood: Shared) -> Self {
        Self {
            inner: VirtualHal::default(),
            flood,
        }
    }
}

impl Hal for FloodHal {
    fn describe(&self) -> String {
        "flood lab".into()
    }

    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }

    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.inner.apply(from, to)
    }

    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }

    fn now_unix(&self) -> Option<u64> {
        self.inner.now_unix()
    }

    fn address_list_dynamic(&mut self, change: DynamicChange<'_>) -> Result<(), HalError> {
        self.inner.address_list_dynamic(change)
    }

    fn dhcp_server_port(&mut self, _name: &IfName) -> Result<Box<dyn DhcpServerPort>, HalError> {
        Ok(Box::new(FloodPort(self.flood.clone())))
    }

    fn dhcp_relay_uplink(&mut self) -> Result<Box<dyn DhcpUplink>, HalError> {
        Ok(Box::new(FloodUplink(self.flood.clone())))
    }
}

struct FloodUplink(Shared);

impl DhcpUplink for FloodUplink {
    fn recv(&mut self) -> Result<Option<Heard>, HalError> {
        Ok(self.0.lock().unwrap().uplink.pop_front())
    }

    fn send(&mut self, _payload: &[u8], _server: Ipv4Addr) -> Result<(), HalError> {
        Ok(())
    }
}

/// What a storage was asked to write.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Writes {
    pub appends: u64,
    pub rewrites: u64,
    pub states: u64,
}

/// A storage that counts the writes; `fail_journal` makes every journal
/// write fail (a full disk).
#[derive(Clone, Default)]
pub struct Counting {
    pub inner: MemoryStorage,
    pub writes: Arc<Mutex<Writes>>,
    pub fail_journal: bool,
}

impl Counting {
    pub fn take(&self) -> Writes {
        std::mem::take(&mut *self.writes.lock().unwrap())
    }
}

impl ConfigStorage for Counting {
    fn describe(&self) -> String {
        "counting".into()
    }

    fn load(&mut self, slot: Slot) -> Result<Option<String>, StorageError> {
        self.inner.load(slot)
    }

    fn save(&mut self, data: &str) -> Result<(), StorageError> {
        self.inner.save(data)
    }

    fn quarantine(&mut self, slot: Slot) -> Result<(), StorageError> {
        self.inner.quarantine(slot)
    }

    fn load_state(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        self.inner.load_state(name)
    }

    fn save_state(&mut self, name: &str, data: &str) -> Result<(), StorageError> {
        self.writes.lock().unwrap().states += 1;
        self.inner.save_state(name, data)
    }

    fn load_journal(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        self.inner.load_journal(name)
    }

    fn append_journal(&mut self, name: &str, lines: &str) -> Result<(), StorageError> {
        self.writes.lock().unwrap().appends += 1;
        if self.fail_journal {
            return Err(StorageError("disk full".into()));
        }
        self.inner.append_journal(name, lines)
    }

    fn rewrite_journal(&mut self, name: &str, text: &str) -> Result<(), StorageError> {
        self.writes.lock().unwrap().rewrites += 1;
        if self.fail_journal {
            return Err(StorageError("disk full".into()));
        }
        self.inner.rewrite_journal(name, text)
    }
}

/// Files in a directory, synced as `storage-fs` does (fdatasync per
/// append; write, rename and directory sync per state): the real cost of
/// a write on this machine's disk.
pub struct Synced {
    pub dir: PathBuf,
    pub mem: MemoryStorage,
}

impl Synced {
    pub fn new(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            mem: MemoryStorage::default(),
        }
    }

    fn sync_dir(&self) {
        if let Ok(d) = std::fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
    }
}

impl ConfigStorage for Synced {
    fn describe(&self) -> String {
        format!("synced files in {}", self.dir.display())
    }

    fn load(&mut self, slot: Slot) -> Result<Option<String>, StorageError> {
        self.mem.load(slot)
    }

    fn save(&mut self, data: &str) -> Result<(), StorageError> {
        self.mem.save(data)
    }

    fn quarantine(&mut self, slot: Slot) -> Result<(), StorageError> {
        self.mem.quarantine(slot)
    }

    fn load_state(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        Ok(std::fs::read_to_string(self.dir.join(format!("state-{name}.json"))).ok())
    }

    fn save_state(&mut self, name: &str, data: &str) -> Result<(), StorageError> {
        use std::io::Write as _;
        let tmp = self.dir.join(format!("state-{name}.json.tmp"));
        let mut f = std::fs::File::create(&tmp).map_err(|e| StorageError(e.to_string()))?;
        f.write_all(data.as_bytes())
            .map_err(|e| StorageError(e.to_string()))?;
        f.sync_all().map_err(|e| StorageError(e.to_string()))?;
        std::fs::rename(&tmp, self.dir.join(format!("state-{name}.json")))
            .map_err(|e| StorageError(e.to_string()))?;
        self.sync_dir();
        Ok(())
    }

    fn load_journal(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        Ok(std::fs::read_to_string(self.dir.join(format!("journal-{name}.log"))).ok())
    }

    fn append_journal(&mut self, name: &str, lines: &str) -> Result<(), StorageError> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.dir.join(format!("journal-{name}.log")))
            .map_err(|e| StorageError(e.to_string()))?;
        f.write_all(lines.as_bytes())
            .map_err(|e| StorageError(e.to_string()))?;
        f.sync_data().map_err(|e| StorageError(e.to_string()))
    }

    fn rewrite_journal(&mut self, name: &str, text: &str) -> Result<(), StorageError> {
        let file = format!("journal-{name}.log");
        self.save_state(&file, text)?;
        std::fs::rename(
            self.dir.join(format!("state-{file}.json")),
            self.dir.join(file),
        )
        .map_err(|e| StorageError(e.to_string()))
    }
}
