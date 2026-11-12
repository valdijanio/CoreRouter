//! SNTP client (G4.6): asks the servers of `/system ntp client` for the
//! time and reports offset, delay and stratum to the session
//! (`system.ntp.client.get`).
//!
//! One thread, blocking sockets with a timeout, never holding the session
//! lock across the network. Every second it re-reads the running config; a
//! change restarts at `min_poll`. A round asks every server once and keeps
//! the answer with the smallest round trip (RFC 5905 §10 prefers it: the
//! offset error is at most half the delay). After a good round the poll
//! interval doubles up to `max_poll`; a bad round goes back to `min_poll`
//! (never below 64 s: RFC 4330 §5). Kiss-o'-Death (RFC 5905 §7.4): DENY and
//! RSTR drop that server until the config changes, RATE jumps to
//! `max_poll`.
//!
//! The system clock (G4.6b): [`ClockDriver`] carries out what
//! `corerouter_proto_ntp::discipline` decides, through the backend's
//! [`SystemClock`]. The virtual lab has none: it only measures. Without
//! `CAP_SYS_TIME` the client keeps measuring and says why.
//!
//! The first step of a boot (G4.6m): [`BootStep`] lets the discipline pass
//! PANICT (1000 s) once per boot (RFC 8633 §5.2, "at startup"): forward any
//! amount, backward a day at most. The mark is the kernel's `boot_id` in the
//! runtime directory (tmpfs on the image), so a daemon restarted in the same
//! boot asks again.
//!
//! Servers: the configured ones, then those of DHCP clients with
//! `use_peer_ntp` (G4.7a), at most [`MAX_SERVERS`] (a DHCP answer is hostile
//! input). Sockets: a new one per exchange, on a port the kernel picks
//! (RFC 9109 §4), bound to the client's VRF.
//!
//! First boot (G1.6zh): a router whose config was never saved starts with
//! the client on and no server configured ([`factory_default`]), so it asks
//! only what the network's DHCP server names (RFC 2132 §8.3, option 42) and
//! nobody else: no public pool is built in (RFC 8633 §6.2, RFC 4085). A
//! round with nobody to ask sends nothing and waits for nothing: the lease
//! that brings a server is asked at once.

use std::collections::BTreeSet;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
#[cfg(test)]
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};
use corerouter_hal::clock::{ClockError, HardwareClock, SystemClock};
use corerouter_model::ntp::{
    ClockState, MAIN_VRF, MAX_SERVERS, NO_SERVER, NtpClient, NtpState, NtpStatus, POLL_RANGE,
};
use corerouter_proto_ntp::discipline::{Action, Discipline, PANIC_NANOS};
use corerouter_proto_ntp::{Packet, ReplyError, Sample, Timestamp, check_reply, sample_of};

/// How long to wait for one server's answer.
const ANSWER_WAIT: Duration = Duration::from_secs(2);
/// How often the thread looks at the config.
const TICK: Duration = Duration::from_secs(1);
/// Warn when the clock is off by more than this and nobody corrects it.
const WARN_OFFSET_MS: f64 = 1000.0;
/// RFC 4330 §5: never ask more often than once a minute, even when a DHCP
/// renewal brings other servers.
const MIN_ROUND_GAP: Duration = Duration::from_secs(64);

/// The loop on a thread of its own, outside the supervisor (tests).
#[cfg(test)]
pub fn spawn(session: Shared, port: u16) -> std::io::Result<()> {
    let health = super::Health::new(corerouter_control::Shutdown::default());
    thread::Builder::new()
        .name("ntp-client".into())
        .spawn(move || run(&session, port, &health, None, &BootStep::system()))
        .map(|_| ())
}

fn unix_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0)
}

/// G4.6m: the mark of this boot's first clock step. The file holds the
/// kernel's `boot_id`: another boot (or no file) leaves the step open, the
/// same boot (a daemon restarted) has spent it. In the runtime directory,
/// tmpfs on the image; the `boot_id` keeps it right where it is not.
#[derive(Debug, Clone, Default)]
pub(crate) struct BootStep {
    marker: Option<PathBuf>,
    boot: Option<String>,
}

/// The mark's file name in the runtime directory.
const BOOT_STEP_FILE: &str = "ntp-boot-step";

impl BootStep {
    pub(crate) fn system() -> Self {
        Self::at(
            corerouter_control::local_token::runtime_dir().map(|d| d.join(BOOT_STEP_FILE)),
            read_small("/proc/sys/kernel/random/boot_id"),
        )
    }

    fn at(marker: Option<PathBuf>, boot: Option<String>) -> Self {
        Self { marker, boot }
    }

    /// The step of this boot is still unspent. Without a runtime directory
    /// or a `boot_id` it is open for this run of the daemon only.
    fn open(&self) -> bool {
        match (&self.marker, &self.boot) {
            (Some(m), Some(b)) => read_small(m).is_none_or(|t| t != *b),
            _ => true,
        }
    }

    fn spend(&self) {
        if let (Some(m), Some(b)) = (&self.marker, &self.boot)
            && let Err(e) = std::fs::write(m, b)
        {
            log::warn!("NTP: {}: {e} (the first-step mark of this boot)", m.display());
        }
    }
}

/// A small text file, trimmed (at most 128 bytes: hostile input).
fn read_small(path: impl AsRef<std::path::Path>) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(path).ok()?.take(128).read_to_string(&mut text).ok()?;
    Some(text.trim().to_owned()).filter(|t| !t.is_empty())
}

/// Carries out the discipline on the backend's clock.
struct ClockDriver {
    clock: Option<Box<dyn SystemClock>>,
    /// Why there is no clock (or the last failure), for the status.
    error: Option<String>,
    discipline: Discipline,
    /// The frequency last given to the kernel.
    frequency: Option<f64>,
    taken_over: bool,
    state: ClockState,
    last_adjustment_ms: Option<f64>,
    /// When this driver started: the steady time of the discipline.
    start: Instant,
    /// The refusal was already logged.
    complained: bool,
    /// The question to the operator was already logged, for this offset.
    asked: Option<i64>,
    /// G4.6m: where this boot's first step is marked (`None`: never open).
    boot: Option<BootStep>,
    /// G4.6o: whether the board's clock follows (`LeaveAlone` on the live
    /// image), and whether the log already said it is left alone.
    hardware: HardwareClock,
    told_hardware: bool,
}

impl ClockDriver {
    fn new(clock: Result<Box<dyn SystemClock>, String>) -> Self {
        let (clock, error) = match clock {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(e)),
        };
        Self {
            clock,
            error,
            discipline: Discipline::default(),
            frequency: None,
            taken_over: false,
            state: ClockState::NotSet,
            last_adjustment_ms: None,
            start: Instant::now(),
            complained: false,
            asked: None,
            boot: None,
            hardware: HardwareClock::Follow,
            told_hardware: false,
        }
    }

    /// G4.6o: the live image leaves the RTC alone.
    fn with_hardware_clock(mut self, hardware: HardwareClock) -> Self {
        self.hardware = hardware;
        self
    }

    /// G4.6m: with the boot's first step, when this boot has not spent it.
    fn with_boot_step(mut self, boot: &BootStep) -> Self {
        if boot.open() {
            self.discipline.allow_boot_step();
        }
        self.boot = Some(boot.clone());
        self
    }

    fn now(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Every loop: ends a slew on time. Between rounds the slew is the only
    /// thing that changes the frequency.
    fn tick(&mut self) -> Result<(), ClockError> {
        let now = self.now();
        self.discipline.tick(now);
        self.push_frequency()
    }

    /// Nothing is written before the first correction: a client that only
    /// asks (no answer yet, or a step waiting for the operator) leaves the
    /// clock as it found it.
    fn push_frequency(&mut self) -> Result<(), ClockError> {
        if !self.taken_over {
            return Ok(());
        }
        let want = self.discipline.frequency_ppm();
        if self.frequency != Some(want)
            && let Some(clock) = &mut self.clock
        {
            clock.set_frequency_ppm(want)?;
            self.frequency = Some(want);
        }
        Ok(())
    }

    /// How long the loop may sleep: until the slew ends, at most `TICK`.
    fn sleep(&self) -> Duration {
        self.discipline
            .slew_until()
            .map_or(TICK, |until| {
                Duration::from_secs_f64((until - self.now()).clamp(0.01, TICK.as_secs_f64()))
            })
    }

    /// Back to the drift alone: a slew never outlives the client.
    fn stand_down(&mut self) {
        let now = self.now();
        if self.discipline.slew_until().is_some() {
            self.discipline.tick(now + 1e9);
            if let Err(e) = self.push_frequency() {
                log::warn!("NTP: cannot end the slew: {e}");
            }
        }
        self.state = ClockState::NotSet;
    }

    /// One good measurement; returns what to tell the log.
    fn apply(
        &mut self,
        offset_nanos: i64,
        delay_nanos: i64,
        wall_unix: i64,
        confirmed: bool,
    ) -> Option<(&'static str, String)> {
        self.clock.as_ref()?;
        let open = self.discipline.boot_step_open();
        let action = self.discipline.update(self.now(), wall_unix, offset_nanos, confirmed);
        let spent = open && !self.discipline.boot_step_open();
        match self.carry_out(action, delay_nanos) {
            Ok(said) => {
                self.error = None;
                self.complained = false;
                if spent && let Some(boot) = &self.boot {
                    boot.spend();
                }
                // RFC 8633 §5.2: past PANICT only at startup; the log says why.
                let big = matches!(action, Action::Step { offset_nanos } if offset_nanos.saturating_abs() >= PANIC_NANOS);
                match said {
                    Some((level, text)) if spent && big && !confirmed => Some((
                        level,
                        format!("{text} (primeiro acerto deste boot, sem confirmação: RFC 8633 §5.2)"),
                    )),
                    other => other,
                }
            }
            Err(e) => {
                // Whatever the discipline believed did not happen.
                self.discipline.reset();
                if open {
                    self.discipline.allow_boot_step();
                }
                self.frequency = None;
                self.taken_over = false;
                self.state = ClockState::NotSet;
                let first = !self.complained;
                self.complained = true;
                let text = format!("cannot set the system clock: {e}");
                self.error = Some(text.clone());
                first.then_some(("warning", format!("NTP: {text}")))
            }
        }
    }

    fn carry_out(
        &mut self,
        action: Action,
        delay_nanos: i64,
    ) -> Result<Option<(&'static str, String)>, ClockError> {
        let Some(clock) = &mut self.clock else {
            return Ok(None);
        };
        let moves = matches!(action, Action::Slew { .. } | Action::Step { .. });
        if moves && !self.taken_over {
            clock.take_over()?;
            self.taken_over = true;
        }
        let ms = |n: i64| n as f64 / 1e6;
        let mut said = None;
        match action {
            Action::Slew { offset_nanos, .. } => {
                self.state = ClockState::Slewing;
                self.last_adjustment_ms = Some(ms(offset_nanos));
            }
            Action::Step { offset_nanos } => {
                clock.step(offset_nanos)?;
                self.state = ClockState::Stepped;
                self.last_adjustment_ms = Some(ms(offset_nanos));
                said = Some((
                    "warning",
                    format!(
                        "NTP: relógio do sistema acertado de uma vez em {:+.3} s",
                        offset_nanos as f64 / 1e9
                    ),
                ));
            }
            Action::HoldSpike { offset_nanos, held_secs } => {
                self.state = ClockState::HoldingSpike;
                if held_secs == 0.0 {
                    said = Some((
                        "warning",
                        format!(
                            "NTP: o servidor agora difere {:+.3} s; o relógio fica como está por \
                             até 900 s, para o caso de ser uma resposta errada (RFC 5905 §11.3)",
                            offset_nanos as f64 / 1e9
                        ),
                    ));
                }
            }
            Action::NeedConfirm { offset_nanos } => {
                self.state = ClockState::AwaitingConfirmation;
                if self.asked != Some(offset_nanos / 60_000_000_000) {
                    self.asked = Some(offset_nanos / 60_000_000_000);
                    said = Some((
                        "warning",
                        format!(
                            "NTP: o relógio está {:+.0} s fora; acima de 1000 s é preciso \
                             confirmar: system.ntp.client.confirm-step",
                            offset_nanos as f64 / 1e9
                        ),
                    ));
                }
            }
            Action::Refuse { offset_nanos } => {
                self.state = ClockState::Refused;
                if !self.complained {
                    said = Some((
                        "error",
                        format!(
                            "NTP: resposta recusada: {:+.0} s levaria o relógio para antes de 2026",
                            offset_nanos as f64 / 1e9
                        ),
                    ));
                }
            }
        }
        self.push_frequency()?;
        // Half the round trip bounds the error (RFC 5905 §8); the maximum
        // also leaves room for the correction under way.
        let estimated = u64::try_from(delay_nanos / 2).unwrap_or(0);
        let maximum = estimated.saturating_add(self.discipline_error());
        if moves && let Some(clock) = &mut self.clock {
            clock.synchronized(estimated, maximum, self.hardware)?;
            if self.hardware == HardwareClock::LeaveAlone && !self.told_hardware {
                self.told_hardware = true;
                const LIVE: &str = "imagem live: o relógio da placa (RTC) fica como está, para não \
                                    mudar a hora que outro sistema da máquina lê";
                said = Some(match said {
                    Some((level, text)) => (level, format!("{text}; {LIVE}")),
                    None => ("info", format!("NTP: relógio do sistema acertado; {LIVE}")),
                });
            }
        }
        Ok(said)
    }

    fn discipline_error(&self) -> u64 {
        match self.last_adjustment_ms {
            Some(ms) if self.state == ClockState::Slewing => (ms.abs() * 1e6) as u64,
            _ => 0,
        }
    }

    /// The fields of the status this driver owns.
    fn fill(&self, status: &mut NtpStatus) {
        status.clock = self.state;
        status.last_adjustment_ms = self.last_adjustment_ms;
        status.freq_drift_ppm = self.clock.as_ref().map(|_| self.discipline.drift_ppm());
        status.pending_step_ms = self.discipline.pending_step().map(|n| n as f64 / 1e6);
        status.clock_error = self.error.clone();
    }
}

/// Servers to ask: the configured, then the dynamic, without repeats, at
/// most [`MAX_SERVERS`]. Returns also the dynamic ones actually used.
fn merged_servers(cfg: &NtpClient, dynamic: &[std::net::Ipv4Addr]) -> (Vec<String>, Vec<String>) {
    let mut all: Vec<String> = cfg.servers.iter().take(MAX_SERVERS).cloned().collect();
    let mut extra = Vec::new();
    for ip in dynamic {
        let name = ip.to_string();
        if all.len() < MAX_SERVERS && !all.contains(&name) {
            all.push(name.clone());
            extra.push(name);
        }
    }
    (all, extra)
}

type OpenClock<'a> = Option<&'a dyn Fn() -> Result<Box<dyn SystemClock>, String>>;

fn open_clock(session: &Shared, open: OpenClock<'_>, boot: &BootStep) -> ClockDriver {
    // G4.6o: on the live image (`--live`) the RTC is left as it is.
    let hardware = if corerouter_engine::live::is_live(&lock(session)) {
        HardwareClock::LeaveAlone
    } else {
        HardwareClock::Follow
    };
    ClockDriver::new(match open {
        Some(f) => f(),
        None => lock(session).open_system_clock(),
    })
    .with_boot_step(boot)
    .with_hardware_clock(hardware)
}

fn run(session: &Shared, port: u16, health: &super::Health, open: OpenClock<'_>, boot: &BootStep) {
    let mut cfg: Option<NtpClient> = None;
    let mut status = NtpStatus::default();
    let mut poll_exp = 0u8;
    let mut next = Instant::now();
    let mut last_round: Option<Instant> = None;
    let mut denied: BTreeSet<String> = BTreeSet::new();
    let mut warned = false;
    let mut dynamic: Vec<String> = Vec::new();
    let mut driver: Option<ClockDriver> = None;
    // The operator confirmed a step; held until a round has a sample.
    let mut confirmed = false;
    loop {
        health.beat();
        let (now_cfg, peers, confirmation) = {
            let mut s = lock(session);
            (
                s.store().running().system.ntp_client.clone(),
                s.dhcp_peer_ntp(),
                s.take_ntp_step_confirmation(),
            )
        };
        let (servers, now_dynamic) = merged_servers(&now_cfg, &peers);
        if cfg.as_ref() != Some(&now_cfg) {
            poll_exp = poll_bounds(&now_cfg).0;
            next = Instant::now();
            denied.clear();
            status = NtpStatus {
                status: if now_cfg.enabled {
                    NtpState::Waiting
                } else {
                    NtpState::Stopped
                },
                ..NtpStatus::default()
            };
            lock(session).set_ntp_status(status.clone());
            if let Some(d) = &mut driver
                && !(now_cfg.enabled && now_cfg.set_system_clock)
            {
                d.stand_down();
            }
            if now_cfg.enabled && now_cfg.set_system_clock {
                driver.get_or_insert_with(|| open_clock(session, open, boot));
            }
            cfg = Some(now_cfg.clone());
        } else if now_dynamic != dynamic {
            // A DHCP renewal brought other servers: ask them soon, not
            // sooner than RFC 4330 §5 allows.
            next = next.min(last_round.map_or_else(Instant::now, |t| t + MIN_ROUND_GAP));
            denied.clear();
        }
        dynamic = now_dynamic;
        if confirmation {
            confirmed = true;
            next = next.min(last_round.map_or_else(Instant::now, |t| t + MIN_ROUND_GAP));
        }
        let active = now_cfg.enabled && now_cfg.set_system_clock;
        if active && let Some(d) = &mut driver && let Err(e) = d.tick() {
            d.error = Some(format!("cannot set the system clock: {e}"));
        }
        if now_cfg.enabled && Instant::now() >= next {
            let resolve = |host: &str| super::dns::resolve(session, host);
            let alive = || {
                health.beat();
                !health.stopping()
            };
            let round = poll_round(&servers, port, &now_cfg.vrf, &mut denied, &resolve, &alive);
            if health.stopping() {
                if let Some(d) = &mut driver {
                    d.stand_down();
                }
                return;
            }
            // A round with nobody to ask sent nothing (G1.6zh): the servers
            // a DHCP lease brings a moment later are asked at once, not
            // `MIN_ROUND_GAP` after it.
            if !servers.is_empty() {
                last_round = Some(Instant::now());
            }
            poll_exp = next_poll(poll_exp, &now_cfg, &round);
            let said = match (&round.best, active.then_some(driver.as_mut()).flatten()) {
                (Some((_, _, _, sample)), Some(d)) => {
                    let wall = i64::try_from(unix_nanos() / 1_000_000_000).unwrap_or(i64::MAX);
                    let said = d.apply(sample.offset_nanos, sample.delay_nanos, wall, confirmed);
                    confirmed = false;
                    // RFC 5905 §11.3: while the clock is not settled, keep
                    // the poll short so the next look comes soon.
                    if matches!(
                        d.state,
                        ClockState::Stepped
                            | ClockState::HoldingSpike
                            | ClockState::AwaitingConfirmation
                    ) {
                        poll_exp = poll_bounds(&now_cfg).0;
                    }
                    said
                }
                _ => None,
            };
            let wait = 1u64 << poll_exp.min(17);
            status = round.status(&status, wait, !servers.is_empty());
            status.dynamic_servers = dynamic.clone();
            if let Some(d) = driver.as_ref().filter(|_| active) {
                d.fill(&mut status);
            }
            let spoke = said.is_some();
            if let Some((level, text)) = said {
                log::warn!("{text}");
                lock(session).log_event(
                    &["ntp", level],
                    corerouter_engine::logging::DAEMON,
                    text,
                    serde_json::Value::Null,
                );
            }
            // Nobody corrects the clock: say so, once.
            let corrected = status.clock != ClockState::NotSet;
            if let Some(off) = status.system_offset_ms
                && off.abs() > WARN_OFFSET_MS
                && !warned
                && !corrected
                && !spoke
            {
                let why = status
                    .clock_error
                    .clone()
                    .unwrap_or_else(|| "set_system_clock=no".to_owned());
                let server = status.synced_server.as_deref().unwrap_or("?");
                log::warn!(
                    "NTP: the system clock is off by {:.1} s from {server}, and it is not being \
                     corrected: {why}",
                    off / 1000.0
                );
                lock(session).log_event(
                    &["ntp", "warning"],
                    corerouter_engine::logging::DAEMON,
                    format!(
                        "NTP: o relógio do sistema está {:.1} s fora de {server} e não está sendo \
                         corrigido: {why}",
                        off / 1000.0
                    ),
                    serde_json::Value::Null,
                );
                warned = true;
            }
            next = Instant::now() + Duration::from_secs(wait);
            lock(session).set_ntp_status(status.clone());
            match &status.last_error {
                Some(e) => health.error(e),
                None => health.clear_error(),
            }
            if let Some(server) = &status.synced_server {
                health.event(format!("synchronized with {server}"));
            }
        }
        health.disabled((!now_cfg.enabled).then_some("system.ntp.client enabled=no"));
        let pause = driver.as_ref().filter(|_| active).map_or(TICK, ClockDriver::sleep);
        if !health.sleep(pause) {
            if let Some(d) = &mut driver {
                d.stand_down();
            }
            return;
        }
    }
}

/// What one round learned.
#[derive(Debug, Default)]
pub struct Round {
    /// Best answer: (server as configured, address, its header, sample).
    pub best: Option<(String, SocketAddr, Packet, Sample)>,
    pub errors: Vec<String>,
    pub rate_limited: bool,
}

impl Round {
    /// `asked`: there was somebody to ask. A round that asked nobody says
    /// [`NO_SERVER`]; one whose servers all told it to go away (kiss-o'-death,
    /// skipped from then on) says that instead: the health check sends the
    /// operator to the right place.
    fn status(&self, before: &NtpStatus, poll_secs: u64, asked: bool) -> NtpStatus {
        let ms = |n: i64| n as f64 / 1e6;
        let error = (!self.errors.is_empty()).then(|| self.errors.join("; "));
        match &self.best {
            Some((server, addr, reply, s)) => NtpStatus {
                status: NtpState::Synchronized,
                synced_server: Some(server.clone()),
                synced_address: Some(addr.ip().to_string()),
                synced_stratum: Some(reply.stratum),
                root_delay_ms: Some(f64::from(reply.root_delay) / 65.536),
                root_dispersion_ms: Some(f64::from(reply.root_dispersion) / 65.536),
                leap: Some(reply.leap),
                system_offset_ms: Some(ms(s.offset_nanos)),
                round_trip_ms: Some(ms(s.delay_nanos)),
                last_sync: u64::try_from(unix_nanos() / 1_000_000_000).ok(),
                last_error: error,
                poll_secs: Some(poll_secs),
                ..NtpStatus::default()
            },
            None => NtpStatus {
                status: NtpState::Waiting,
                last_sync: before.last_sync,
                last_error: Some(error.unwrap_or_else(|| {
                    if asked {
                        "every server refused this client (kiss-o'-death DENY or RSTR)".into()
                    } else {
                        NO_SERVER.into()
                    }
                })),
                poll_secs: Some(poll_secs),
                ..NtpStatus::default()
            },
        }
    }
}

/// `(min_poll, max_poll)` inside [`POLL_RANGE`] and in order, whatever the
/// config says: `system.ntp.client.set` checks them, but a saved file is
/// loaded as written (and `clamp` panics when min > max).
fn poll_bounds(cfg: &NtpClient) -> (u8, u8) {
    let (lo, hi) = (*POLL_RANGE.start(), *POLL_RANGE.end());
    let (a, b) = (cfg.min_poll.clamp(lo, hi), cfg.max_poll.clamp(lo, hi));
    (a.min(b), a.max(b))
}

fn next_poll(exp: u8, cfg: &NtpClient, round: &Round) -> u8 {
    let (min, max) = poll_bounds(cfg);
    if round.rate_limited {
        max
    } else if round.best.is_some() {
        exp.saturating_add(1).clamp(min, max)
    } else {
        min
    }
}

/// How a server name becomes addresses: the router's resolver (G4.1a),
/// never the host's.
pub type Resolve<'a> = &'a dyn Fn(&str) -> Result<Vec<IpAddr>, String>;

/// Asks every server not denied; keeps the smallest round trip. `alive`
/// runs before each server (the service beats its heartbeat there) and
/// ends the round early when it says no (a stop).
pub fn poll_round(
    servers: &[String],
    port: u16,
    vrf: &str,
    denied: &mut BTreeSet<String>,
    resolve: Resolve<'_>,
    alive: &dyn Fn() -> bool,
) -> Round {
    let mut round = Round::default();
    for server in servers {
        if !alive() {
            break;
        }
        if denied.contains(server) {
            continue;
        }
        let addr = match resolve(server) {
            Ok(a) => a.first().map(|ip| SocketAddr::new(*ip, port)),
            Err(e) => {
                round.errors.push(format!("{server}: {e}"));
                continue;
            }
        };
        let Some(addr) = addr else {
            round.errors.push(format!("{server}: no address"));
            continue;
        };
        match query(addr, vrf, ANSWER_WAIT) {
            // RFC 5905 §8 bounds the delay below by the precision: a
            // negative one is a broken or lying server, and would win.
            Ok((_, sample)) if sample.delay_nanos < 0 => {
                round
                    .errors
                    .push(format!("{server}: negative round trip (bad timestamps)"));
            }
            Ok((reply, sample)) => {
                let better = round
                    .best
                    .as_ref()
                    .is_none_or(|(_, _, _, b)| sample.delay_nanos < b.delay_nanos);
                if better {
                    round.best = Some((server.clone(), addr, reply, sample));
                }
            }
            Err(QueryError::Reply(ReplyError::Kiss(code))) => {
                if code == "DENY" || code == "RSTR" {
                    log::warn!("NTP: {server} refused us ({code}); not asking it again");
                    denied.insert(server.clone());
                } else if code == "RATE" {
                    round.rate_limited = true;
                }
                round.errors.push(format!("{server}: kiss-o'-death {code}"));
            }
            Err(e) => round.errors.push(format!("{server}: {e}")),
        }
    }
    round
}

#[derive(Debug)]
pub enum QueryError {
    Io(std::io::Error),
    Timeout,
    Reply(ReplyError),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Timeout => f.write_str("no answer"),
            Self::Reply(e) => write!(f, "{e}"),
        }
    }
}

/// A socket on a port the kernel picks (RFC 9109 §4: per-exchange, not
/// shared, not 123), in `vrf`, that only hears `addr`.
fn exchange_socket(addr: SocketAddr, vrf: &str) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if vrf != MAIN_VRF {
        #[cfg(target_os = "linux")]
        sock.bind_device(Some(vrf.as_bytes()))?;
        #[cfg(not(target_os = "linux"))]
        return Err(std::io::Error::other("VRFs exist only on Linux"));
    }
    let local: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    sock.bind(&local.into())?;
    // `connect` makes the kernel drop datagrams from anyone else.
    sock.connect(&addr.into())?;
    Ok(sock.into())
}

/// One exchange with `addr`. Replies that do not answer this request
/// (another origin timestamp: late or forged) are skipped until `wait`.
pub fn query(addr: SocketAddr, vrf: &str, wait: Duration) -> Result<(Packet, Sample), QueryError> {
    let sock = exchange_socket(addr, vrf).map_err(QueryError::Io)?;
    let t1 = unix_nanos();
    let sent = Timestamp::from_unix_nanos(t1);
    sock.send(&Packet::client_request(sent).encode())
        .map_err(QueryError::Io)?;
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(QueryError::Timeout);
        }
        sock.set_read_timeout(Some(left)).map_err(QueryError::Io)?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(QueryError::Timeout);
            }
            Err(e) => return Err(QueryError::Io(e)),
        };
        let t4 = unix_nanos();
        let Ok(reply) = Packet::decode(buf.get(..n).unwrap_or_default()) else {
            continue;
        };
        match check_reply(sent, &reply) {
            Ok(()) => return Ok((reply, sample_of(&reply, t1, t4))),
            Err(ReplyError::WrongOrigin) => continue,
            Err(e) => return Err(QueryError::Reply(e)),
        }
    }
}


/// No flags: configured with `system.ntp.client.*`.
pub(crate) const SERVICE: super::Service = super::Service {
    name: "ntp-client",
    flags: &[],
    topic: "ntp",
    enable: "system.ntp.client.set enabled=yes servers=…",
    depends: &[],
    start,
};

/// G1.6zh: the client on for a config that was never saved (a new router,
/// the live image) and that nobody touched yet. No server goes in: it asks
/// what the DHCP clients learn (`use_peer_ntp`, on by default), so the
/// router talks to no third party the operator did not name. A saved config
/// is left as it is: a file without `ntp_client` still means off.
fn factory_default(session: &Shared) {
    let mut s = lock(session);
    if s.storage_status().loaded_from.is_some()
        || !s.store().running().system.ntp_client.is_default()
    {
        return;
    }
    match s.execute("system.ntp.client.set", &serde_json::json!({"enabled": true})) {
        Ok(_) => log::info!(
            "new config: NTP client on, asking the servers the DHCP clients learn (option 42)"
        ),
        Err(e) => log::warn!("new config: NTP client not turned on: {e}"),
    }
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    // A router has a config directory; the lab without one stays as it is.
    if ctx.config_dir.is_some() {
        factory_default(&ctx.session);
    }
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, corerouter_proto_ntp::PORT, health, None, &BootStep::system());
        Ok(())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use corerouter_proto_ntp::MODE_SERVER;
    use serde_json::json;

    /// A one-socket SNTP server whose clock is `skew_ms` ahead, or that
    /// answers with a kiss code.
    fn server(skew_ms: i128, kiss: Option<&'static [u8; 4]>) -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 128];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let req = Packet::decode(&buf[..n]).unwrap();
                let now = Timestamp::from_unix_nanos(unix_nanos() + skew_ms * 1_000_000);
                let mut reply = Packet {
                    version: 4,
                    mode: MODE_SERVER,
                    stratum: 2,
                    reference_id: *b"TEST",
                    origin: req.transmit,
                    receive: now,
                    transmit: now,
                    ..Packet::default()
                };
                if let Some(code) = kiss {
                    reply.stratum = 0;
                    reply.reference_id = *code;
                }
                let _ = sock.send_to(&reply.encode(), from);
            }
        });
        port
    }

    #[test]
    fn measures_the_offset_of_a_local_server() {
        let port = server(2_000, None);
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let (reply, s) = query(addr, MAIN_VRF, ANSWER_WAIT).unwrap();
        assert_eq!(reply.stratum, 2);
        let off_ms = s.offset_nanos / 1_000_000;
        assert!((1_900..=2_100).contains(&off_ms), "{off_ms} ms");
        assert!(s.delay_nanos < 500_000_000);
    }

    #[test]
    fn silence_is_a_timeout() {
        // Bound but never answering.
        let mute = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = mute.local_addr().unwrap();
        let err = query(addr, MAIN_VRF, Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, QueryError::Timeout), "{err}");
    }

    fn literal(host: &str) -> Result<Vec<IpAddr>, String> {
        host.parse().map(|ip| vec![ip]).map_err(|_| "not an IP".into())
    }

    #[test]
    fn names_go_through_the_router_resolver() {
        let port = server(0, None);
        let via = |h: &str| match h {
            "time.example" => Ok(vec![IpAddr::from([127, 0, 0, 1])]),
            _ => Err("name 'nope.example' does not exist".to_owned()),
        };
        let servers = ["time.example".into(), "nope.example".into()];
        let r = poll_round(&servers, port, MAIN_VRF, &mut BTreeSet::new(), &via, &|| true);
        assert_eq!(r.best.unwrap().0, "time.example");
        assert!(r.errors[0].starts_with("nope.example: name"), "{:?}", r.errors);
    }

    #[test]
    fn deny_drops_the_server_and_rate_slows_down() {
        let deny = server(0, Some(b"DENY"));
        let mut denied = BTreeSet::new();
        let r = poll_round(&["127.0.0.1".into()], deny, MAIN_VRF, &mut denied, &literal, &|| true);
        assert!(r.best.is_none());
        assert!(denied.contains("127.0.0.1"));
        assert!(
            poll_round(&["127.0.0.1".into()], deny, MAIN_VRF, &mut denied, &literal, &|| true)
                .errors
                .is_empty()
        );

        // G1.6zh: servers that all refused are not "nobody to ask".
        let quiet = poll_round(&["127.0.0.1".into()], deny, MAIN_VRF, &mut denied, &literal, &|| true);
        let refused = quiet.status(&NtpStatus::default(), 64, true).last_error.unwrap();
        assert!(refused.contains("refused this client"), "{refused}");
        let nobody = Round::default().status(&NtpStatus::default(), 64, false).last_error.unwrap();
        assert_eq!(nobody, NO_SERVER);

        let rate = server(0, Some(b"RATE"));
        let r = poll_round(&["127.0.0.1".into()], rate, MAIN_VRF, &mut BTreeSet::new(), &literal, &|| true);
        let cfg = NtpClient::default();
        assert_eq!(next_poll(cfg.min_poll, &cfg, &r), cfg.max_poll);
    }

    #[test]
    fn poll_interval_backs_off_and_resets() {
        let cfg = NtpClient {
            min_poll: 6,
            max_poll: 8,
            ..NtpClient::default()
        };
        let good = Round {
            best: Some((
                "s".into(),
                ([127, 0, 0, 1], 123).into(),
                Packet::default(),
                Sample {
                    offset_nanos: 0,
                    delay_nanos: 0,
                },
            )),
            ..Round::default()
        };
        assert_eq!(next_poll(6, &cfg, &good), 7);
        assert_eq!(next_poll(8, &cfg, &good), 8);
        assert_eq!(next_poll(8, &cfg, &Round::default()), 6);

        // audit-services #5: min > max (or out of range) from a saved file
        // panicked in `clamp`, and the supervisor gave up on the service.
        let bad = NtpClient {
            min_poll: 10,
            max_poll: 6,
            ..NtpClient::default()
        };
        assert_eq!(next_poll(6, &bad, &good), 7);
        assert!((6..=10).contains(&next_poll(10, &bad, &good)));
        let low = NtpClient {
            min_poll: 0,
            max_poll: 30,
            ..NtpClient::default()
        };
        assert_eq!(next_poll(0, &low, &Round::default()), 6, "RFC 4330 §5");
        assert_eq!(next_poll(17, &low, &good), 17);
    }

    /// audit-services #11: a reply with T3 < T2 gave a negative delay and
    /// always won the "smallest round trip" selection.
    #[test]
    fn a_negative_round_trip_never_wins() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let liar = sock.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 128];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let req = Packet::decode(&buf[..n]).unwrap();
                let now = unix_nanos();
                let reply = Packet {
                    version: 4,
                    mode: MODE_SERVER,
                    stratum: 1,
                    reference_id: *b"LIAR",
                    origin: req.transmit,
                    // Held the request "ten seconds" in a 1 ms round trip.
                    receive: Timestamp::from_unix_nanos(now - 10_000_000_000),
                    transmit: Timestamp::from_unix_nanos(now),
                    ..Packet::default()
                };
                let _ = sock.send_to(&reply.encode(), from);
            }
        });
        let r = poll_round(
            &["127.0.0.1".into()],
            liar,
            MAIN_VRF,
            &mut BTreeSet::new(),
            &literal,
            &|| true,
        );
        assert!(r.best.is_none(), "{:?}", r.best);
        assert!(r.errors[0].contains("negative"), "{:?}", r.errors);
    }

    /// audit-services #15: a round over mute servers ignored a stop for up
    /// to 8 × (resolve + 2 s).
    #[test]
    fn a_round_stops_between_servers() {
        let mute = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = mute.local_addr().unwrap().port();
        let servers: Vec<String> = (0..8).map(|_| "127.0.0.1".to_owned()).collect();
        let asked = std::cell::Cell::new(0);
        let start = Instant::now();
        let r = poll_round(&servers, port, MAIN_VRF, &mut BTreeSet::new(), &literal, &|| {
            asked.set(asked.get() + 1);
            asked.get() <= 1
        });
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(start.elapsed() < ANSWER_WAIT + Duration::from_secs(1));
    }

    #[test]
    fn the_thread_reports_to_the_session() {
        let port = server(-500, None);
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute(
                "system.ntp.client.set",
                &json!({"enabled": true, "servers": ["127.0.0.1"]}),
            )
            .unwrap();
        spawn(session.clone(), port).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let st = loop {
            let st = lock(&session).ntp_status();
            if st.status == NtpState::Synchronized || Instant::now() > deadline {
                break st;
            }
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(st.status, NtpState::Synchronized, "{st:?}");
        assert_eq!(st.synced_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(st.poll_secs, Some(128), "doubled after a good round");
        let off = st.system_offset_ms.unwrap();
        assert!((-600.0..=-400.0).contains(&off), "{off}");
    }

    /// What the driver did to a clock that only writes it down.
    #[derive(Debug, Clone, PartialEq)]
    enum Op {
        TakeOver,
        Frequency,
        Step(i64),
        Synchronized,
    }

    #[derive(Clone, Default)]
    struct FakeClock {
        ops: std::sync::Arc<std::sync::Mutex<Vec<Op>>>,
        /// What each `synchronized` said about the RTC (G4.6o).
        hardware: std::sync::Arc<std::sync::Mutex<Vec<HardwareClock>>>,
        frequency: std::sync::Arc<std::sync::Mutex<f64>>,
        refuse: bool,
    }

    impl FakeClock {
        fn ops(&self) -> Vec<Op> {
            self.ops.lock().unwrap().clone()
        }

        fn did(&self, op: Op) -> Result<(), ClockError> {
            if self.refuse {
                return Err(ClockError::NoPermission);
            }
            self.ops.lock().unwrap().push(op);
            Ok(())
        }

        fn boxed(&self) -> Result<Box<dyn SystemClock>, String> {
            Ok(Box::new(self.clone()))
        }
    }

    impl SystemClock for FakeClock {
        fn take_over(&mut self) -> Result<(), ClockError> {
            self.did(Op::TakeOver)
        }
        fn set_frequency_ppm(&mut self, ppm: f64) -> Result<(), ClockError> {
            self.did(Op::Frequency)?;
            *self.frequency.lock().unwrap() = ppm;
            Ok(())
        }
        fn step(&mut self, offset_nanos: i64) -> Result<(), ClockError> {
            self.did(Op::Step(offset_nanos))
        }
        fn synchronized(&mut self, _: u64, _: u64, hardware: HardwareClock) -> Result<(), ClockError> {
            self.did(Op::Synchronized)?;
            self.hardware.lock().unwrap().push(hardware);
            Ok(())
        }
    }

    const WALL: i64 = 1_794_000_000;
    const MS: i64 = 1_000_000;
    const SEC: i64 = 1_000 * MS;

    #[test]
    fn a_small_offset_slews_and_a_slew_ends() {
        let fake = FakeClock::default();
        let mut d = ClockDriver::new(fake.boxed());
        assert_eq!(d.apply(1_600_000, 2 * MS, WALL, false), None);
        assert_eq!(
            fake.ops(),
            [Op::TakeOver, Op::Frequency, Op::Synchronized],
            "take over once, run fast, tell the kernel"
        );
        // 1.6 ms over 16 s: 100 ppm.
        assert!((*fake.frequency.lock().unwrap() - 100.0).abs() < 1e-6);
        assert_eq!(d.state, ClockState::Slewing);
        // The second update does not take over again.
        d.apply(8 * MS, 2 * MS, WALL, false);
        assert_eq!(fake.ops().iter().filter(|o| **o == Op::TakeOver).count(), 1);
        // Stopping ends the slew: the frequency goes back to the drift.
        d.stand_down();
        assert_eq!(*fake.frequency.lock().unwrap(), d.discipline.drift_ppm());
    }

    #[test]
    fn a_big_first_offset_steps_and_the_log_says_so() {
        let fake = FakeClock::default();
        let mut d = ClockDriver::new(fake.boxed());
        let said = d.apply(2 * SEC, MS, WALL, false).unwrap();
        assert!(said.1.contains("+2.000 s"), "{said:?}");
        assert!(fake.ops().contains(&Op::Step(2 * SEC)));
        assert_eq!(d.state, ClockState::Stepped);
        assert_eq!(d.last_adjustment_ms, Some(2000.0));
    }

    #[test]
    fn panic_offset_waits_asks_once_and_steps_when_confirmed() {
        let fake = FakeClock::default();
        let mut d = ClockDriver::new(fake.boxed());
        let off = 5000 * SEC;
        let said = d.apply(off, MS, WALL, false).unwrap();
        assert!(said.1.contains("confirm-step"), "{said:?}");
        assert_eq!(d.state, ClockState::AwaitingConfirmation);
        assert_eq!(d.apply(off, MS, WALL, false), None, "asked already");
        assert!(!fake.ops().iter().any(|o| matches!(o, Op::Step(_))));
        let mut st = NtpStatus::default();
        d.fill(&mut st);
        assert_eq!(st.pending_step_ms, Some(5_000_000.0));
        d.apply(off, MS, WALL, true);
        assert!(fake.ops().contains(&Op::Step(off)));
        d.fill(&mut st);
        assert_eq!(st.pending_step_ms, None);
    }

    /// Without CAP_SYS_TIME: keeps measuring, says why, once.
    #[test]
    fn no_permission_is_reported_not_fatal() {
        let fake = FakeClock {
            refuse: true,
            ..FakeClock::default()
        };
        let mut d = ClockDriver::new(fake.boxed());
        let said = d.apply(2 * SEC, MS, WALL, false).unwrap();
        assert!(said.1.contains("CAP_SYS_TIME"), "{said:?}");
        assert_eq!(d.apply(2 * SEC, MS, WALL, false), None);
        let mut st = NtpStatus::default();
        d.fill(&mut st);
        assert_eq!(st.clock, ClockState::NotSet);
        assert!(st.clock_error.unwrap().contains("CAP_SYS_TIME"));
    }

    #[test]
    fn no_clock_measures_only() {
        let mut d = ClockDriver::new(Err("no clock here".into()));
        assert_eq!(d.apply(2 * SEC, MS, WALL, false), None);
        let mut st = NtpStatus::default();
        d.fill(&mut st);
        assert_eq!(st.clock, ClockState::NotSet);
        assert_eq!(st.clock_error.as_deref(), Some("no clock here"));
        assert_eq!(st.freq_drift_ppm, None);
    }

    #[test]
    fn dynamic_servers_come_after_and_are_bounded() {
        let cfg = NtpClient {
            servers: vec!["192.0.2.1".into(), "pool.ntp.org".into()],
            ..NtpClient::default()
        };
        let ip = |i: u8| std::net::Ipv4Addr::new(192, 0, 2, i);
        let (all, extra) = merged_servers(&cfg, &[ip(1), ip(2)]);
        assert_eq!(all, ["192.0.2.1", "pool.ntp.org", "192.0.2.2"]);
        assert_eq!(extra, ["192.0.2.2"], "the static one is not repeated");
        // A hostile lease with 100 servers.
        let many: Vec<_> = (1..=100).map(ip).collect();
        let (all, extra) = merged_servers(&cfg, &many);
        assert_eq!(all.len(), MAX_SERVERS);
        assert_eq!(extra.len(), MAX_SERVERS - 2);
    }

    /// The thread, a skewed server and a fake clock: the step arrives, the
    /// status shows it, and turning the client off ends the discipline.
    #[test]
    fn the_thread_steps_the_clock() {
        let port = server(3_000, None);
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute(
                "system.ntp.client.set",
                &json!({"enabled": true, "servers": ["127.0.0.1"]}),
            )
            .unwrap();
        let fake = FakeClock::default();
        let opener = fake.clone();
        let (s2, health) = (
            session.clone(),
            super::super::Health::new(corerouter_control::Shutdown::default()),
        );
        thread::spawn(move || {
            let open = move || opener.boxed();
            run(&s2, port, &health, Some(&open), &BootStep::default());
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let st = loop {
            let st = lock(&session).ntp_status();
            if st.status == NtpState::Synchronized || Instant::now() > deadline {
                break st;
            }
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(st.clock, ClockState::Stepped, "{st:?}");
        let step = fake.ops().into_iter().find_map(|o| match o {
            Op::Step(n) => Some(n),
            _ => None,
        });
        let step_ms = step.unwrap() / MS;
        assert!((2_900..=3_100).contains(&step_ms), "{step_ms} ms");
        assert!(st.last_adjustment_ms.is_some());
        assert_eq!(st.poll_secs, Some(64), "settling: not doubled after a step");
    }

    /// G4.6m, RFC 8633 §5.2: the notebook of the audit booted 2 h 50 min
    /// behind and waited for `confirm-step`. Now the boot's first step goes
    /// through, the mark (this boot's id) is written, and a daemon started
    /// again in the same boot asks for a big step as before.
    #[test]
    fn the_first_step_of_a_boot_needs_no_confirmation_once() {
        let dir = std::env::temp_dir().join(format!("cr-ntp-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join(BOOT_STEP_FILE);
        // A mark of an earlier boot does not count.
        std::fs::write(&marker, "earlier-boot").unwrap();
        let boot = BootStep::at(Some(marker.clone()), Some("this-boot".into()));
        let start = |skew_ms: i128| {
            let port = server(skew_ms, None);
            let session = shared(Session::virtual_lab());
            lock(&session)
                .execute("system.ntp.client.set", &json!({"enabled": true, "servers": ["127.0.0.1"]}))
                .unwrap();
            let fake = FakeClock::default();
            let opener = fake.clone();
            let (s2, health, boot) = (
                session.clone(),
                super::super::Health::new(corerouter_control::Shutdown::default()),
                boot.clone(),
            );
            thread::spawn(move || {
                let open = move || opener.boxed();
                run(&s2, port, &health, Some(&open), &boot);
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let st = loop {
                let st = lock(&session).ntp_status();
                let settled = matches!(st.clock, ClockState::Stepped | ClockState::AwaitingConfirmation);
                if settled || Instant::now() > deadline {
                    break st;
                }
                thread::sleep(Duration::from_millis(50));
            };
            let log = lock(&session).execute("log.print", &json!({"find": "NTP"})).unwrap().to_string();
            (st, fake, log)
        };
        let (st, fake, log) = start(10_200_000);
        assert_eq!(st.clock, ClockState::Stepped, "{st:?}");
        let step = fake.ops().into_iter().find_map(|o| match o {
            Op::Step(n) => Some(n / SEC),
            _ => None,
        });
        assert!(step.is_some_and(|s| (10_199..=10_201).contains(&s)), "{step:?}");
        assert!(log.contains("primeiro acerto deste boot"), "{log}");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "this-boot");
        // The daemon again, same boot: PANICT holds.
        let (st, fake, log) = start(5_000_000);
        assert_eq!(st.clock, ClockState::AwaitingConfirmation, "{st:?}");
        assert!(!fake.ops().iter().any(|o| matches!(o, Op::Step(_))));
        assert!(log.contains("confirm-step"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// G4.6o: the driver passes its RTC choice to every `synchronized` and,
    /// leaving the RTC alone, says so in the log once.
    #[test]
    fn the_driver_tells_the_clock_whether_the_rtc_follows() {
        let fake = FakeClock::default();
        let mut d = ClockDriver::new(fake.boxed());
        assert_eq!(d.apply(1_600_000, 2 * MS, WALL, false), None, "installed: nothing to say");
        assert_eq!(*fake.hardware.lock().unwrap(), [HardwareClock::Follow]);

        let fake = FakeClock::default();
        let mut d = ClockDriver::new(fake.boxed()).with_hardware_clock(HardwareClock::LeaveAlone);
        let (level, text) = d.apply(1_600_000, 2 * MS, WALL, false).unwrap();
        assert_eq!(level, "info");
        assert!(text.contains("relógio da placa (RTC) fica como está"), "{text}");
        // Said once: the next slew is silent, and still leaves it alone.
        assert_eq!(d.apply(2 * MS, 2 * MS, WALL, false), None);
        assert_eq!(
            *fake.hardware.lock().unwrap(),
            [HardwareClock::LeaveAlone, HardwareClock::LeaveAlone]
        );
        // The first word is joined to a step's line.
        let fake = FakeClock::default();
        let mut d = ClockDriver::new(fake.boxed()).with_hardware_clock(HardwareClock::LeaveAlone);
        let (level, text) = d.apply(300 * MS, 2 * MS, WALL, false).unwrap();
        assert_eq!(level, "warning");
        assert!(text.contains("acertado de uma vez") && text.contains("(RTC) fica como está"), "{text}");
    }

    /// G4.6o, the service: on the live image (`--live`) the clock is set
    /// and the RTC left alone; installed, the RTC follows.
    #[test]
    fn the_live_image_leaves_the_board_clock_alone() {
        let start = |live: bool| {
            let port = server(400, None);
            let session = shared(Session::virtual_lab());
            lock(&session)
                .execute("system.ntp.client.set", &json!({"enabled": true, "servers": ["127.0.0.1"]}))
                .unwrap();
            if live {
                corerouter_engine::live::set(&mut lock(&session));
            }
            let fake = FakeClock::default();
            let opener = fake.clone();
            let (s2, health) = (
                session.clone(),
                super::super::Health::new(corerouter_control::Shutdown::default()),
            );
            thread::spawn(move || {
                let open = move || opener.boxed();
                run(&s2, port, &health, Some(&open), &BootStep::default());
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            while fake.hardware.lock().unwrap().is_empty() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(50));
            }
            thread::sleep(Duration::from_millis(100));
            let log = lock(&session).execute("log.print", &json!({"find": "NTP"})).unwrap().to_string();
            let hardware = fake.hardware.lock().unwrap().clone();
            (hardware, log)
        };
        let (hardware, log) = start(true);
        assert_eq!(hardware, [HardwareClock::LeaveAlone], "{log}");
        assert!(log.contains("relógio da placa (RTC) fica como está"), "{log}");
        let (hardware, log) = start(false);
        assert_eq!(hardware, [HardwareClock::Follow], "{log}");
        assert!(!log.contains("RTC"), "{log}");
    }

    /// `set_system_clock=no`: measures, never opens the clock.
    #[test]
    fn measuring_only_leaves_the_clock_alone() {
        let port = server(3_000, None);
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute(
                "system.ntp.client.set",
                &json!({"enabled": true, "servers": ["127.0.0.1"], "set_system_clock": false}),
            )
            .unwrap();
        let fake = FakeClock::default();
        let opener = fake.clone();
        let (s2, health) = (
            session.clone(),
            super::super::Health::new(corerouter_control::Shutdown::default()),
        );
        thread::spawn(move || {
            let open = move || opener.boxed();
            run(&s2, port, &health, Some(&open), &BootStep::default());
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let st = loop {
            let st = lock(&session).ntp_status();
            if st.status == NtpState::Synchronized || Instant::now() > deadline {
                break st;
            }
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(st.status, NtpState::Synchronized);
        assert_eq!(st.clock, ClockState::NotSet);
        assert_eq!(fake.ops(), []);
    }

    /// A DHCP lease's servers are asked (G4.7a `use_peer_ntp`), with no
    /// static server configured; G1.6zh: also before any DHCP client exists.
    #[test]
    fn a_client_with_only_dynamic_servers_is_allowed_by_config() {
        let session = shared(Session::virtual_lab());
        let mut s = lock(&session);
        let r = s.execute("system.ntp.client.set", &json!({"enabled": true})).unwrap();
        assert!(r["warning"].is_string(), "{r}");
        s.execute("ip.dhcp-client.add", &json!({"interface": "ether1"})).unwrap();
        let r = s.execute("system.ntp.client.set", &json!({"enabled": true})).unwrap();
        assert!(r.get("warning").is_none(), "{r}");
    }

    fn stored(storage: &corerouter_engine::MemoryStorage) -> Shared {
        shared(Session::with_storage(
            Box::new(corerouter_hal::VirtualHal::default()),
            Box::new(storage.clone()),
        ))
    }

    /// G1.6zh: a config that was never saved starts with the client on and
    /// no server of its own; once saved, what the file says holds, on or
    /// off — a file from before this default (no `ntp_client` in it) means
    /// off, as it always did.
    #[test]
    fn a_new_config_starts_with_the_client_on_and_a_saved_one_is_left_alone() {
        // First boot.
        let storage = corerouter_engine::MemoryStorage::default();
        let session = stored(&storage);
        factory_default(&session);
        {
            let s = lock(&session);
            let c = &s.store().running().system.ntp_client;
            assert!(c.enabled && c.servers.is_empty(), "{c:?}");
            let log = s.log_since(0);
            assert!(
                log.iter().any(|e| e.message == "NTP Client ligado: servidores do DHCP (opção 42), poll 6–10"),
                "{log:?}"
            );
        }
        // The operator turns it off: the next boot keeps it off.
        lock(&session).execute("system.ntp.client.set", &json!({"enabled": false})).unwrap();
        drop(session);
        let session = stored(&storage);
        assert!(lock(&session).storage_status().loaded_from.is_some());
        factory_default(&session);
        assert!(!lock(&session).store().running().system.ntp_client.enabled);

        // A router saved before G1.6zh: its file has no `ntp_client` (off was
        // the default and defaults are not written). Nothing changes.
        let storage = corerouter_engine::MemoryStorage::default();
        let session = stored(&storage);
        lock(&session).execute("system.identity.set", &json!({"name": "edge1"})).unwrap();
        drop(session);
        let saved = corerouter_engine::ConfigStorage::load(&mut storage.clone(), corerouter_engine::Slot::Current)
            .unwrap()
            .unwrap();
        assert!(!saved.contains("ntp_client"), "{saved}");
        let session = stored(&storage);
        factory_default(&session);
        let s = lock(&session);
        assert_eq!(s.store().running().system.identity, "edge1");
        assert!(s.store().running().system.ntp_client.is_default());
        assert_eq!(s.store().current_revision(), 1, "no commit of ours");
    }

    /// Before the first save, a client the operator already configured is
    /// not touched either.
    #[test]
    fn the_factory_default_does_not_undo_the_operator() {
        let session = stored(&corerouter_engine::MemoryStorage::default());
        // Off again, but no longer the default: the operator was here.
        lock(&session)
            .execute("system.ntp.client.set", &json!({"servers": ["192.0.2.1"], "max_poll": 12}))
            .unwrap();
        factory_default(&session);
        assert!(!lock(&session).store().running().system.ntp_client.enabled);
    }

    /// G1.6zh: on with nobody to ask says so and sends nothing; a server
    /// that shows up is asked at once. (The server a DHCP lease brings takes
    /// the other path, `MIN_ROUND_GAP` after the last round that asked
    /// somebody: `tests/netns_ntp_first_boot.rs` times it.)
    #[test]
    fn nobody_to_ask_waits_without_delaying_the_first_server() {
        let port = server(250, None);
        let session = shared(Session::virtual_lab());
        lock(&session).execute("system.ntp.client.set", &json!({"enabled": true})).unwrap();
        spawn(session.clone(), port).unwrap();
        let until = |what: &str, ok: &dyn Fn(&NtpStatus) -> bool| {
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                let st = lock(&session).ntp_status();
                if ok(&st) {
                    return st;
                }
                assert!(Instant::now() < end, "timed out waiting for {what}: {st:?}");
                thread::sleep(Duration::from_millis(20));
            }
        };
        let st = until("the empty round", &|st| st.last_error.is_some());
        assert_eq!(st.status, NtpState::Waiting);
        assert_eq!(st.last_error.as_deref(), Some(NO_SERVER));
        let asked = Instant::now();
        lock(&session).execute("system.ntp.client.set", &json!({"servers": ["127.0.0.1"]})).unwrap();
        let st = until("the first answer", &|st| st.status == NtpState::Synchronized);
        assert!(asked.elapsed() < Duration::from_secs(5), "{:?}", asked.elapsed());
        assert!((200.0..=300.0).contains(&st.system_offset_ms.unwrap()), "{st:?}");
    }
}
