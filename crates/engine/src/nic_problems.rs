//! Network cards the kernel could not bring up in full (G1.6ja): a card with
//! no driver, firmware that did not load, `ice` in Safe Mode. The daemon's
//! `nic_problems` service reads the machine on its own thread and hands the
//! reading over ([`Session::nic_reading_feed`]); here it becomes rows with the
//! reason and what to do, in Portuguese, the health check, the chip of the
//! port in `interface.list`, the line of the CLI and the MCP, and one line in
//! the router's log when a problem shows up or goes.
//!
//! [`evaluate`] is a pure function of the reading. The rules that keep it
//! from crying wolf: only Ethernet counts (a Wi-Fi card is out of the image's
//! purpose), a virtual function without a driver is its owner's choice, what
//! the kernel says about anything but a network card is not looked at, and on
//! the live ISO, which has no firmware files by design, it is a note.

use std::collections::{BTreeMap, BTreeSet};

use corerouter_hal::nic_problem::{Bus, DeviceNotes, NicDevice, NicKind, NicReading, SafeModeCause, names_device};
use serde::Serialize;
use serde_json::{Value, json};

use crate::Session;

/// Lines the CLI and the MCP show at login.
pub const MAX_LINES: usize = 8;

/// One problem of one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// `no-driver`, `firmware`, `safe-mode`.
    pub kind: &'static str,
    pub device: String,
    pub bus: Bus,
    pub ports: Vec<String>,
    pub driver: Option<String>,
    pub vendor_id: String,
    pub product_id: String,
    /// The vendor and product, or the ids.
    pub name: String,
    /// The firmware files the kernel did not find.
    pub files: Vec<String>,
    /// The kernel's error for the first file (`-2`).
    pub error: Option<i32>,
    /// The module of the image that claims a card without a driver.
    pub module: Option<String>,
    /// Normal where it is (the live ISO has no firmware): not a warning.
    pub expected: bool,
    /// Why, in Portuguese.
    pub reason: String,
    /// What to do, in Portuguese.
    pub action: String,
    /// One line in English, for the CLI, the MCP and the log.
    pub line: String,
}

/// A device without a driver that is not a problem, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ignored {
    pub device: String,
    pub bus: Bus,
    pub name: String,
    pub why: &'static str,
}

fn name_of(d: &NicDevice) -> String {
    match (&d.vendor, &d.product) {
        (Some(v), Some(p)) => format!("{v} {p}"),
        (None, Some(p)) => p.clone(),
        (Some(v), None) => format!("{v} {}:{}", d.vendor_id, d.product_id),
        (None, None) if d.vendor_id.is_empty() => d.address.clone(),
        (None, None) => format!("{}:{}", d.vendor_id, d.product_id),
    }
}

/// `ether3`, or the bus address of a device without a port.
fn where_of(d: &NicDevice) -> String {
    if d.ports.is_empty() { d.address.clone() } else { d.ports.join(", ") }
}

fn no_driver(d: &NicDevice, r: &NicReading) -> Problem {
    let name = name_of(d);
    // The live ISO first: its PID 1 loads no module, even with the index of
    // the installed image at hand (**medido** in QEMU: `pcnet32` "existed").
    let (reason, action, line) = match (&d.module, r.modules_off, r.live) {
        (Some(m), _, true) => (
            format!("{name} ({}) sem porta aqui: a ISO não carrega módulos; o driver {m} vem na imagem instalada", d.address),
            "Depois de instalar ela deve virar porta. Se for a sua porta de gerência, instale por outra porta ou pelo console.".to_owned(),
            format!("{name} ({}): no port on the live ISO; module {m} loads once installed", d.address),
        ),
        (None, _, true) => (
            format!("{name} ({}, id {}:{}) sem porta aqui: a ISO só traz os drivers embutidos", d.address, d.vendor_id, d.product_id),
            "Se ela for a sua porta de gerência, instale por outra porta ou pelo console, e confira a placa na tabela de docs/os-image.md: os drivers em módulo estão na imagem instalada.".to_owned(),
            format!("{name} ({}, {}:{}): no driver on the live ISO; it may work once installed", d.address, d.vendor_id, d.product_id),
        ),
        (Some(m), true, false) => (
            format!("{name} ({}) sem driver: o boot tem corerouter.modules=off e o módulo {m} não foi carregado", d.address),
            "Tire corerouter.modules=off da linha do kernel (system.tuning.boot) e reinicie, para a placa virar porta.".to_owned(),
            format!("{name} ({}): no driver, corerouter.modules=off kept module {m} out", d.address),
        ),
        (Some(m), false, false) => (
            format!("{name} ({}) sem driver: o módulo {m} existe nesta imagem e não ficou preso à placa", d.address),
            format!("Veja o que o kernel disse (log.os.print, filtre por {m}) e reinicie. Se repetir, a placa pode estar com defeito ou ser uma revisão que o driver recusa."),
            format!("{name} ({}): no driver, module {m} did not bind", d.address),
        ),
        (None, _, false) => (
            format!("{name} ({}, id {}:{}) sem driver: nenhum módulo desta imagem conhece a placa", d.address, d.vendor_id, d.product_id),
            "Confira a tabela de placas suportadas em docs/os-image.md. Sem driver ela não vira porta; troque a placa ou peça o driver com este id.".to_owned(),
            format!("{name} ({}, {}:{}): no driver in this image", d.address, d.vendor_id, d.product_id),
        ),
    };
    Problem {
        kind: "no-driver",
        device: d.address.clone(),
        bus: d.bus,
        ports: Vec::new(),
        driver: None,
        vendor_id: d.vendor_id.clone(),
        product_id: d.product_id.clone(),
        name,
        files: Vec::new(),
        error: None,
        module: d.module.clone(),
        expected: false,
        reason,
        action,
        line,
    }
}

fn firmware(d: &NicDevice, n: &DeviceNotes, r: &NicReading) -> Problem {
    let files: Vec<String> = n.files.iter().map(|(f, _)| f.clone()).collect();
    let error = n.files.first().and_then(|(_, e)| *e);
    let list = files.join(", ");
    let driver = d.driver.clone().or_else(|| n.driver.clone()).unwrap_or_else(|| "driver".into());
    let at = where_of(d);
    let err = error.map(|e| format!(" (erro {e})")).unwrap_or_default();
    let (reason, action) = if r.live {
        (
            format!("{at}: o {driver} pediu {list}, que a ISO não traz"),
            "Nada a fazer: a imagem instalada traz o firmware; a porta pode ficar com menos recursos até lá.".to_owned(),
        )
    } else {
        (
            format!("{at}: o {driver} não conseguiu carregar {list}{err}; a porta pode não subir, ou subir sem os recursos que dependem dele"),
            "O arquivo deveria vir na imagem: confira a versão (system.package.print) e atualize (system.package.update). Se a trava de firmware não traz o arquivo, a licença não permite ou ele não existe (linhas skip, docs/os-image.md): troque a placa.".to_owned(),
        )
    };
    Problem {
        kind: "firmware",
        device: d.address.clone(),
        bus: d.bus,
        ports: d.ports.clone(),
        driver: Some(driver.clone()),
        vendor_id: d.vendor_id.clone(),
        product_id: d.product_id.clone(),
        name: name_of(d),
        files,
        error,
        module: None,
        expected: r.live,
        reason,
        action,
        line: format!("{at}: {driver} could not load firmware {list}"),
    }
}

fn safe_mode(d: &NicDevice, n: Option<&DeviceNotes>, r: &NicReading) -> Problem {
    let cause = n.and_then(|n| n.safe_mode).unwrap_or(SafeModeCause::Unknown);
    let files: Vec<String> = n.map(|n| n.files.iter().map(|(f, _)| f.clone()).collect()).unwrap_or_default();
    let at = where_of(d);
    let limits = "uma fila só, sem RSS, sem XDP e sem offloads: o tráfego passa, num núcleo";
    let action = if r.live {
        "Nada a fazer: é o esperado na ISO, que não traz o pacote DDP; a imagem instalada traz.".to_owned()
    } else {
        match cause {
            SafeModeCause::FileMissing => "O pacote intel/ice/ddp/ice.pkg deveria vir na imagem: atualize (system.package.update). Se persistir, confira no boot a linha do pacote em log.os.print.".to_owned(),
            SafeModeCause::FileInvalid => "O pacote DDP está inválido ou com assinatura recusada: atualize a imagem (system.package.update), que traz o arquivo conferido por hash.".to_owned(),
            SafeModeCause::Version => "Pacote, driver e NVM da placa não combinam: atualize a imagem (system.package.update) e, se a mensagem pedir, o NVM da placa com a ferramenta da Intel.".to_owned(),
            SafeModeCause::Unknown => "Veja o motivo em log.os.print (filtre por ice) e reinicie. Se repetir, atualize a imagem (system.package.update) e o NVM da placa.".to_owned(),
        }
    };
    let what = match cause {
        SafeModeCause::FileMissing => "o pacote DDP não foi encontrado",
        SafeModeCause::FileInvalid => "o pacote DDP é inválido",
        SafeModeCause::Version => "pacote DDP, driver e NVM não combinam",
        SafeModeCause::Unknown => "o driver só oferece uma fila",
    };
    Problem {
        kind: "safe-mode",
        device: d.address.clone(),
        bus: d.bus,
        ports: d.ports.clone(),
        driver: Some("ice".into()),
        vendor_id: d.vendor_id.clone(),
        product_id: d.product_id.clone(),
        name: name_of(d),
        line: format!(
            "{at}: ice in Safe Mode, one queue, no XDP{}",
            files.first().map(|f| format!(" ({f})")).unwrap_or_default()
        ),
        files,
        error: None,
        module: None,
        expected: r.live,
        reason: format!("{at}: ice em Safe Mode: {what}; {limits}"),
        action,
    }
}

/// The problems of a reading, and the driverless devices that are not one.
pub fn evaluate(r: &NicReading) -> (Vec<Problem>, Vec<Ignored>) {
    let mut out = Vec::new();
    let mut ignored = Vec::new();
    for d in &r.devices {
        let ignore = |why| Ignored { device: d.address.clone(), bus: d.bus, name: name_of(d), why };
        if d.kind == NicKind::Other {
            if d.driver.is_none() {
                ignored.push(ignore("not Ethernet (Wi-Fi and the like are out of the image's purpose)"));
            }
            continue;
        }
        if d.driver.is_none() && d.bus != Bus::Mdio {
            if d.virtual_function {
                ignored.push(ignore("SR-IOV virtual function: no driver may be on purpose"));
            } else {
                out.push(no_driver(d, r));
            }
            continue;
        }
        let notes = r.notes.iter().find(|(logged, _)| names_device(logged, &d.address)).map(|(_, n)| n);
        if d.safe_mode_queues || notes.is_some_and(|n| n.safe_mode.is_some()) {
            out.push(safe_mode(d, notes, r));
        } else if let Some(n) = notes.filter(|n| !n.files.is_empty()) {
            out.push(firmware(d, n, r));
        }
    }
    (out, ignored)
}

/// What the session keeps.
#[derive(Debug, Default)]
pub struct NicState {
    reading: Option<NicReading>,
    problems: Vec<Problem>,
    ignored: Vec<Ignored>,
    /// (kind, device) already in the log.
    logged: BTreeSet<(String, String)>,
}

impl Session {
    /// A new reading, from the daemon's service. Only arithmetic and the log
    /// line of what changed: the reads were outside the lock.
    pub fn nic_reading_feed(&mut self, reading: NicReading) {
        let (problems, ignored) = evaluate(&reading);
        let now: BTreeSet<(String, String)> = problems.iter().map(|p| (p.kind.to_owned(), p.device.clone())).collect();
        let was = self.ext::<NicState>().map(|s| s.logged.clone()).unwrap_or_default();
        for p in problems.iter().filter(|p| !was.contains(&(p.kind.to_owned(), p.device.clone()))) {
            let level = if p.expected { "info" } else { "warning" };
            self.log_event(&["interface", level], "nic", p.line.clone(), json!({"kind": p.kind, "device": p.device, "files": p.files}));
        }
        for (kind, device) in was.difference(&now) {
            self.log_event(&["interface", "info"], "nic", format!("{device}: {kind} problem gone"), Value::Null);
        }
        if let Some(s) = self.ext_mut::<NicState>() {
            s.reading = Some(reading);
            s.problems = problems;
            s.ignored = ignored;
            s.logged = now;
        }
    }

    /// The lab knows its machine without a service; no log line for it.
    fn nic_state(&mut self) -> Option<&NicState> {
        if self.ext::<NicState>().is_none_or(|s| s.reading.is_none())
            && let Some(reading) = self.hal_mut().nic_reading()
            && let Some(s) = self.ext_mut::<NicState>()
        {
            (s.problems, s.ignored) = evaluate(&reading);
            s.logged = s.problems.iter().map(|p| (p.kind.to_owned(), p.device.clone())).collect();
            s.reading = Some(reading);
        }
        self.ext::<NicState>().filter(|s| s.reading.is_some())
    }

    /// `interface.hardware-problem.print`.
    pub(crate) fn nic_problems_json(&mut self) -> Value {
        let Some(s) = self.nic_state() else {
            return json!({
                "scanned": false,
                "reason": "nobody has looked at this machine's cards (no daemon service on this backend)",
                "live": false, "kernel_log": false, "kernel_log_reason": null,
                "devices": 0, "problems": [], "ignored": [],
            });
        };
        let r = s.reading.as_ref();
        json!({
            "scanned": true,
            "reason": null,
            "live": r.is_some_and(|r| r.live),
            "kernel_log": r.is_some_and(|r| r.kernel_log),
            "kernel_log_reason": r.and_then(|r| r.kernel_log_reason.as_ref()),
            "devices": r.map_or(0, |r| r.devices.iter().filter(|d| d.bus != Bus::Mdio).count()),
            "problems": s.problems,
            "ignored": s.ignored,
        })
    }

    /// Port → (kind, reason), for `interface.list`.
    pub(crate) fn nic_problems_by_port(&mut self) -> BTreeMap<String, (&'static str, String)> {
        let mut out = BTreeMap::new();
        if let Some(s) = self.nic_state() {
            for p in &s.problems {
                for port in &p.ports {
                    out.insert(port.clone(), (p.kind, p.reason.clone()));
                }
            }
        }
        out
    }

    /// For the health check.
    pub(crate) fn nic_health(&mut self) -> Option<NicHealth> {
        let s = self.nic_state()?;
        let r = s.reading.as_ref()?;
        let (expected, warn): (Vec<&Problem>, Vec<&Problem>) = s.problems.iter().partition(|p| p.expected);
        let mut actions: Vec<String> = Vec::new();
        for p in &warn {
            if !actions.contains(&p.action) {
                actions.push(p.action.clone());
            }
        }
        Some(NicHealth {
            warn: warn.iter().map(|p| p.reason.clone()).collect(),
            expected: expected.iter().map(|p| p.reason.clone()).collect(),
            actions,
            devices: r.devices.iter().filter(|d| d.bus != Bus::Mdio).count(),
            kernel_log: r.kernel_log,
        })
    }

    /// The lines every client shows at login (only what is not expected).
    /// Reads only what is there: no look at the machine under `whoami`.
    pub fn nic_problem_lines(&self) -> Vec<String> {
        self.ext::<NicState>()
            .map(|s| s.problems.iter().filter(|p| !p.expected).take(MAX_LINES).map(|p| p.line.clone()).collect())
            .unwrap_or_default()
    }
}

/// What [`crate::health_check`] needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicHealth {
    pub warn: Vec<String>,
    pub expected: Vec<String>,
    pub actions: Vec<String>,
    pub devices: usize,
    pub kernel_log: bool,
}

#[cfg(test)]
mod tests {
    use corerouter_hal::nic_problem::{KernelNotes, lab_reading};

    use super::*;

    fn dev(address: &str, driver: Option<&str>, port: Option<&str>) -> NicDevice {
        NicDevice {
            bus: Bus::Pci,
            address: address.into(),
            kind: NicKind::Ethernet,
            vendor_id: "8086".into(),
            product_id: "1592".into(),
            vendor: None,
            product: None,
            driver: driver.map(str::to_owned),
            ports: port.map(str::to_owned).into_iter().collect(),
            virtual_function: false,
            module: None,
            safe_mode_queues: false,
        }
    }

    fn reading(devices: Vec<NicDevice>, lines: &[&str]) -> NicReading {
        let mut notes = KernelNotes::default();
        for l in lines {
            notes.line(l);
        }
        notes.keep_devices(&devices);
        NicReading {
            notes: notes.iter().map(|(k, v)| (k.to_owned(), v.clone())).collect(),
            devices,
            kernel_log: true,
            ..NicReading::default()
        }
    }

    #[test]
    fn a_card_without_a_driver_says_what_to_do() {
        let (p, _) = evaluate(&reading(vec![dev("0000:05:00.0", None, None)], &[]));
        assert_eq!(p[0].kind, "no-driver");
        assert!(p[0].reason.contains("8086:1592"), "{}", p[0].reason);
        assert!(p[0].action.contains("docs/os-image.md"), "{}", p[0].action);
        assert!(!p[0].expected);
        assert!(p[0].line.contains("no driver in this image"), "{}", p[0].line);

        // The image has the module: another story.
        let mut d = dev("0000:05:00.0", None, None);
        d.module = Some("nfp".into());
        let (p, _) = evaluate(&reading(vec![d.clone()], &[]));
        assert!(p[0].reason.contains("módulo nfp"), "{}", p[0].reason);
        assert!(p[0].action.contains("log.os.print"), "{}", p[0].action);

        // Told not to load drivers.
        let mut r = reading(vec![d], &[]);
        r.modules_off = true;
        let (p, _) = evaluate(&r);
        assert!(p[0].action.contains("corerouter.modules=off"), "{}", p[0].action);

        // On the live ISO, the install is what fixes it, and it still warns:
        // the operator may be about to lose the only port.
        let mut r = reading(vec![dev("0000:05:00.0", None, None)], &[]);
        r.live = true;
        let (p, _) = evaluate(&r);
        assert!(!p[0].expected);
        assert!(p[0].action.contains("instale"), "{}", p[0].action);
        // The index of the installed image is at hand on the ISO, whose PID 1
        // loads nothing: "did not bind" would be false (found in QEMU).
        let mut with_module = dev("0000:05:00.0", None, None);
        with_module.module = Some("pcnet32".into());
        let mut r = reading(vec![with_module], &[]);
        r.live = true;
        let (p, _) = evaluate(&r);
        assert!(p[0].reason.contains("imagem instalada"), "{}", p[0].reason);
        assert!(p[0].line.contains("once installed"), "{}", p[0].line);
    }

    #[test]
    fn firmware_names_the_file_and_the_port() {
        let (p, _) = evaluate(&reading(
            vec![dev("0000:02:00.0", Some("r8169"), Some("ether2"))],
            &["r8169 0000:02:00.0: Unable to load firmware rtl_nic/rtl8168h-2.fw (-2)"],
        ));
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].kind, "firmware");
        assert_eq!(p[0].files, ["rtl_nic/rtl8168h-2.fw"]);
        assert_eq!(p[0].error, Some(-2));
        assert!(p[0].reason.starts_with("ether2: o r8169"), "{}", p[0].reason);
        assert!(p[0].action.contains("system.package.update"), "{}", p[0].action);
        assert!(p[0].line.contains("rtl_nic/rtl8168h-2.fw"), "{}", p[0].line);
    }

    #[test]
    fn safe_mode_by_log_and_by_queues() {
        let ice = dev("0000:03:00.0", Some("ice"), Some("ether7"));
        let missing = [
            "ice 0000:03:00.0: Direct firmware load for intel/ice/ddp/ice.pkg failed with error -2",
            "ice 0000:03:00.0: The DDP package file was not found or could not be read. Entering Safe Mode",
        ];
        let (p, _) = evaluate(&reading(vec![ice.clone()], &missing));
        assert_eq!(p.len(), 1, "one row, not firmware and Safe Mode: {p:?}");
        assert_eq!(p[0].kind, "safe-mode");
        assert_eq!(p[0].files, ["intel/ice/ddp/ice.pkg"]);
        assert!(p[0].reason.contains("não foi encontrado"), "{}", p[0].reason);
        assert!(p[0].line.contains("ice.pkg"), "{}", p[0].line);

        // A package of the wrong version.
        let (p, _) = evaluate(&reading(vec![ice.clone()], &[
            "ice 0000:03:00.0: The firmware loaded on the device is not compatible with the DDP package.  Please update the device's NVM.  Entering safe mode.",
        ]));
        assert!(p[0].action.contains("NVM"), "{}", p[0].action);

        // The log wrapped, a restarted daemon: the queues still say it.
        let mut q = ice.clone();
        q.safe_mode_queues = true;
        let (p, _) = evaluate(&reading(vec![q], &[]));
        assert_eq!(p[0].kind, "safe-mode");
        assert!(p[0].reason.contains("uma fila"), "{}", p[0].reason);

        // Loaded: nothing.
        let (p, _) = evaluate(&reading(vec![ice], &[
            "ice 0000:03:00.0: The DDP package was successfully loaded: ICE OS Default Package version 1.3.43.0",
        ]));
        assert!(p.is_empty(), "{p:?}");
    }

    #[test]
    fn no_false_alarms() {
        let mut wifi = dev("0000:06:00.0", None, None);
        wifi.kind = NicKind::Other;
        let mut wifi2 = dev("0000:07:00.0", Some("iwlwifi"), Some("wlan0"));
        wifi2.kind = NicKind::Other;
        let mut vf = dev("0000:03:01.0", None, None);
        vf.virtual_function = true;
        let mut phy = dev("stmmac-0:01", None, Some("ether3"));
        phy.bus = Bus::Mdio;
        let (p, ignored) = evaluate(&reading(
            vec![dev("0000:01:00.0", Some("igb"), Some("ether1")), wifi, wifi2, vf, phy],
            &[
                "platform regulatory.0: Direct firmware load for regulatory.db failed with error -2",
                "cfg80211: failed to load regulatory.db",
                "iwlwifi 0000:07:00.0: Direct firmware load for iwlwifi-x.ucode failed with error -2",
                "i915 0000:00:02.0: Direct firmware load for i915/x.bin failed with error -2",
                "cxgb4 0000:01:00.0: Direct firmware load for cxgb4/t5-config.txt failed with error -2",
            ],
        ));
        assert!(p.is_empty(), "{p:?}");
        assert_eq!(ignored.len(), 2);
        assert!(ignored.iter().any(|i| i.why.contains("Wi-Fi")));
        assert!(ignored.iter().any(|i| i.why.contains("SR-IOV")));
    }

    #[test]
    fn on_the_live_iso_missing_firmware_is_a_note() {
        let mut r = reading(
            vec![dev("0000:03:00.0", Some("ice"), Some("ether1")), dev("0000:02:00.0", Some("r8169"), Some("ether2"))],
            &[
                "ice 0000:03:00.0: The DDP package file was not found or could not be read. Entering Safe Mode",
                "r8169 0000:02:00.0: Unable to load firmware rtl_nic/rtl8168h-2.fw (-2)",
            ],
        );
        r.live = true;
        let (p, _) = evaluate(&r);
        assert_eq!(p.len(), 2);
        assert!(p.iter().all(|p| p.expected), "{p:?}");
        assert!(p.iter().all(|p| p.action.contains("Nada a fazer")), "{p:?}");
    }

    #[test]
    fn the_log_says_what_changes_once() {
        let mut s = Session::virtual_lab();
        let bad = reading(vec![dev("0000:05:00.0", None, None)], &[]);
        s.nic_reading_feed(bad.clone());
        s.nic_reading_feed(bad);
        let lines = |s: &mut Session| {
            s.execute("log.print", &json!({})).unwrap().as_array().unwrap().iter()
                .filter(|l| l["origin"] == "nic").map(|l| l["message"].as_str().unwrap().to_owned()).collect::<Vec<_>>()
        };
        let got = lines(&mut s);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("no driver"), "{got:?}");
        assert_eq!(s.nic_problem_lines().len(), 1);
        s.nic_reading_feed(reading(vec![dev("0000:05:00.0", Some("nfp"), Some("ether9"))], &[]));
        let got = lines(&mut s);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[1].contains("gone"), "{got:?}");
        assert!(s.nic_problem_lines().is_empty());
    }

    #[test]
    fn the_lab_reads_itself_silently() {
        let mut s = Session::virtual_lab();
        assert_eq!(s.nic_problems_by_port().get("ether7").map(|p| p.0), Some("safe-mode"));
        let h = s.nic_health().unwrap();
        assert_eq!(h.warn.len(), 2);
        assert!(h.kernel_log);
        assert_eq!(evaluate(&lab_reading()).1.len(), 1, "the Wi-Fi card");
    }
}
