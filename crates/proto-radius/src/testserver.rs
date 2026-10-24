//! A RADIUS server for tests and labs (not for production).
//!
//! Sans-IO like the client: [`TestServer::handle`] takes a datagram and
//! returns the reply with the time it should leave, so a virtual network
//! (the load simulation) or real UDP sockets (the loopback test, the mass
//! lab of G4.3d) can drive it.
//!
//! It knows users (PAP, CHAP, MS-CHAPv1, MS-CHAPv2 with MPPE keys), reply
//! attributes per user, accounting (logged), Status-Server (RFC 5997), and
//! a [`Script`] of misbehaviour: drops (random or the next N), delays,
//! offline, a reply without Message-Authenticator (Blast-RADIUS check), a
//! wrong secret. It keeps the RFC 5080 §2.2.2 duplicate cache, so a
//! retransmission gets the same answer.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::crypto::{self, MaCheck};
use crate::mschap::{self, VENDOR_MICROSOFT, vsa as ms};
use crate::packet::{AttrList, Builder, Code, Packet, PushAttr, attr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestUser {
    pub password: String,
    /// Attributes added to the Access-Accept.
    pub reply: AttrList,
    /// Reject even with the right password.
    pub reject: bool,
}

/// Scripted misbehaviour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    /// Drop this share of requests (0–100), deterministic per seed.
    pub drop_percent: u8,
    /// Drop the next N requests.
    pub drop_next: u32,
    /// Answer this much later.
    pub delay_ms: u64,
    /// Plus a uniform 0..jitter_ms.
    pub jitter_ms: u64,
    /// Drop everything (a dead server).
    pub offline: bool,
    /// Answer Access-Requests without Message-Authenticator.
    pub omit_message_authenticator: bool,
    /// Sign replies with this secret instead.
    pub reply_secret: Option<Vec<u8>>,
    /// Do not answer Status-Server (an old server).
    pub ignore_status_server: bool,
    /// Accept Access-Requests without Message-Authenticator (an old
    /// client). Off: such requests are dropped (Blast-RADIUS).
    pub allow_missing_message_authenticator: bool,
}

/// One logged Accounting-Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcctLog {
    pub from: SocketAddr,
    pub identifier: u8,
    pub status: u32,
    pub session_id: String,
    pub delay_time: u32,
    pub input_octets: u64,
    pub output_octets: u64,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TestServerStats {
    pub received: u64,
    pub dropped: u64,
    pub duplicates: u64,
    pub bad: u64,
    pub accepts: u64,
    pub rejects: u64,
    pub accounting: u64,
    pub status: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub at_ms: u64,
    pub to: SocketAddr,
    pub bytes: Vec<u8>,
}

type Cached = ([u8; 16], Vec<u8>, u64);

#[derive(Debug, Clone)]
pub struct TestServer {
    secret: Vec<u8>,
    users: HashMap<String, TestUser>,
    pub script: Script,
    /// Code answering Status-Server: Access-Accept on an authentication
    /// port, Accounting-Response on an accounting one (RFC 5997 §3).
    pub status_reply: Code,
    pub accounting: Vec<AcctLog>,
    /// Keep at most this many accounting records (oldest dropped).
    pub max_log: usize,
    pub stats: TestServerStats,
    /// RFC 5080 §2.2.2 cache: (source, identifier) → (authenticator,
    /// reply, time).
    dup: HashMap<(SocketAddr, u8), Cached>,
    rng: u64,
    salt: u16,
}

impl TestServer {
    pub fn new(secret: &[u8], seed: u64) -> Self {
        Self {
            secret: secret.to_vec(),
            users: HashMap::new(),
            script: Script::default(),
            status_reply: Code::AccessAccept,
            accounting: Vec::new(),
            max_log: 1 << 20,
            stats: TestServerStats::default(),
            dup: HashMap::new(),
            rng: seed | 1,
            salt: 0,
        }
    }

    pub fn add_user(&mut self, name: &str, password: &str, reply: AttrList) {
        self.users.insert(
            name.to_owned(),
            TestUser {
                password: password.to_owned(),
                reply,
                reject: false,
            },
        );
    }

    pub fn user_mut(&mut self, name: &str) -> Option<&mut TestUser> {
        self.users.get_mut(name)
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn next_salt(&mut self) -> [u8; 2] {
        self.salt = self.salt.wrapping_add(1);
        let s = self.salt.to_be_bytes();
        // RFC 2868 §3.5 / RFC 2548 §2.4.2: the high bit is set.
        [s[0] | 0x80, s[1]]
    }

    /// One datagram in, at most one reply out.
    pub fn handle(&mut self, from: SocketAddr, data: &[u8], now_ms: u64) -> Option<Reply> {
        self.stats.received += 1;
        let s = &mut self.script;
        let drop = s.offline
            || if s.drop_next > 0 {
                s.drop_next -= 1;
                true
            } else {
                false
            };
        let pct = u64::from(self.script.drop_percent.min(100));
        if drop || (pct > 0 && self.rand() % 100 < pct) {
            self.stats.dropped += 1;
            return None;
        }
        let Ok(p) = Packet::parse(data) else {
            self.stats.bad += 1;
            return None;
        };
        let auth = p.authenticator();
        self.dup
            .retain(|_, (_, _, t)| now_ms.saturating_sub(*t) < 30_000);
        if let Some((a, bytes, _)) = self.dup.get(&(from, p.identifier()))
            && *a == auth
        {
            self.stats.duplicates += 1;
            let bytes = bytes.clone();
            return Some(self.reply_at(from, bytes, now_ms));
        }
        let bytes = match p.code() {
            Code::AccessRequest => self.access(&p)?,
            Code::AccountingRequest => self.accounting(&p, from, now_ms)?,
            Code::StatusServer => self.status(&p)?,
            _ => {
                self.stats.bad += 1;
                return None;
            }
        };
        self.dup
            .insert((from, p.identifier()), (auth, bytes.clone(), now_ms));
        Some(self.reply_at(from, bytes, now_ms))
    }

    fn reply_at(&mut self, to: SocketAddr, bytes: Vec<u8>, now_ms: u64) -> Reply {
        let jitter = match self.script.jitter_ms {
            0 => 0,
            j => self.rand() % (j + 1),
        };
        Reply {
            at_ms: now_ms + self.script.delay_ms + jitter,
            to,
            bytes,
        }
    }

    fn sign(&self, b: Builder, request_auth: &[u8; 16]) -> Vec<u8> {
        let secret = self.script.reply_secret.as_deref().unwrap_or(&self.secret);
        crypto::sign_response(b, request_auth, secret)
    }

    fn echo_proxy_state(b: &mut Builder, p: &Packet<'_>) {
        for a in p.attributes().filter(|a| a.typ == attr::PROXY_STATE) {
            let _ = b.push(attr::PROXY_STATE, a.value);
        }
    }

    fn access(&mut self, p: &Packet<'_>) -> Option<Vec<u8>> {
        match crypto::check_message_authenticator(p, &p.authenticator(), &self.secret) {
            MaCheck::Valid => {}
            MaCheck::Absent if self.script.allow_missing_message_authenticator => {}
            _ => {
                self.stats.bad += 1;
                return None;
            }
        }
        let name = p
            .attr(attr::USER_NAME)
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("");
        let user = self.users.get(name).cloned();
        let mut extra = AttrList::new();
        let ok = user
            .as_ref()
            .is_some_and(|u| !u.reject && self.verify(p, name, &u.password, &mut extra));
        let code = if ok {
            Code::AccessAccept
        } else {
            Code::AccessReject
        };
        let mut b = Builder::new(code, p.identifier());
        if !self.script.omit_message_authenticator {
            let _ = b.message_authenticator();
        }
        if ok {
            self.stats.accepts += 1;
            if let Some(u) = &user {
                let _ = b.extend(&u.reply);
            }
            let _ = b.extend(&extra);
        } else {
            self.stats.rejects += 1;
            if p.vsa(VENDOR_MICROSOFT, ms::MS_CHAP2_RESPONSE).is_some() {
                let ident = p
                    .vsa(VENDOR_MICROSOFT, ms::MS_CHAP2_RESPONSE)
                    .and_then(|v| v.first().copied())
                    .unwrap_or(0);
                let mut v = vec![ident];
                v.extend_from_slice(b"E=691 R=0 V=3");
                let _ = b.push_vsa(VENDOR_MICROSOFT, ms::MS_CHAP_ERROR, &v);
            }
        }
        Self::echo_proxy_state(&mut b, p);
        Some(self.sign(b, &p.authenticator()))
    }

    /// Check the credentials; MS-CHAPv2 success attributes go in `extra`.
    fn verify(&mut self, p: &Packet<'_>, name: &str, password: &str, extra: &mut AttrList) -> bool {
        let ra = p.authenticator();
        if let Some(hidden) = p.attr(attr::USER_PASSWORD) {
            return crypto::unhide_user_password(hidden, &self.secret, &ra)
                .is_some_and(|pw| crypto::ct_eq(&pw, password.as_bytes()));
        }
        if p.attr(attr::CHAP_PASSWORD).is_some() {
            return crypto::verify_chap(p, password.as_bytes());
        }
        let challenge = p.vsa(VENDOR_MICROSOFT, ms::MS_CHAP_CHALLENGE);
        let pw = mschap::utf16le(password);
        if let (Some(c), Some(r)) = (challenge, p.vsa(VENDOR_MICROSOFT, ms::MS_CHAP2_RESPONSE)) {
            let (Ok(auth), Some(resp)) = (<[u8; 16]>::try_from(c), mschap::Chap2Response::parse(r))
            else {
                return false;
            };
            let user = mschap::strip_domain(name.as_bytes());
            let want = mschap::generate_nt_response(&auth, &resp.peer_challenge, user, &pw);
            if !crypto::ct_eq(&want, &resp.nt_response) {
                return false;
            }
            let digest = mschap::authenticator_response(
                &pw,
                &resp.nt_response,
                &resp.peer_challenge,
                &auth,
                user,
            );
            let _ = extra.push_vsa(
                VENDOR_MICROSOFT,
                ms::MS_CHAP2_SUCCESS,
                &mschap::chap2_success(resp.ident, &digest),
            );
            let keys = mschap::mppe_keys(&pw, &resp.nt_response);
            for (t, k) in [
                (ms::MS_MPPE_SEND_KEY, keys.send),
                (ms::MS_MPPE_RECV_KEY, keys.recv),
            ] {
                let salt = self.next_salt();
                if let Ok(v) = crypto::salt_encrypt(&k, &self.secret, &ra, salt) {
                    let _ = extra.push_vsa(VENDOR_MICROSOFT, t, &v);
                }
            }
            // RFC 2548 §2.4.4/§2.4.5: encryption allowed, 128-bit keys.
            let _ = extra.push_vsa(
                VENDOR_MICROSOFT,
                ms::MS_MPPE_ENCRYPTION_POLICY,
                &1u32.to_be_bytes(),
            );
            let _ = extra.push_vsa(
                VENDOR_MICROSOFT,
                ms::MS_MPPE_ENCRYPTION_TYPES,
                &4u32.to_be_bytes(),
            );
            return true;
        }
        if let (Some(c), Some(r)) = (challenge, p.vsa(VENDOR_MICROSOFT, ms::MS_CHAP_RESPONSE)) {
            let (Ok(c8), Some(resp)) = (<[u8; 8]>::try_from(c), mschap::Chap1Response::parse(r))
            else {
                return false;
            };
            return resp.flags == 1
                && crypto::ct_eq(&mschap::v1_nt_response(&c8, &pw), &resp.nt_response);
        }
        false
    }

    fn accounting(&mut self, p: &Packet<'_>, from: SocketAddr, now_ms: u64) -> Option<Vec<u8>> {
        if !crypto::verify_computed_request(p, &self.secret) {
            self.stats.bad += 1;
            return None;
        }
        self.stats.accounting += 1;
        let (input_octets, output_octets) = crate::acct::octets(p);
        if self.accounting.len() >= self.max_log {
            self.accounting.remove(0);
        }
        self.accounting.push(AcctLog {
            from,
            identifier: p.identifier(),
            status: p.attr_u32(attr::ACCT_STATUS_TYPE).unwrap_or(0),
            session_id: p
                .attr(attr::ACCT_SESSION_ID)
                .and_then(|v| std::str::from_utf8(v).ok())
                .unwrap_or("")
                .to_owned(),
            delay_time: p.attr_u32(attr::ACCT_DELAY_TIME).unwrap_or(0),
            input_octets,
            output_octets,
            at_ms: now_ms,
        });
        let mut b = Builder::new(Code::AccountingResponse, p.identifier());
        Self::echo_proxy_state(&mut b, p);
        Some(self.sign(b, &p.authenticator()))
    }

    fn status(&mut self, p: &Packet<'_>) -> Option<Vec<u8>> {
        // RFC 5997 §3: Status-Server without a valid Message-Authenticator
        // MUST be silently discarded.
        if self.script.ignore_status_server
            || crypto::check_message_authenticator(p, &p.authenticator(), &self.secret)
                != MaCheck::Valid
        {
            self.stats.bad += 1;
            return None;
        }
        self.stats.status += 1;
        let mut b = Builder::new(self.status_reply, p.identifier());
        if self.status_reply == Code::AccessAccept && !self.script.omit_message_authenticator {
            let _ = b.message_authenticator();
        }
        Some(self.sign(b, &p.authenticator()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from() -> SocketAddr {
        "192.0.2.1:5000".parse().unwrap()
    }

    fn access(id: u8, f: impl FnOnce(&mut Builder, &[u8; 16])) -> Vec<u8> {
        let ra = [id; 16];
        let mut b = Builder::with_authenticator(Code::AccessRequest, id, ra);
        b.message_authenticator().unwrap();
        b.push_text(attr::USER_NAME, "ana").unwrap();
        f(&mut b, &ra);
        crypto::sign_request(b, b"s")
    }

    #[test]
    fn pap_chap_and_mschapv2() {
        let mut s = TestServer::new(b"s", 1);
        s.add_user("ana", "pw", AttrList::new());
        let pap = access(1, |b, ra| {
            b.push(
                attr::USER_PASSWORD,
                &crypto::hide_user_password(b"pw", b"s", ra).unwrap(),
            )
            .unwrap();
        });
        let r = s.handle(from(), &pap, 0).unwrap();
        assert_eq!(Packet::parse(&r.bytes).unwrap().code(), Code::AccessAccept);
        let bad = access(2, |b, ra| {
            b.push(
                attr::USER_PASSWORD,
                &crypto::hide_user_password(b"no", b"s", ra).unwrap(),
            )
            .unwrap();
        });
        let r = s.handle(from(), &bad, 0).unwrap();
        assert_eq!(Packet::parse(&r.bytes).unwrap().code(), Code::AccessReject);

        let chap = access(3, |b, _| {
            let ch = [9u8; 16];
            let mut v = vec![5];
            v.extend_from_slice(&crypto::chap_response(5, b"pw", &ch));
            b.push(attr::CHAP_PASSWORD, &v).unwrap();
            b.push(attr::CHAP_CHALLENGE, &ch).unwrap();
        });
        let r = s.handle(from(), &chap, 0).unwrap();
        assert_eq!(Packet::parse(&r.bytes).unwrap().code(), Code::AccessAccept);

        let auth = [0x5Bu8; 16];
        let peer = [0x21u8; 16];
        let nt = mschap::generate_nt_response(&auth, &peer, b"ana", &mschap::utf16le("pw"));
        let ms2 = access(4, |b, _| {
            b.push_vsa(VENDOR_MICROSOFT, ms::MS_CHAP_CHALLENGE, &auth)
                .unwrap();
            let resp = mschap::Chap2Response {
                ident: 1,
                flags: 0,
                peer_challenge: peer,
                nt_response: nt,
            };
            b.push_vsa(VENDOR_MICROSOFT, ms::MS_CHAP2_RESPONSE, &resp.encode())
                .unwrap();
        });
        let r = s.handle(from(), &ms2, 0).unwrap();
        let p = Packet::parse(&r.bytes).unwrap();
        assert_eq!(p.code(), Code::AccessAccept);
        let ra = [4u8; 16];
        let send =
            crypto::salt_decrypt(p.vsa(311, ms::MS_MPPE_SEND_KEY).unwrap(), b"s", &ra).unwrap();
        assert_eq!(send, mschap::mppe_keys(&mschap::utf16le("pw"), &nt).send);
        let success = p.vsa(311, ms::MS_CHAP2_SUCCESS).unwrap();
        let want =
            mschap::authenticator_response(&mschap::utf16le("pw"), &nt, &peer, &auth, b"ana");
        assert_eq!(
            &success[1..],
            mschap::authenticator_response_string(&want).as_bytes()
        );
    }

    #[test]
    fn duplicates_get_the_cached_answer_and_scripts_drop() {
        let mut s = TestServer::new(b"s", 1);
        s.add_user("ana", "pw", AttrList::new());
        let pap = access(1, |b, ra| {
            b.push(
                attr::USER_PASSWORD,
                &crypto::hide_user_password(b"pw", b"s", ra).unwrap(),
            )
            .unwrap();
        });
        let a = s.handle(from(), &pap, 0).unwrap();
        let b = s.handle(from(), &pap, 10).unwrap();
        assert_eq!(a.bytes, b.bytes);
        assert_eq!((s.stats.accepts, s.stats.duplicates), (1, 1));
        s.script.drop_next = 1;
        assert!(s.handle(from(), &pap, 20).is_none());
        s.script.delay_ms = 500;
        assert_eq!(s.handle(from(), &pap, 30).unwrap().at_ms, 530);
        // Without Message-Authenticator the request is dropped.
        let mut b = Builder::with_authenticator(Code::AccessRequest, 9, [1; 16]);
        b.push_text(attr::USER_NAME, "ana").unwrap();
        assert!(
            s.handle(from(), &crypto::sign_request(b, b"s"), 40)
                .is_none()
        );
    }
}
