// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! What the two OATH commands whose whole job is removal answer when the medium
//! refuses it. All three drops below spelled themselves `let _ = fs.delete…`
//! under an unconditional `9000` — the delete-caller audit's caller half, where
//! nothing else on the card repairs the survivor. The siblings that already read
//! the answer are PIV's `DELETE DATA` (`6581`) and CTAP's `deleteCredential`
//! (`CTAP2_ERR_NOT_ALLOWED`).

use super::*;

/// A medium that takes writes and refuses to remove one nominated fid — the shape
/// of a flash whose tombstone write fails, and narrow enough that the setup and
/// the observation cannot be what fails.
struct Unremovable {
    inner: RamStorage,
    fid: std::rc::Rc<std::cell::Cell<u16>>,
}

impl Storage for Unremovable {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if fid == self.fid.get() {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

fn stuck_fs() -> (Fs<Unremovable>, std::rc::Rc<std::cell::Cell<u16>>) {
    let fid = std::rc::Rc::new(std::cell::Cell::new(0u16));
    let mut fs = Fs::new(Unremovable {
        inner: RamStorage::new(),
        fid: fid.clone(),
    });
    fs.scan();
    (fs, fid)
}

fn drive(app: &mut OathApplet, fs: &mut Fs<Unremovable>, raw: &[u8]) -> Sw {
    let mut out = [0u8; 2048];
    let mut res = ResBuf::new(&mut out);
    Applet::process(app, &Apdu::parse(raw).unwrap(), fs, &mut res)
}

fn applet<'a>(rng: &'a RefCell<CountRng>, touch: &'a RefCell<AlwaysConfirm>) -> OathApplet<'a> {
    OathApplet::new(SERIAL, [0x22; 32], None, rng, touch)
}

/// DELETE (`0x02`) names one credential and takes it away. Its `let _ =` meant a
/// refused removal answered `9000` over a TOTP secret still in flash — the host
/// tool prints "deleted" and the shared secret is where it was.
#[test]
fn deleting_a_credential_answers_for_one_that_survives() {
    let (mut fs, stuck) = stuck_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = applet(&rng, &touch);

    let cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    assert_eq!(
        drive(&mut app, &mut fs, &apdu(INS_PUT, 0, 0, &cred)),
        Sw::OK
    );
    // The credential's own fid, so the removal is the only thing that can fail.
    stuck.set(EF_OATH_CRED);

    let deleted = drive(
        &mut app,
        &mut fs,
        &apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"bank")),
    );
    stuck.set(0);

    let (_, listed) = {
        let mut out = [0u8; 2048];
        let mut res = ResBuf::new(&mut out);
        let sw = Applet::process(
            &mut app,
            &Apdu::parse(&apdu(INS_LIST, 0, 0, &[])).unwrap(),
            &mut fs,
            &mut res,
        );
        (sw, res.as_slice().to_vec())
    };
    assert_eq!(
        (deleted, listed.is_empty()),
        (Sw::MEMORY_FAILURE, false),
        "the credential outlived the command that says it deleted it"
    );
}

/// SET CODE (`0x03`) installing a lock also drops any OTP-PIN, because VERIFY PIN
/// raises the same `validated` flag VALIDATE does — so a PIN minted while the
/// applet was open is a second, invisible way past the code being installed right
/// now. That drop was a `let _ =` under a `9000`.
#[test]
fn installing_a_code_answers_for_an_otp_pin_that_survives() {
    let (mut fs, stuck) = stuck_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = applet(&rng, &touch);

    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(
        drive(&mut app, &mut fs, &apdu(INS_PUT, 0, 0, &cred)),
        Sw::OK
    );
    assert_eq!(
        drive(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        ),
        Sw::OK
    );
    stuck.set(EF_OTP_PIN);

    let mut key = vec![ALG_HMAC_SHA1];
    key.extend_from_slice(b"accesscodeaccesscode");
    let chal = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut body = tlv(TAG_KEY, &key);
    body.extend(tlv(TAG_CHALLENGE, &chal));
    body.extend(tlv(
        TAG_RESPONSE,
        &hmac_sha1(b"accesscodeaccesscode", &chal),
    ));
    let installed = drive(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &body));
    stuck.set(0);

    assert_eq!(
        (installed, fs.has_data(EF_OTP_PIN)),
        (Sw::MEMORY_FAILURE, true),
        "the OTP-PIN unlock path outlived the command that says it dropped it"
    );
}

/// SET CODE's other spelling, `73 00`: remove the access code. Fail-CLOSED — the
/// survivor is the lock, not a secret — but `select` derives `validated` from
/// `!code_set`, so a `9000` over a code that stayed hands the owner a card that
/// locks itself again on the next power cycle, behind a code they were told was
/// gone. Same shape as its two siblings above, and fixed with them by class.
#[test]
fn removing_the_access_code_answers_for_a_code_that_survives() {
    let (mut fs, stuck) = stuck_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = applet(&rng, &touch);

    let mut key = vec![ALG_HMAC_SHA1];
    key.extend_from_slice(b"accesscodeaccesscode");
    let chal = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut body = tlv(TAG_KEY, &key);
    body.extend(tlv(TAG_CHALLENGE, &chal));
    body.extend(tlv(
        TAG_RESPONSE,
        &hmac_sha1(b"accesscodeaccesscode", &chal),
    ));
    assert_eq!(
        drive(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &body)),
        Sw::OK
    );
    // Installing the code locks the session down, so removing it needs a VALIDATE
    // over the challenge this SELECT offers — the gate the removal sits behind.
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    Applet::select(&mut app, false, &mut fs, &mut res);
    let offered = find_tag(res.as_slice(), TAG_CHALLENGE as u16)
        .unwrap()
        .to_vec();
    let mut proof = tlv(TAG_RESPONSE, &hmac_sha1(b"accesscodeaccesscode", &offered));
    proof.extend(tlv(TAG_CHALLENGE, &[9u8; 8]));
    assert_eq!(
        drive(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &proof)),
        Sw::OK
    );
    stuck.set(EF_OATH_CODE.get());

    let removed = drive(
        &mut app,
        &mut fs,
        &apdu(INS_SET_CODE, 0, 0, &tlv(TAG_KEY, &[])),
    );
    stuck.set(0);

    assert_eq!(
        (removed, fs.has_key(EF_OATH_CODE)),
        (Sw::MEMORY_FAILURE, true),
        "the lock outlived the command that says it removed it"
    );
}
