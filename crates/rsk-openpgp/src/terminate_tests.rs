// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0x11; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn seeded() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

fn apdu() -> Apdu<'static> {
    Apdu {
        cla: 0x00,
        ins: INS_TERMINATE_DF,
        p1: 0x00,
        p2: 0x00,
        nc: 0,
        ne: 0,
        data: &[],
    }
}

#[test]
fn openpgp_fids_classified_disjoint_from_fido() {
    // OpenPGP internal EFs + a few DO tags.
    for fid in [
        EF_PW1,
        EF_PW3,
        EF_PK_SIG.get(),
        EF_DEK,
        EF_LOGIN_DATA,
        EF_FP,
        EF_SEX,
    ] {
        assert!(is_openpgp_fid(fid), "{fid:#06x} should be OpenPGP");
    }
    // FIDO FIDs (see rsk-fido `is_fido_fid`) must NOT be classified as OpenPGP.
    for fid in [
        0x1080u16, 0x1090, 0x1091, 0x1100, 0x1101, 0xC000, 0xCC00, 0xCF00, 0xD000,
    ] {
        assert!(!is_openpgp_fid(fid), "{fid:#06x} is FIDO, not OpenPGP");
    }
}

/// The device-wide `Fs::factory_wipe` defers each applet's gate records to a second
/// phase, and it can only defer what the applet exports. The set has to be exactly
/// the PW records `scan_files` re-seeds, and every one of them has to be a fid this
/// applet actually owns — a gate arm naming someone else's fid would defer a record
/// another applet's phase-1 sweep already accounts for (audit run-36).
#[test]
fn the_gate_set_is_the_pw_records_and_all_are_openpgp_owned() {
    for fid in [
        EF_PW1,
        EF_RC,
        EF_PW3,
        EF_PW_PRIV,
        EF_PW_RETRIES,
        // The UIF flags are `scan_files`-re-seeded to touch-OFF, so they gate a key
        // a surviving DEK can still open — the OpenPGP analog of FIDO's alwaysUv.
        EF_UIF_SIG,
        EF_UIF_DEC,
        EF_UIF_AUT,
    ] {
        assert!(is_openpgp_gate_fid(fid), "{fid:#06x} gates the applet");
        assert!(
            is_openpgp_fid(fid),
            "{fid:#06x} is deferred but not OpenPGP-owned"
        );
    }
    // FIDO's EF_PIN (0x1080) interleaves with OpenPGP PW1 (0x1081) in the 0x10xx
    // region; the gate set must not reach across into it.
    assert!(!is_openpgp_gate_fid(0x1080));
    // Secrets, not gates: deferring these would invert the rule.
    for fid in [EF_PK_SIG.get(), EF_DEK, EF_LOGIN_DATA] {
        assert!(
            !is_openpgp_gate_fid(fid),
            "{fid:#06x} is a secret, not a gate"
        );
    }
}

#[test]
fn terminate_wipes_openpgp_and_reseeds() {
    let mut fs = seeded();
    // User data that a terminate must erase.
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(EF_LOGIN_DATA, b"alice").unwrap();
    // A FIDO file sharing the Fs must SURVIVE (0x1080 = FIDO EF_PIN).
    fs.put(0x1080, &[8, 4, 1, 0, 0]).unwrap();
    // PW3 verified → terminate permitted.
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu()),
        Sw::OK
    );

    assert!(!fs.has_data(EF_PK_SIG.get()), "imported key must be wiped");
    assert!(!fs.has_data(EF_LOGIN_DATA), "login data must be wiped");
    assert!(
        fs.has_data(0x1080),
        "FIDO file must survive an OpenPGP terminate"
    );
    // Defaults re-seeded.
    assert!(fs.has_data(EF_DEK_PW1.get()));
    let mut pw = [0u8; 7];
    fs.read(EF_PW_PRIV, &mut pw);
    assert_eq!(pw[0], 0x01);
}

#[test]
fn terminate_refused_without_pw3_while_unblocked() {
    let mut fs = seeded();
    // Default PW3 retry counter is 3 (> 0) and PW3 not verified → refused.
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(fs.has_data(EF_DEK_PW1.get()), "nothing wiped on refusal");
}

#[test]
fn terminate_allowed_without_pw3_when_admin_blocked() {
    let mut fs = seeded();
    // Drive the PW3 retry counter to 0 (admin PIN blocked).
    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    pw[6] = 0;
    fs.put(EF_PW_PRIV, &pw[..n]).unwrap();
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
        Sw::OK
    );
}

#[test]
fn terminate_allowed_when_the_admin_verifier_is_unusable() {
    let mut fs = seeded();
    // A card carrying the pre-fix zero-length PW3 verifier: check_pin refuses it
    // before the retry decrement, so its counter never reaches 0 and the applet
    // would otherwise have no way back.
    let mut rec = [0u8; 64];
    let n = fs.read(EF_PW3, &mut rec).unwrap();
    rec[0] = 0;
    fs.put(EF_PW3, &rec[..n]).unwrap();
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
        Sw::OK
    );
}

#[test]
fn terminate_rejects_p1p2_and_data() {
    let mut fs = seeded();
    let mut bad = apdu();
    bad.p1 = 0x01;
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &bad),
        Sw::INCORRECT_P1P2
    );
    let data = [0u8; 2];
    let withdata = Apdu {
        nc: 2,
        data: &data,
        ..apdu()
    };
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &withdata),
        Sw::WRONG_LENGTH
    );
}

/// TERMINATE DF's sweep is the third of the four the delete-caller audit covers,
/// and the metadata half reaches it the same way: EF_META is ONE blob shared by
/// every applet, so a fault reading it fails an OpenPGP removal over a fid that
/// carries no record of its own. Folding that into `Fs::force_delete`'s single
/// answer let the sweep `?` it out of the loop after the first file — and
/// `terminate_df` skips the re-seed on a failed wipe, so the card was left holding
/// the private-key records the command says it destroyed.
///
/// Returns the answer and the imported secrets still live ON THE MEDIUM. Those are
/// the fids `scan_files` never puts back, so they read the same on both arms; the
/// present cache would not, since a delete marks absent whether or not the backend
/// `remove` ran.
fn terminate_with_ef_meta_stuck(stuck: bool) -> (Sw, Vec<&'static str>) {
    let (backend, medium) = rsk_fs::storage::faults::MetaStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let named: [(&'static str, u16); 5] = [
        ("pk_sig", EF_PK_SIG.get()),
        ("pk_dec", EF_PK_DEC.get()),
        ("pk_aut", EF_PK_AUT.get()),
        ("login", EF_LOGIN_DATA),
        ("fp", EF_FP),
    ];
    for (_, fid) in named {
        fs.put(fid, &[0xAB; 40]).unwrap();
    }
    // A PIV head — that crate mints the only ones — so EF_META is live and the
    // sweep's metadata drops read it rather than short-circuiting on absence.
    fs.meta_add(0x9A00, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    medium.stick(stuck);
    let answered = terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu());
    medium.stick(false);

    let survivors = named
        .iter()
        .filter(|&&(_, fid)| medium.live(fid))
        .map(|&(name, _)| name)
        .collect();
    (answered, survivors)
}

/// Both halves are the assertion: the range is empty, AND the answer is `6581`.
/// The status alone passed the defect, because the aborting sweep answered `6581`
/// too.
#[test]
fn a_faulted_metadata_drop_never_stops_the_wipe_and_never_passes_as_clean() {
    assert_eq!(
        terminate_with_ef_meta_stuck(false),
        (Sw::OK, vec![]),
        "the control: nothing armed, so the wipe takes the range and says so"
    );
    assert_eq!(
        terminate_with_ef_meta_stuck(true),
        (Sw::MEMORY_FAILURE, vec![]),
        "under a faulted EF_META the wipe still owes the WHOLE range — a survivor \
         here is a private key TERMINATE reported destroyed — and it still owes an \
         error for the record it could not prove dropped"
    );
}
