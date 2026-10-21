use std::collections::VecDeque;

use super::*;

struct Script {
    input: VecDeque<Message>,
    output: Vec<Message>,
    result: Option<u64>,
}

impl Transport for Script {
    fn send(&mut self, kind: u32, body: &[u8], header: &[u8]) -> Result<()> {
        self.output.push(Message {
            kind,
            body: body.to_vec(),
            header: header.to_vec(),
        });

        if kind == 9524
            && let Some(result) = self.result
        {
            let job = number(header, 10)?.unwrap();

            let mut challenge = Vec::new();

            blob(&mut challenge, 1, &[0x34; 16]);
            uint(&mut challenge, 2, 42);

            let mut challenge_header = Vec::new();

            fixed(&mut challenge_header, 10, 123);

            self.input.push_back(Message {
                kind: 9521,
                header: challenge_header,
                body: challenge,
            });

            // An unrelated successful response must not complete this job.
            self.input.push_back(response(job.wrapping_add(1), 1));
            self.input.push_back(response(job, 8));
            self.input.push_back(response(job, result));
        }

        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Message>> {
        Ok(self.input.pop_front())
    }
}

fn response(job: u64, result: u64) -> Message {
    let mut header = Vec::new();

    fixed(&mut header, 11, job);

    let mut body = Vec::new();

    uint(&mut body, 1, result);

    Message {
        kind: 9525,
        header,
        body,
    }
}

fn session() -> (Lan, Device, config::Auth, Credentials, Script) {
    let device = Device {
        id: 99,
        name: "Frame".into(),
        address: "127.0.0.1:27036".parse().unwrap(),
        frame: true,
    };

    let lan = Lan {
        root: PathBuf::new(),
        local: Local {
            id: 12,
            instance: 13,
            status: vec![],
            users: vec![],
        },
        devices: vec![device.clone()],
    };

    let auth = config::Auth {
        shared: vec![0x12; 32],
        paired: vec![0x56; 32],
    };

    let creds = Credentials {
        ssid: "frame_TEST".into(),
        psk: "test-password".into(),
    };

    let mut status = Vec::new();

    uint(&mut status, 1, 99);

    let script = Script {
        input: VecDeque::from([
            Message {
                kind: 9515,
                header: vec![],
                body: vec![],
            },
            Message {
                kind: 9516,
                header: vec![],
                body: status,
            },
        ]),
        output: vec![],
        result: Some(1),
    };

    (lan, device, auth, creds, script)
}

#[test]
fn authenticated_provisioning_correlates_job_and_answers_proof() {
    let (lan, device, auth, creds, mut script) = session();

    let mut sent = false;

    assert!(
        lan.exchange(
            &mut script,
            &device,
            &auth,
            &creds,
            network_hash(&creds).unwrap(),
            &mut sent,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap()
    );

    assert!(sent);

    let request = script.output.iter().find(|m| m.kind == 9524).unwrap();

    assert_eq!(
        bytes(&request.body, 1).unwrap(),
        Some(creds.ssid.as_bytes())
    );

    assert_eq!(bytes(&request.body, 2).unwrap(), Some(creds.psk.as_bytes()));

    let response = script.output.iter().find(|m| m.kind == 9522).unwrap();

    assert_eq!(number(&response.header, 11).unwrap(), Some(123));

    assert_eq!(number(&response.body, 2).unwrap(), Some(42));

    assert_eq!(bytes(&response.body, 1).unwrap().unwrap().len(), 48);

    let status = script.output.iter().find(|m| m.kind == 9516).unwrap();

    assert_eq!(
        number(bytes(&status.body, 3).unwrap().unwrap(), 29).unwrap(),
        Some(1)
    );
}

#[test]
fn unauthorized_and_unrelated_success_never_confirm_provisioning() {
    let (lan, device, auth, creds, mut script) = session();

    script.result = Some(4);

    let mut sent = false;

    let error = lan
        .exchange(
            &mut script,
            &device,
            &auth,
            &creds,
            1,
            &mut sent,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();

    assert!(error.to_string().contains("authorization rejected"));
}

#[test]
fn reconnect_observes_network_hash_without_reprovisioning() {
    let (lan, device, auth, creds, mut script) = session();

    let expected = network_hash(&creds).unwrap();

    let mut body = Vec::new();

    fixed(&mut body, 5, expected);

    script.input.push_back(Message {
        kind: 9523,
        header: vec![],
        body,
    });

    let mut sent = true;

    assert!(
        lan.exchange(
            &mut script,
            &device,
            &auth,
            &creds,
            expected,
            &mut sent,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap()
    );

    assert!(!script.output.iter().any(|m| m.kind == 9524));
}

#[test]
fn eof_is_not_success_and_wrong_device_is_rejected_before_provisioning() {
    let (lan, mut device, auth, creds, mut script) = session();

    script.result = None;

    let mut sent = false;

    assert!(
        !lan.exchange(
            &mut script,
            &device,
            &auth,
            &creds,
            1,
            &mut sent,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap()
    );

    assert!(sent);

    let (_, _, _, _, mut script) = session();

    device.id = 100;

    sent = false;

    assert!(
        lan.exchange(
            &mut script,
            &device,
            &auth,
            &creds,
            1,
            &mut sent,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );

    assert!(!sent);

    assert!(!script.output.iter().any(|m| m.kind == 9524));
}

#[test]
fn proof_uses_steam_encrypted_iv_and_pkcs7() {
    use openssl::symm::decrypt;

    let key = [0x12; 32];

    let challenge = [0x34; 16];

    let result = proof(&key, &challenge).unwrap();

    assert_eq!(result.len(), 48);

    // ECB decrypt without padding, since this block represents an IV.
    let mut cipher = openssl::symm::Crypter::new(
        Cipher::aes_256_ecb(),
        openssl::symm::Mode::Decrypt,
        &key,
        None,
    )
    .unwrap();

    cipher.pad(false);

    let mut iv = [0; 32];

    let n = cipher.update(&result[..16], &mut iv).unwrap();

    let m = cipher.finalize(&mut iv[n..]).unwrap();

    assert_eq!(n + m, 16);

    assert_eq!(
        decrypt(Cipher::aes_256_cbc(), &key, Some(&iv[..16]), &result[16..]).unwrap(),
        challenge
    );
}

#[test]
fn network_hash_matches_independent_sha1_fixture() {
    let creds = Credentials {
        ssid: "frame_TEST".into(),
        psk: "test-password".into(),
    };

    assert_eq!(network_hash(&creds).unwrap(), 0x9d208a29fce58fc9);
}
