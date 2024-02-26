use age_core::format::{FileKey, Stanza};
use age_core::primitives::{aead_decrypt, aead_encrypt};
use age_core::secrecy::ExposeSecret;
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use base64::prelude::*;
use bech32::ToBase32;
use clap::Parser;
use xwing_kem::{XwingCiphertext, XwingPublicKey, XwingSecretKey};

use std::collections::HashMap;
use std::io;

const RECIPIENT_PREFIX: &str = "age1xwing";
const IDENTITY_PREFIX: &str = "AGE-PLUGIN-XWING-";
const STANZA_TAG: &str = "xwing";

#[derive(Default)]
struct RecipientPlugin {
    recipients: Vec<XwingPublicKey>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        _plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        let bytes = match bytes.try_into() {
            Ok(x) => x,
            _ => {
                return Err(recipient::Error::Recipient {
                    index,
                    message: "Invalid recipient".to_owned(),
                })
            }
        };
        self.recipients.push(XwingPublicKey::from(bytes));
        Ok(())
    }

    fn add_identity(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        unimplemented!()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        Ok(Ok(file_keys
            .into_iter()
            .map(|file_key| {
                self.recipients
                    .iter()
                    .map(|recipient| {
                        let (ss, ct) = recipient.encapsulate();
                        let wrapped_key = aead_encrypt(&ss.to_bytes(), file_key.expose_secret());
                        Stanza {
                            tag: STANZA_TAG.to_string(),
                            args: vec![BASE64_STANDARD.encode(ct.to_bytes())],
                            body: wrapped_key,
                        }
                    })
                    .collect()
            })
            .collect()))
    }
}

#[derive(Default)]
struct IdentityPlugin {
    identities: Vec<XwingSecretKey>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        _plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        let bytes = match bytes.try_into() {
            Ok(x) => x,
            _ => {
                return Err(identity::Error::Identity {
                    index,
                    message: "Invalid identity".to_owned(),
                })
            }
        };
        self.identities.push(XwingSecretKey::from(bytes));
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        Ok(files
            .into_iter()
            .map(|file| try_decrypt_file(&self.identities, file))
            .enumerate()
            .map(|(file_index, file_key)| {
                file_key.ok_or(vec![identity::Error::Stanza {
                    file_index,
                    stanza_index: 1,
                    message: "Invalid stanzas".to_string(),
                }])
            })
            .enumerate()
            .collect())
    }
}

fn try_decrypt_file(keys: &Vec<XwingSecretKey>, stanzas: Vec<Stanza>) -> Option<FileKey> {
    stanzas
        .iter()
        .map(|stanza| try_decrypt(keys, stanza))
        .filter(|file_key| file_key.is_some())
        .map(|file_key| file_key.expect("This should never fail"))
        .next()
}

fn try_decrypt(keys: &Vec<XwingSecretKey>, stanza: &Stanza) -> Option<FileKey> {
    let ct = BASE64_STANDARD
        .decode(&stanza.args.get(0).unwrap_or(&"".to_string()))
        .ok()?;
    let ct: [u8; 1120] = ct.try_into().ok()?;
    let ct = XwingCiphertext::from(ct);

    for key in keys {
        let ss = key.decapsulate(ct);
        let file_key = aead_decrypt(&ss.to_bytes(), 16, &stanza.body);

        if let Ok(file_key) = file_key {
            let file_key: [u8; 16] = file_key.try_into().expect("This should never fail");
            return Some(FileKey::from(file_key));
        }
    }

    None
}

#[derive(Debug, Parser)]
struct PluginOptions {
    #[arg(help = "run the given age plugin state machine", long)]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse();

    if let Some(state_machine) = opts.age_plugin {
        // The plugin was started by an age client; run the state machine.
        run_state_machine(
            &state_machine,
            Some(|| RecipientPlugin::default()),
            Some(|| IdentityPlugin::default()),
        )?;
        return Ok(());
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.
    let (sk, pk) = xwing_kem::generate_keypair();
    println!(
        "# created: {}",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    println!(
        "# public key: {}",
        bech32::encode(
            RECIPIENT_PREFIX,
            pk.to_vec().to_base32(),
            bech32::Variant::Bech32
        )
        .unwrap()
        .to_lowercase()
        .as_str()
    );
    println!(
        "{}",
        bech32::encode(
            IDENTITY_PREFIX,
            sk.to_vec().to_base32(),
            bech32::Variant::Bech32
        )
        .unwrap()
        .to_ascii_uppercase()
        .as_str()
    );

    Ok(())
}
