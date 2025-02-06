use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, aead_encrypt},
    secrecy::ExposeSecret,
};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks, PluginHandler,
};
use base64::prelude::*;
use clap::Parser;
use kem::{Decapsulate, Encapsulate};
use rand_core::OsRng;
use std::{
    array::TryFromSliceError,
    collections::{HashMap, HashSet},
    io,
};
use x_wing::{
    Ciphertext, DecapsulationKey, EncapsulationKey, DECAPSULATION_KEY_SIZE, ENCAPSULATION_KEY_SIZE,
};

const PLUGIN_NAME: &str = "xwing";

struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin::default())
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin::default())
    }
}

#[derive(Default)]
struct RecipientPlugin {
    recipients: Vec<EncapsulationKey>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(recipient::Error::Recipient {
                index,
                message: "This recipient should not be handeled by this plugin".to_string(),
            });
        }

        let pk: Result<&[u8; ENCAPSULATION_KEY_SIZE], TryFromSliceError> = bytes.try_into();
        let pk = match pk {
            Ok(x) => EncapsulationKey::from(x),
            Err(_) => {
                return Err(recipient::Error::Recipient {
                    index,
                    message: "Invalid recipient".to_string(),
                })
            }
        };

        self.recipients.push(pk);

        Ok(())
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(recipient::Error::Identity {
                index,
                message: "This Identity should not be handeled by this plugin".to_owned(),
            });
        }

        let sk: Result<&[u8; DECAPSULATION_KEY_SIZE], TryFromSliceError> = bytes.try_into();
        let sk = match sk {
            Ok(x) => DecapsulationKey::from(x.to_owned()),
            Err(_) => {
                return Err(recipient::Error::Identity {
                    index,
                    message: "Invalid identity".to_string(),
                })
            }
        };

        self.recipients.push(sk.encapsulation_key());

        Ok(())
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
                        let (ct, ss) = recipient.encapsulate(&mut OsRng).unwrap();
                        let wrapped_key = aead_encrypt(&ss, file_key.expose_secret());
                        Stanza {
                            tag: PLUGIN_NAME.to_string(),
                            args: vec![BASE64_STANDARD.encode(ct.as_bytes())],
                            body: wrapped_key,
                        }
                    })
                    .collect()
            })
            .collect()))
    }

    fn labels(&mut self) -> std::collections::HashSet<String> {
        HashSet::default()
    }
}

#[derive(Default)]
struct IdentityPlugin {
    identities: Vec<DecapsulationKey>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(identity::Error::Identity {
                index,
                message: "This Identity should not be handeled by this plugin".to_string(),
            });
        }

        let bytes: [u8; DECAPSULATION_KEY_SIZE] = match bytes.try_into() {
            Ok(x) => x,
            _ => {
                return Err(identity::Error::Identity {
                    index,
                    message: "Invalid identity".to_string(),
                })
            }
        };

        self.identities.push(DecapsulationKey::from(bytes));

        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        Ok(files
            .into_iter()
            .map(|file| try_decrypt_file_key(&self.identities, file))
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

fn try_decrypt_file_key(keys: &Vec<DecapsulationKey>, stanzas: Vec<Stanza>) -> Option<FileKey> {
    stanzas
        .iter()
        .filter_map(|stanza| try_decrypt_stanza(keys, stanza))
        .next()
}

fn try_decrypt_stanza(keys: &Vec<DecapsulationKey>, stanza: &Stanza) -> Option<FileKey> {
    let ct = BASE64_STANDARD.decode(stanza.args.first()?).ok()?;
    let ct = Ciphertext::from(&ct.try_into().ok()?);

    for key in keys {
        let ss = key.decapsulate(&ct).unwrap();
        let file_key = aead_decrypt(&ss, FILE_KEY_BYTES, &stanza.body);

        if let Ok(file_key) = file_key {
            return Some(FileKey::new(Box::new(file_key.try_into().ok()?)));
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
        run_state_machine(&state_machine, Handler)?;
        return Ok(());
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.
    let (sk, pk) = x_wing::generate_key_pair_from_os_rng();
    print_new_identity(PLUGIN_NAME, sk.as_bytes(), &pk.as_bytes());

    Ok(())
}
