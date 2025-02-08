#![forbid(unsafe_code)]

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
    Ciphertext, DecapsulationKey, EncapsulationKey, CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE,
    ENCAPSULATION_KEY_SIZE,
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

impl RecipientPlugin {
    fn wrap_file_key(&self, file_key: FileKey) -> Vec<Stanza> {
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
    }
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
            .map(|file_key| self.wrap_file_key(file_key))
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

impl IdentityPlugin {
    fn decrypt_stanzas(
        &self,
        file_index: usize,
        stanzas: Vec<(usize, Stanza)>,
    ) -> Result<FileKey, Vec<identity::Error>> {
        let mut file_key = None;
        let mut errors = Vec::new();

        for (stanza_index, stanza) in stanzas {
            let arg = match stanza.args.first() {
                Some(arg) => arg,
                None => {
                    errors.push(identity::Error::Stanza {
                        file_index,
                        stanza_index,
                        message: "Stanza is missing arguments".to_string(),
                    });
                    continue;
                }
            };

            let ct = match BASE64_STANDARD.decode(arg) {
                Ok(ct) => ct,
                Err(_) => {
                    errors.push(identity::Error::Stanza {
                        file_index,
                        stanza_index,
                        message: "Malformed base64".to_string(),
                    });
                    continue;
                }
            };

            let ct: [u8; CIPHERTEXT_SIZE] = match ct.try_into() {
                Ok(ct) => ct,
                Err(_) => {
                    errors.push(identity::Error::Stanza {
                        file_index,
                        stanza_index,
                        message: "Malformed ciphertext".to_string(),
                    });
                    continue;
                }
            };

            let ct = Ciphertext::from(&ct);

            let ss = match self
                .identities
                .iter()
                .filter_map(|key| key.decapsulate(&ct).ok())
                .next()
            {
                Some(ss) => ss,
                None => {
                    errors.push(identity::Error::Stanza {
                        file_index,
                        stanza_index,
                        message: "No identity found that can decrypt the file".to_string(),
                    });
                    continue;
                }
            };

            let unwrapped_file_key = match aead_decrypt(&ss, FILE_KEY_BYTES, &stanza.body) {
                Ok(file_key) => FileKey::new(Box::new(file_key.try_into().unwrap_or_else(|_| {
                    panic!(
                        "aead_decrypt returned a plaintext with a different size as {}",
                        FILE_KEY_BYTES
                    )
                }))),
                Err(e) => {
                    errors.push(identity::Error::Stanza {
                        file_index,
                        stanza_index,
                        message: e.to_string(),
                    });
                    continue;
                }
            };

            file_key = Some(unwrapped_file_key);
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        if let Some(file_key) = file_key {
            return Ok(file_key);
        }

        Err(vec![identity::Error::Stanza {
            file_index,
            stanza_index: 0,
            message: "No stanzas found to be handeled by this plugin".to_string(),
        }])
    }
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
            Err(_) => {
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
        let mut ret = HashMap::default();

        for (file_index, stanzas) in files.into_iter().enumerate() {
            let x_wing_stanzas = stanzas
                .into_iter()
                .enumerate()
                .filter(|(_, stanza)| stanza.tag == PLUGIN_NAME)
                .collect();

            ret.insert(file_index, self.decrypt_stanzas(file_index, x_wing_stanzas));
        }

        Ok(ret)
    }
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

    // Here you can assume the binary is being run directly by a user, and perform administrative tasks like generating keys.
    let (sk, pk) = x_wing::generate_key_pair_from_os_rng();
    print_new_identity(PLUGIN_NAME, sk.as_bytes(), &pk.as_bytes());

    Ok(())
}
