use notify_rust::Notification;
use pgp::composed::{Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PacketTrait;
use pgp::{
    composed::KeyType,
    packet::{PubKeyInner, PublicKey, SecretKey},
    types::{KeyVersion, Password, Timestamp},
};
use rand::thread_rng;
use std::env;
use std::fs;
use std::fs::File;
use std::io::Cursor;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let server_url = "https://ntfy.sh/"; // change here to change the base server url 

    if args.len() < 2 {
        println!("usage is {} <subcommand>", args[0]);
        println!(
            "\"{} genkey\" generates your keypair (run this first)",
            args[0]
        );
        println!("usage for send is {} send \"<message>\" <topic>", args[0]);
        println!("usage for listen is {} listen <topic>", args[0]);
        return Ok(());
    }

    match args[1].as_ref() {
        "send" => {
            let encrypted = encrypt_2_key(args[2].clone().into_bytes().to_vec());
            let topic = &args[3];
            let agent = ureq::agent();
            let res = agent
                .post(format!("{server_url}{topic}"))
                .send(encrypted?.as_bytes());
            println!("{:?}", res);
        }
        "listen" => listen_and_decrypt(server_url, &args[2])?,
        "genkey" => {
            let home = env!("HOME");
            if fs::exists(format!("{}/.config/e2ee_ntfy/secretkey.asc", home)).unwrap()
                || fs::exists(format!("{}/.config/e2ee_ntfy/PublicKey.asc", home)).unwrap()
            {
                Err(
                    "keys already exist refusing to overwrite (run rm -rf ~/.config/e2ee_ntfy/ to overide this warning.)",
                )?
            }
            let (secretkey, pubkey) = gen_keypair();
            let mut path = PathBuf::from(&home);
            path.push(".config/e2ee_ntfy");
            std::fs::create_dir_all(&path).unwrap_or(());
            let mut secretkeyfile =
                File::create(format!("{}/.config/e2ee_ntfy/secretkey.asc", &home))?;
            let mut pubkeyfile =
                File::create(format!("{}/.config/e2ee_ntfy/publicKey.asc", &home))?;
            let _ = pubkey.to_writer_with_header(&mut pubkeyfile);
            let _ = secretkey.to_writer_with_header(&mut secretkeyfile);
            println!("keys were generated");
        }
        _ => println!("wrong usage run without args to get usage"),
    }
    Ok(())
}

fn listen_and_decrypt(server_url: &str, topic: &String) -> Result<(), Box<dyn std::error::Error>> {
    let home = env!("HOME");
    let private_key = if fs::exists(format!("{}/.config/e2ee_ntfy/secretkey.asc", home)).unwrap() {
        pgp::composed::SignedSecretKey::from_file(format!(
            "{}/.config/e2ee_ntfy/secretkey.asc",
            home
        ))
        .expect("secret key exists but is invalid.")
    } else {
        Err("no private key exists run genkey subcommand to generate one.")?
    };
    let response = ureq::get(format!("{server_url}{topic}/json")).call()?;
    let reader = BufReader::new(response.into_body().into_reader());
    for line in reader.lines() {
        let line = line?;
        let value = json::parse(&line)?;
        let msg = value["message"].as_str().unwrap_or("");
        if msg.contains("-----BEGIN PGP MESSAGE-----") {
            println!("notification received, decrypting..");
            let notifcation = decrypt_msg(msg.to_string(), private_key.clone())?;
            println!("notification is {}", &notifcation);
            let _ = Notification::new()
                .summary("E2EE_NTFY")
                .body(&notifcation)
                .show()?;
        }
    }
    Ok(())
}

fn encrypt_2_key(plain: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    let home = env!("HOME");
    let mut rng = thread_rng();
    let pubkey: SignedPublicKey =
        if fs::exists(format!("{}/.config/e2ee_ntfy/publicKey.asc", home)).unwrap() {
            pgp::composed::SignedPublicKey::from_file(format!(
                "{}/.config/e2ee_ntfy/publicKey.asc",
                home
            ))?
        } else {
            Err("no publickey exists run genkey subcommand to generate one.")?
        };

    let mut builder =
        MessageBuilder::from_bytes("", plain).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);

    builder.encrypt_to_key(&mut rng, &pubkey)?;

    let encrypted = builder.to_armored_string(&mut rng, Default::default())?;

    Ok(encrypted)
}

fn decrypt_msg(
    msg: String,
    priv_key: SignedSecretKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let (msg, _) = Message::from_armor(Cursor::new(msg))?;
    let decrypted = msg.decrypt(&Password::from(""), &priv_key);
    if let Err(ref e) = decrypted {
        println!("decryption error {:?}", e)
    }
    Ok(decrypted?.decompress()?.as_data_string()?)
}
fn gen_keypair() -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();
    let now = Timestamp::now();

    let (public_params, secret_params) = KeyType::X25519
        .generate(&mut rng)
        .expect("error generating key");

    let pub_key_inner = PubKeyInner::new(
        KeyVersion::V4,
        KeyType::X25519.to_alg(),
        now,
        None,
        public_params,
    )
    .expect("create inner public key");

    let pub_key = PublicKey::from_inner(pub_key_inner).expect("failed to create public key");

    let sec_key =
        SecretKey::new(pub_key.clone(), secret_params).expect("failed to create secret key");

    (sec_key, pub_key)
}
