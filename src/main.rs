use notify_rust::Notification;
use pgp::composed::{Deserializable, Message, MessageBuilder, SignedSecretKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKey;
use pgp::types::Password;
use rand::thread_rng;
use std::env;
use std::io::Cursor;
use std::io::{BufRead, BufReader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (pub_key, _) = pgp::composed::SignedPublicKey::from_armor_file("pubkey.asc")?;
    let args: Vec<String> = env::args().collect();
    let server_url = "https://ntfy.sh/"; // change here to change the base server url 

    if args.len() < 4 {
        println!("usage is {} <subcommand>", args[0]);
        println!("two subcommands are possible send and listento");
        println!("usage for send is {} send \"<message>\" <topic>", args[0]);
        println!("usage for listento is {} listento <topic>", args[0]);
        return Ok(());
    }
    // if we were ran without any args just listen for new encrypted notifications and decrypt them
    if args[1] == "listento" {
        let _ = listen_and_decrypt(server_url, args[2].clone());
    }
    // if subcommand was "send", we send an encrypted notification to server with desired in
    if args[1] == "send" {
        let encrypted = encrypt_2_key(args[2].clone().into_bytes().to_vec(), pub_key.primary_key);
        let topic = args[3].clone();
        let agent = ureq::agent();
        let res = agent
            .post(format!("{server_url}{topic}"))
            .send(encrypted?.as_bytes());
        println!("{:?}", res);
    }
    Ok(())
}

fn listen_and_decrypt(server_url: &str, topic: String) -> Result<(), Box<dyn std::error::Error>> {
    let (private_key, _) = pgp::composed::SignedSecretKey::from_armor_file("priv.asc")?;
    let response = ureq::get(format!("{server_url}{topic}/json")).call()?;
    let reader = BufReader::new(response.into_body().into_reader());
    for line in reader.lines() {
        let line = line?;
        let value = json::parse(&line)?;
        let msg = &value["message"].as_str().unwrap_or("");
        if msg.contains("-----BEGIN PGP MESSAGE-----") {
            println!("notification received, decrypting.");
            let notifcation = decrypt_msg(msg.to_string(), private_key.clone())?;
            println!("notification is \"{}\"", &notifcation);
            let _ = Notification::new()
                .summary("ntfy_E2EE")
                .body(&notifcation)
                .show()
                .unwrap();
        }
    }
    Ok(())
}

fn encrypt_2_key(
    plain: Vec<u8>,
    public_key: PublicKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let mut builder =
        MessageBuilder::from_bytes("", plain).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);

    builder.encrypt_to_key(&mut rng, &public_key)?;

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

    Ok(decrypted?.decompress().unwrap().as_data_string()?)
}
