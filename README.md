# E2EE_ntfy
ntfy client implementation with E2EE support written 100% in rust
# why? 
if you havent setup ssl encryption to your ntfy server or your server gets compromised all your notifications are there in plain text for an attacker to see when you E2EE (End To End Encrypt) your notifications it ensures that no one except yourself can have access to your notifications even if a server gets compromissed 
#### note: You shouldn't use this instead of ssl certificates on your ntfy server! they wont be able to access the content of your messages but they could still get everything around it.
# how?
before sending your notifications to your desired server it encrypts your messages with pgp to your public key then when you receive the encrypted message it decrypts using your private key.
# usage
first you must create your pgp key with gpg which is installed in most linux systems
```bash 
gpg --quick-generate-key notifications@example.com rsa4096 encrypt
```
then you must export your public and private keys the code expects priv.asc to be your private key and pubkey.asc to your public key (private and pubkey generation will be a feature soon so you dont have to do this)
```bash
gpg --armor --export notifications@example.com > pubkey.asc
gpg --export-secret-keys --armor > priv.asc
```
compile the code~
```bash
cargo build --release
```
now run it! running it with no arguments shows usage information.
```bash
./target/release/E2EE_ntfy
```
## examples
#### heres examples where this would be useful!
sending .env from one device to another
```bash
#sending it
./E2EE_ntfy send "$(cat .env)" generictopic
#receiving from the other computer
./E2EE_ntfy listento generictopic
```
not really that useful self hosting is safe enough for 99.9% of people this would've been a pull request if I written it in go instead of rust.
