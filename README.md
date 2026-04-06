# E2EE_ntfy
ntfy client implementation with E2EE support written 100% in rust
# why? 
if you havent setup ssl encryption to your ntfy server or your server gets compromised all your notifications are there in plain text for an attacker to see when you E2EE (End To End Encrypt) your notifications it ensures that no one except yourself can have access to your notifications even if a server gets compromissed 
#### note: You shouldn't use this instead of ssl certificates on your ntfy server! they wont be able to access the content of your messages but they could still get everything around it.
# how?
before sending your notifications to your desired server it encrypts your messages with pgp to your public key then when you receive the encrypted message it decrypts using your private key.
# usage
compile the code~
```bash
cargo build --release
```
now run it! running it with no arguments shows usage information.
```bash
target/release/E2EE_ntfy
```
## examples
#### heres a example where this would be useful!
sending .env from one device to another
```bash
#sending it
target/release/E2EE_ntfy send "$(cat .env)" generictopic
#receiving from the other computer
target/release/E2EE_ntfy listen generictopic
```
not really that useful self hosting is safe enough for 99.9% of people this would've been a pull request if I written it in go instead of rust.
