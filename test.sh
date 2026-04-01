#!/usr/bin/env bash
delaysend() {
  sleep 3 
  target/debug/EE2E_ntfy send "If you're seeing this everything works!!" null
}
set -e 
echo this will delete your private keys this is only for testing. enter Y to confirm
read -r choice  
if [[ "$choice" = "Y" || "$choice" = "y" ]];then
  echo building..
  cargo build
  rm -rf ~/.config/e2ee_ntfy/
  target/debug/EE2E_ntfy genkey
  echo successful, sending message.
  delaysend &
  target/debug/EE2E_ntfy listen null 
fi
