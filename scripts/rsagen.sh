ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N ""
chmod 600 ssh_host_rsa_key
ssh-keygen -t ed25519 -f ssh_host_ed25519 -N ""
chmod 600 ssh_host_ed25519_gen
ssh-keygen -t ecdsa -f ssh_host_ecdsa -N ""
chmod 600 ssh_host_ecdsa -N ""
