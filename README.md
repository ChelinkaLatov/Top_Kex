# Top Kex

Outil d'analyse de ports SSH pour des audits en boite noire/grise
Ne remplace pas un audit de la configuration, mais aide pas mal sinon.

## Utilisation

```
uv sync
uv run ssh_checker.py HOST 
```

### options :

```
HOST : Le nom de serveur ou l'ip directement. Si un nom est spécifié, l'outil afficher l'ip sélectionnée dans le retour.
--port : Spécifie le port ssh du serveur distant.
--algodir : Plusieurs référentiels sot prévus. Pour le moment, 'default', 'anssi' et 'bsi' sont disponibles.
--add-signature : écrit la signature dans le fichier signature_file. Peut être envoyé au dev pour améliorer la qualité des empreintes.
--copy-banner : Lors de l'authentification, renvoie la même bannière au serveur que celle envoyée.
--enable-auth : Essaie de s'authentifier en none. Cela devant échouer, ça permet de lister les méthodes d'authentification données par le serveur
```

## British version

SSH port analysis for black/graybox audits
Does NOT replace a clean SSH configuration analysis, but helps a lot nonethless.

## Installation

TODO

### Contact

discord: @.chelinka

### Example

```bash
chelinka@MACHINE:~/Top_Kex$ uv run ssh_checker.py 51.210.106.2 --algodir bsi
[i] Connecting to (client.ip) 1.2.3.4:22...
[i] Raw Server Banner: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4
[+] Banner Conformity: RFC 4253 Compliant
[-] Protocol Version: 2.0
[-] Software Version: OpenSSH_7.9p1 (2018-10-19)
[-] Optional Comments: Debian-10+deb10u4
[i] SSH_MSG_KEXINIT received. Parsing protocol lists...
[-] Key Exchange:
[o] 	curve25519-sha256 
[o] 	curve25519-sha256 
[x] 	ecdh-sha2-nistp256 (BSI recommended)
[x] 	ecdh-sha2-nistp384 (BSI recommended)
[x] 	ecdh-sha2-nistp521 (BSI recommended)
[+] 	diffie-hellman-group-exchange-sha256 (BSI recommended)
[o] 	diffie-hellman-group16-sha512 (BSI recommended)
[+] 	diffie-hellman-group18-sha512 
[+] 	diffie-hellman-group14-sha256 
[x] 	diffie-hellman-group14-sha1 
[o] 	kex-strict-s-v00 (Terrapin mitigation)
[+] Server seems resilient against Terrapin attack.
[-] Host Key Algs:
[o] 	rsa-sha2-512 
[o] 	rsa-sha2-256 
[x] 	ssh-rsa 
[o] 	ecdsa-sha2-nistp256 (BSI recommended)
[o] 	ssh-ed25519 
[-] Ciphers (C->S->C):
[o] 	chacha20-poly1305 
[o] 	aes128-ctr (BSI recommended)
[o] 	aes192-ctr (BSI recommended)
[o] 	aes256-ctr (BSI recommended)
[o] 	aes128-gcm (BSI recommended)
[o] 	aes256-gcm (BSI recommended)
[-] MACs (C->S->C)
[x] 	umac-64-etm 
[o] 	umac-128-etm 
[o] 	hmac-sha2-256-etm 
[o] 	hmac-sha2-512-etm 
[+] 	hmac-sha1-etm 
[x] 	umac-64 
[+] 	umac-128 
[+] 	hmac-sha2-256 (BSI Recommended)
[+] 	hmac-sha2-512 (BSI recommended)
[x] 	hmac-sha1 
[-] Compression (C->S->C):
[+] 	none No compression
[+] 	zlib Standard zlib compression
[i] First KEX Packet Follows: False
[s] 1.2.3.4:22;SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4;38e7692881903b133332da1216b61374556a207cb223d810596f1a969925a652;
[-] Fingerprint found in database. Corresponding to :
	OpenSSH_7.9p1
```