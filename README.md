# Top Kex

Top Kex est un petit outil CLI Python pour interroger un serveur SSH et afficher rapidement :

- sa banniere SSH ;
- les algorithmes proposes pendant la negociation ;
- les methodes d'authentification annoncees en option ;
- une empreinte de configuration utile pour comparer un service a une base locale.

L'outil vise un usage simple en audit black box ou gray box. Il ne remplace pas un audit complet de configuration SSH.

## Installation

### Avec `pip`

Installation locale recommandee dans un environnement virtuel :

```bash
python -m venv .venv
.venv\Scripts\activate
pip install .
```

Puis :

```bash
top-kex --help
```

### Avec `uv`

Pour une installation en tant qu'outil CLI :

```bash
uv tool install .
```

Puis :

```bash
top-kex --help
```

## Utilisation

Commande minimale :

```bash
top-kex HOST
```

Exemples :

```bash
top-kex 192.0.2.10
top-kex ssh.example.org --port 2222
top-kex ssh.example.org --algodir bsi
top-kex ssh.example.org --enable-auth
```

Si `HOST` est un nom DNS, l'outil affiche l'adresse IP resolue avant l'analyse.

## Options principales

- `--port INTEGER` : port SSH cible, `22` par defaut.
- `--algodir TEXT` : referentiel a utiliser (`default`, `anssi`, `bsi`).
- `--add-signature` : ajoute la signature generee dans le fichier `signature_file`.
- `--copy-banner` : renvoie au serveur la meme banniere que celle recue.
- `--enable-auth` : tente une authentification `none` pour lister les methodes annoncees.
- `--timeout INTEGER` : delai maximal de connexion en secondes.

Aide complete :

```bash
top-kex --help
```

## Exemple

```bash
top-kex 51.210.106.2 --algodir bsi
```

Sortie abregee :

```text
[i] Connecting to 51.210.106.2:22...
[i] Raw Server Banner: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4
[+] Banner Conformity: RFC 4253 Compliant
[-] Software Version: OpenSSH_7.9p1 (2018-10-19)
[-] Key Exchange:
[o]     curve25519-sha256
[x]     ecdh-sha2-nistp256 (BSI recommended)
[+] Server seems resilient against Terrapin attack.
[s] 51.210.106.2:22;SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4;...
```

## Installation pour le developpement

Si tu veux simplement lancer le projet depuis le depot sans installation globale :

```bash
uv sync
uv run top-kex --help
```

## Limites

- pas de support IPv6 pour le moment ;
- l'analyse repose sur les fichiers de reference presents dans `algorithms/`.

## Contact

- discord : `@.chelinka`
