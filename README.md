# Top Kex

Top Kex est un petit outil CLI Python pour interroger un serveur SSH et afficher :

- sa bannière SSH ;
- les algorithmes proposés pendant la négociation ;
- les méthodes d'authentification annoncées ;
- une empreinte de configuration utile pour comparer un service a une base locale.

L'outil vise un usage simple en audit boite noire ou boite grise. Il ne remplace pas une revue de configuration SSH.

## Installation

### Avec `uv` (méthode recommandée)

Installation recommandée pour un usage CLI propre et isolé:

```bash
uv tool install .
```

Cette commande crée un environnement outil isolé. Il est donc possible de supprimer
le dossier du dépôt après l'installation et continuer à utiliser `top-kex`
sans dépendre des fichiers sources. C'est la méthode recommandée pour éviter
de mélanger les dépendances de l'outil avec celles du système.

Pour vérifier que l'installation s'est bien passée :

```bash
top-kex --help
```

### Avec `pip`

`pip` fonctionne aussi, mais il faut bien choisir le mode d'installation.

#### Option 1 - environnement virtuel dédié (recommandé avec `pip`)

Installation recommandée dans un environnement virtuel dédie :

```bash
python -m venv .venv
.venv\Scripts\activate
pip install .
```

Installe `top-kex` dans l'environnement Python actif. Une fois
l'installation terminée, tu peux supprimer le dossier du dépôt et continuer a
utiliser l'outil tant que l'environnement reste disponible.

#### Option 2 - installation utilisateur

```bash
pip install --user .
```

Cette option évite de toucher au Python global du système, mais elle
reste moins isolée qu'un environnement virtuel ou avec un environnement uv.


Pour vérifier que l'installation s'est bien passée :

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
top-kex 51.210.106.154 --port 1306 --algodir anssi --enable-auth
```

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

Sortie abregée :

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
[-] Fingerprint found in database. Corresponding to :
	OpenSSH_7.9p1
```

## Installation pour le developpement

Si tu veux lancer le projet depuis le dépôt sans installation globale :

```bash
uv sync
uv run top-kex --help
```

## Limites

- pas de support des range ip / de CIDR pour scanner des plages d'adresses
- pas de support IPv6

## Contact

- discord : `@.chelinka`
