# Top Kex

Top Kex est un petit outil CLI Python pour interroger un serveur SSH et afficher rapidement :

- sa banniere SSH ;
- les algorithmes proposes pendant la negociation ;
- les methodes d'authentification annoncees en option ;
- une empreinte de configuration utile pour comparer un service a une base locale.

L'outil vise un usage simple en audit black box ou gray box. Il ne remplace pas un audit complet de configuration SSH.

## Installation

### Avec `uv` (recommande)

Installation recommandee pour un usage CLI propre et isole :

```bash
uv tool install .
```

`uv tool install .` cree un environnement outil isole. Tu peux donc supprimer
le dossier du depot apres l'installation et continuer a utiliser `top-kex`
sans dependre des fichiers sources. C'est la methode recommandee pour eviter
de melanger les dependances de l'outil avec celles de ton Python systeme.

Puis :

```bash
top-kex --help
```

### Avec `pip`

`pip` fonctionne aussi, mais il faut bien choisir le mode d'installation.

#### Option 1 - environnement virtuel dedie (recommande avec `pip`)

Installation recommandee dans un environnement virtuel dedie :

```bash
python -m venv .venv
.venv\Scripts\activate
pip install .
```

Cette commande installe `top-kex` dans l'environnement Python actif. Une fois
l'installation terminee, tu peux supprimer le dossier du depot et continuer a
utiliser l'outil tant que l'environnement reste disponible.

#### Option 2 - installation utilisateur

```bash
pip install --user .
```

Cette option evite en general de toucher au Python global du systeme, mais elle
reste moins isolee qu'un environnement virtuel ou `uv tool`.

#### Option 3 - installation dans le Python courant

```bash
pip install .
```

Cette option installe `top-kex` dans l'environnement Python actuellement actif.
Elle n'est a utiliser que si tu sais exactement quel interpreteur et quelles
dependances tu modifies.

Evite d'installer directement dans le Python systeme si tu veux minimiser les
risques de conflit avec d'autres outils ou applications.

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

- pas de support IPv6 pour le moment.

## Contact

- discord : `@.chelinka`
