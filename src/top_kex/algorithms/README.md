# Ciphers

Ici, les suites de chiffrement sont inscrites pour pouvoir changer / faire de nouveaux formats.
pour créer un nouveau format, il faut:

Créer un nouveau répertoire dans ce répertoire 'algorithms'.
copier le contenu du répertoire default dans ce nouveau répertoire.
Cela inclut les cinq fichiers: `cipher_algorithms.json`, `compression_algorithms.json`, `hostkey_algorithms.json`, `kex_algorithms.json`, `mac_algorithms.json`
Il est ensuite possible de sélectionner les valeurs à mettre pour chaque algorithme. au choix:

- optimal
Les algorithmes que l'on veut, ou qui sont nécessaire à la sécurisation du serveur
- good
Les algorithmes qui sont résistants, mais qui ne sont pas au fait de l'art. i.e. tout ce qui est pas hybride post-quantique pour l'anssi
- bad
Les algorithmes qui sont jugés dépréciés, mais qui ne sont pas encore cassés.
- error
Les algorithmes qui sont jugés obsolètes, qui sont déjà cassés. Par exemple, le md5

## Commandes:

```
mkdir referentielmodele
cp default/* referentielmodele/*
top-kex HOST --algodir referentielmodele
```
