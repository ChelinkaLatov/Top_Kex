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