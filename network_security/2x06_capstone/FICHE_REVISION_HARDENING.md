# Fiche de révision : Enforcement (clean.sh + vpn_setup.sh)

## 0. Le contexte en une phrase

Tu es **le consultant**. Les scripts sont un **livrable** que l'administrateur de LogiCorp lance avec ses droits root (`sudo`). Toi, en `student`, tu les testes avec `--dry-run`. Le mot de passe root trouvé pendant l'audit est un **constat à écrire dans le rapport**, pas un accès à utiliser.

Les quatre contraintes de la consigne guident **toutes** les décisions :

| Contrainte | Ce que ça change dans les scripts |
|---|---|
| FTP doit marcher pour Finance | le FTP passe par le serveur de la DMZ (`10.50.60.40`), joignable **uniquement via le VPN**. Le vsftpd de la passerelle est sécurisé, pas supprimé. |
| L'accès distant doit marcher pour IT | SSH « key-only » **seulement si une clé existe**, sinon ils seraient enfermés dehors |
| La base de données reste accessible | aucun service de base de données, web, DNS ou DHCP n'est touché, et le routage (`ip_forward = 1`) est gardé |
| Si tu t'enfermes dehors, tu échoues | sauvegardes, `sshd -t` avant tout rechargement, retour arrière automatique |

**Ordre d'exécution :** `clean.sh` → `vpn_setup.sh` → `panic_button.sh arm` → `firewall.sh apply` (fait par ta collègue) → tests → `panic_button.sh disarm`.

Les valeurs communes sont alignées sur `firewall.sh` : VPN IT `10.8.0.10-19`, VPN Finance `10.8.0.100-149`, WireGuard `51820/udp` sur `eth1`, serveur FTP `10.50.60.40`, ports passifs `30000-30100`.

---

## 1. Le squelette commun aux scripts

| Élément | Rôle |
|---|---|
| `set -u` | arrête le script si une variable n'existe pas (une faute de frappe comme `$SSHD_CONG` devient visible au lieu d'être silencieuse) |
| `--dry-run` | mode simulation : affiche ce qui **serait** fait, sans rien modifier, et marche sans droits |
| `run commande...` | exécute la commande en mode réel, l'affiche seulement en dry-run. **Toute modification du système passe par `run`.** |
| `ok "message"` | écrit un succès dans le log **seulement en mode réel**. Règle : *un log ne doit jamais mentir.* |
| `log "message"` | écrit à l'écran et dans le fichier `.log` (`tee -a`) |
| `write_file chemin droits` | écrit un fichier entier à partir d'un heredoc. En dry-run, affiche son contenu. |
| `backup_once fichier` | crée `fichier.bak` **une seule fois**. Un 2ᵉ lancement n'écrase pas l'original. |
| `set_option fichier clé séparateur valeur` | remplace la ligne active de l'option, ou l'insère **en haut** si elle n'existe pas |

Préfixes du log : `[i]` = information, `[+]` = changement appliqué, `[!]` = avertissement ou problème, `[DRY-RUN]` = simulation.

---

## 2. clean.sh, section par section

### [1] Services inutiles

**Méthode d'inventaire, trois angles :**
- `ss -tulpn` : ce qui **écoute maintenant** ;
- `systemctl list-unit-files --state=enabled` : ce qui **démarrera au boot** ;
- `dpkg -s paquet` : ce qui est **installé**.

Exemple : telnetd n'était visible que par `dpkg`, et inetd n'apparaissait que dans `systemctl`. C'était une menace dormante, qui revient au reboot.

| Action | Commande | Quand l'utiliser |
|---|---|---|
| Supprimer | `apt-get purge` | protocoles en clair et vieux protocoles (telnet, rsh, inetd) |
| Couper | `systemctl disable --now` + `mask` | services de l'OS inutiles (avahi, cups, rpcbind...) |
| Tuer ce qui reste | `pkill -x` | processus lancés hors de systemd (conteneur) |

- `mask` empêche **tout** redémarrage, même par une dépendance.
- Il faut couper le `.service` **et** le `.socket` : sinon, le socket relance le service à la première connexion.

**vsftpd (FTP Finance) est gardé, mais sécurisé :**
- `anonymous_enable=NO` : pas d'accès anonyme ;
- `chroot_local_user=YES` : chaque utilisateur est enfermé dans son dossier ;
- `userlist_*` : seuls les membres du groupe `finance` peuvent se connecter. **Si ce groupe n'existe pas, la liste n'est pas activée**, sinon personne ne pourrait plus se connecter.
- ports passifs fixes `30000-30100` (la même plage que `firewall.sh`) : sans ça, le pare-feu ne peut pas laisser passer le FTP passif ;
- s'il ne redémarre pas, la config d'origine (`.bak`) est restaurée.

### [2] SSH (no root, key-only)

Ce que tu as découvert pendant l'audit : `PermitRootLogin yes` + `PasswordAuthentication yes` + mot de passe root connu = **prise de contrôle totale à distance**.

| Option | Pourquoi |
|---|---|
| `PermitRootLogin no` | « no root » : on se connecte avec un compte nominatif puis sudo, ce qui laisse une trace. Toujours appliqué. |
| `PasswordAuthentication no` | « key-only » |
| `KbdInteractiveAuthentication no` | sinon, le mot de passe passe encore par PAM |
| `AuthenticationMethods publickey` | ceinture et bretelles |
| `MaxAuthTries 3`, `LoginGraceTime 30` | ralentissent le brute-force |
| `X11Forwarding no`, `ClientAlive*`, `Banner` | réduction de surface, fermeture des sessions abandonnées, bannière légale |

**Les trois réflexes anti-verrouillage :**
1. **Vérifier qu'une clé existe** (`/home/*/.ssh/authorized_keys`, non vide = test `-s`) avant de couper les mots de passe. Sans clé, on garde les mots de passe et on affiche un avertissement.
2. **`sshd -t`** teste la config. Si elle est invalide, on restaure la copie et on **ne recharge pas**.
3. **`reload`, pas `restart`** : les sessions ouvertes restent ouvertes. Garde **toujours** une session ouverte pendant que tu testes une nouvelle connexion.

**Pièges sshd :**
- sshd garde la **première** valeur lue, contrairement à la plupart des logiciels. D'où l'insertion en **haut** du fichier (`sed 1i`), et la désactivation des mêmes options dans `sshd_config.d/`.
- Ajouter une option **à la fin** du fichier peut la placer dans un bloc `Match`, où elle ne s'appliquerait qu'à certains utilisateurs. C'est une autre raison d'insérer en haut.
- Sans ligne `Include`, le dossier `sshd_config.d/` est ignoré.

### [3] Secure defaults

| Mesure | Fichier | Pourquoi |
|---|---|---|
| Paramètres noyau | `/etc/sysctl.d/99-logicorp-hardening.conf` | anti-usurpation d'IP (`rp_filter`), pas de redirections ICMP, protection contre le SYN flood (`syncookies`), ASLR. **`ip_forward = 1` est gardé** : c'est une passerelle. |
| Politique de mots de passe | `/etc/login.defs` | 90 jours max, `UMASK 027` (les nouveaux fichiers ne sont pas lisibles par les « autres ») |
| Pas de core dumps | `/etc/security/limits.d/` | un dump de mémoire peut contenir des mots de passe et des clés |
| Droits des fichiers sensibles | `chmod` | shadow 640, crontab 600, /root 700 |
| Verrouillage du mot de passe root | `passwd -l root` | le mot de passe a été trouvé. Fait **seulement si un membre du groupe sudo existe**, sinon plus personne ne pourrait administrer. |

Dans un conteneur, certains paramètres `sysctl` sont en lecture seule. Le script le signale sans planter.

---

## 3. vpn_setup.sh

**Le principe :** WireGuard crée un tunnel chiffré. FTP envoie tout en clair, donc Finance n'atteint le serveur FTP de la DMZ (`10.50.60.40`) **qu'à travers le tunnel**. Le chiffrement est apporté par le VPN, et le pare-feu bloque tout autre chemin : c'est le « FTP-over-VPN ».

| Étape | Ce qui se passe |
|---|---|
| [1] Installation | `wireguard-tools` |
| [2] Clés | une paire clé privée/publique par machine, générée **une seule fois** (relancer le script garde les clés) |
| [3] Serveur | `/etc/wireguard/wg0.conf`. La clé privée est chargée par `PostUp`, donc elle n'est **jamais écrite** dans la config ni dans le log. |
| [4] Clients | `/etc/wireguard/clients/<nom>.conf`, à transmettre de façon sécurisée |
| [5] Démarrage | `systemctl enable` + `restart wg-quick@wg0`, puis vérification que `wg0` existe. Si `wg0` ne monte pas : **ne pas appliquer firewall.sh**, car SSH n'est autorisé que par le VPN. |
| [6] FTP-over-VPN | vérifie que la passerelle route bien les paquets (`ip_forward = 1`) et rappelle le chemin : Finance VPN → `10.50.60.40:21` + passifs `30000-30100` |

**Séparation des rôles par adresse IP (les plages de firewall.sh) :**
- IT (`VPN_ADMINS`) : `10.8.0.10-19`. `AllowedIPs` = sous-réseau VPN (SSH vers la passerelle) + réseaux internes (`LAN_NETS`, vide tant que firewall.sh ne fait pas passer le trafic admin vers l'intérieur).
- Finance (`VPN_ACCOUNTANTS`) : `10.8.0.100-149`. `AllowedIPs` = `10.50.60.40/32`, donc **le serveur FTP seulement** (split tunnel).

Comme les deux rôles ont des plages différentes, le pare-feu peut les distinguer : un comptable qui tente SSH est bloqué et journalisé (`FW-SSH-ACCOUNTANTS`).

**Le retour des paquets :** le serveur FTP doit renvoyer ses réponses vers `10.8.0.0/24` **en passant par la passerelle** (c'est le cas si la passerelle est sa route par défaut). Sinon, les connexions restent bloquées.

**Les règles de firewall.sh qui correspondent :**
- `51820/udp` en entrée sur `eth1` (WAN) ;
- SSH vers la passerelle uniquement depuis `VPN_ADMINS` sur `wg0` ;
- forward `VPN_ACCOUNTANTS` → `10.50.60.40` en `21` + `30000-30100`.

**À ajuster si le design change** : variables en haut de `vpn_setup.sh` (elles doivent rester identiques à `firewall.sh`), et `FINANCE_GROUP` / `FTP_USERS` dans `clean.sh`.

---

## 3 bis. panic_button.sh (le filet de sécurité du pare-feu)

**Le principe de l'« homme mort » (dead man's switch) :** on arme un minuteur **avant** d'appliquer le pare-feu. Si les nouvelles règles t'enferment dehors, tu ne peux pas annuler le minuteur, et il restaure l'ancien état tout seul.

```
sudo ./panic_button.sh arm 5     # 1. sauvegarde les règles actuelles + minuteur de 5 min
sudo ./firewall.sh apply         # 2. nouvelles règles
# 3. tester SSH / VPN / FTP depuis une NOUVELLE session
sudo ./panic_button.sh disarm    # 4a. tout marche : on annule
                                 # 4b. enfermé dehors : au bout de 5 min, retour automatique
```

| Détail | Pourquoi |
|---|---|
| sauvegarde avec `nft list ruleset`, précédée de `flush ruleset` | le fichier se recharge d'un coup (atomique) avec `nft -f` |
| minuteur `systemd-run --on-active=5m` (sinon `nohup sleep &`) | il continue à tourner même si ta session SSH meurt |
| `arm` s'arrête si le minuteur ne démarre pas | un filet qui n'est pas tendu ne doit pas laisser croire qu'on est protégé |
| `fire` recopie aussi la sauvegarde dans `/etc/nftables.conf` | `firewall.sh` active nftables au boot : sans ça, un reboot réappliquerait les mauvaises règles |
| sans sauvegarde utilisable : `nft flush ruleset` | dernier recours : plus de filtrage du tout, mais l'accès revient |

---

## 4. Ce que tu as appris en bash (les pièges)

| Piège | La règle |
|---|---|
| `KEY_FOUND= 1` | **pas d'espace** autour du `=` dans une affectation. Sinon bash exécute `1` comme une commande. |
| `[ "$x" -eq 1]` | `[` est une commande : il faut un espace avant le `]` |
| `[ ... ]` vs `if grep -q` | `[ ]` compare des valeurs, `if commande` lit le code de retour de la commande |
| Tester ≠ affecter | `[ "$X" -eq 1 ]` pose une question, `X=1` donne une valeur |
| `elif` sans condition | pour un « sinon » simple, c'est `else` |
| Branche vide | un `if`/`else` ne peut pas contenir **seulement** un commentaire |
| Guillemets | toujours `"$var"`. **Exception :** un glob qu'on veut étendre (`for f in $KEYS`). |
| `'...'` vs `"..."` | les variables ne sont remplacées qu'entre guillemets **doubles**. Écris `\$` pour garder un `$` littéral (`"\$a"` pour sed). |
| Chemins relatifs | un script système utilise **toujours des chemins absolus**, sinon il dépend du dossier d'où on le lance |
| `-f` vs `-s` | `-f` = le fichier existe, `-s` = il existe **et n'est pas vide** |
| Redirection + fonction | `run echo x >> fichier` : le `>>` s'applique à **toute** la ligne, `run` compris. En dry-run, le log finirait dans le fichier ! L'action doit rester **dans les arguments** (`sed -i`, `tee`). |
| `sudo cmd > fichier` | la redirection est faite par **ton** shell, avec **tes** droits. Utilise `cmd \| sudo tee fichier`. |
| `bash -n script` | vérifie la syntaxe sans exécuter, mais ne détecte **pas** les fautes dans les noms de variables |
| Tester au bon endroit | ton Mac n'est pas la passerelle : pas de dpkg, pas de /home/student, un sshd_config différent |

### sed en résumé

```
sed  -i  's|MOTIF|LIGNE ENTIÈRE|'  FICHIER
     │    └── quoi ──────────────┘  └ où ┘
     └ -i = modifie le fichier (sans -i : affiche seulement)
```
- sed remplace **tout ce que le motif a trouvé**. Avec `^Option.*`, c'est la ligne entière, donc « LIGNE ENTIÈRE » doit être complète.
- `^` = début de ligne (ignore les `#` des commentaires), `\s*` = zéro ou plusieurs espaces, `.*` = n'importe quoi jusqu'à la fin.
- `*` s'applique **uniquement à l'élément juste avant lui**.
- `$a texte` = ajouter après la dernière ligne, `1i texte` = insérer avant la première.
- Séparateur `|` au lieu de `/` quand la valeur contient un chemin (`/etc/...`).
- Pour tester sans risque : `printf "ligne1\nligne2\n" | sed '...'`

### Les concepts de sécurité à savoir expliquer à l'oral

- **Surface d'attaque** : chaque service actif est du code exposé.
- **Moindre privilège** : chacun n'a que les droits dont il a besoin.
- **Défense en profondeur** : plusieurs couches de protection (purge + disable + mask, VPN + pare-feu).
- **Idempotence** : relancer le script donne le même résultat, sans erreur ni dégât.
- **Preuves** : `ports_before.txt` / `ports_after.txt` et les logs. Une action non prouvée est considérée comme non faite.
- **Retour arrière** : on prévoit toujours comment annuler avant de modifier.

---

## 5. Checklist le jour J (sur la passerelle)

```bash
chmod +x clean.sh vpn_setup.sh
bash -n clean.sh && bash -n vpn_setup.sh   # syntaxe
./clean.sh --dry-run                       # en student : lire TOUTE la sortie
./vpn_setup.sh --dry-run
```
Ensuite, l'admin, **avec une 2ᵉ session SSH ouverte** :
```bash
sudo ./clean.sh
ssh user@gateway                 # depuis une NOUVELLE session : ça marche toujours ?
sudo ./vpn_setup.sh
sudo wg show                     # le tunnel est actif ?
sudo ./panic_button.sh arm 5
sudo ./firewall.sh apply
# depuis une NOUVELLE session, PAR LE VPN : SSH (IT) et FTP vers 10.50.60.40 (Finance)
sudo ./panic_button.sh disarm    # seulement si tout marche
```

Points à vérifier dans le rapport : `inetd` masqué, telnet supprimé, `sshd -T | grep permitrootlogin` → `no`, FTP joignable seulement via le VPN.
