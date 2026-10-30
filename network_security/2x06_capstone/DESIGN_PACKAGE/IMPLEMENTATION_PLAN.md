# IMPLEMENTATION PLAN : LogiCorp Gateway

## 1. Principes

1. **Ne jamais se couper l'accès** : un accès console hors bande est vérifié avant toute modification ; un nouveau chemin d'administration est validé **avant** de fermer l'ancien.
2. **Chaque étape est réversible** : sauvegarde avant, test de validation après, procédure de rollback écrite.
3. **Go / No-Go** : on ne passe à l'étape suivante que si tous les tests de l'étape en cours sont verts.
4. **Observer avant de bloquer** : les règles sont d'abord chargées en mode journalisation, puis en mode blocage.
5. **La persistance arrive en dernier** : une règle n'est rendue permanente (survie au reboot) qu'une fois validée. Un reboot reste ainsi un moyen de rollback jusqu'à la fin.

Toutes les étapes ont lieu dans une **fenêtre de maintenance** annoncée aux utilisateurs (comptables prévenus du changement d'accès FTP).

## 2. Vue d'ensemble

| Étape | Action | Impact production | Rollback |
|---|---|---|---|
| 0 | Préparation, sauvegardes, accès console | Aucun | — |
| 1 | Confinement : backdoor, Telnet, permissions, identifiants | Aucun | Restauration ciblée |
| 2 | Durcissement SSH | Aucun si l'ordre est respecté | Restauration de `sshd_config` |
| 3 | Déploiement du VPN WireGuard | Aucun (ajout) | `wg-quick down wg0` |
| 4 | Firewall en mode observation | Aucun | `nft flush ruleset` |
| 5 | Firewall en mode blocage (INPUT/FORWARD DROP) | Fort si erreur | Automatique (dead man's switch) |
| 6 | Segmentation VLAN | Fort si erreur | Repasser les ports switch dans l'ancien VLAN |
| 7 | Migration du FTP en DMZ | Moyen (comptables) | Réactiver le vsftpd de la passerelle |
| 8 | OUTPUT DROP | Faible | Repasser la policy OUTPUT en ACCEPT |
| 9 | Persistance et supervision | Aucun | Restaurer `run.sh` |

L'ordre suit la logique « d'abord ce qui ne casse rien, ensuite ce qui peut casser ». Le confinement passe en premier : il est inutile de durcir une machine dont l'attaquant garde la clé.

---

## 3. Étapes détaillées

### Étape 0 : préparation

| | |
|---|---|
| **Actions** | 1. Vérifier l'accès **console hors bande** (console physique, IPMI ou console de l'hébergeur) : c'est le filet de sécurité de toutes les étapes suivantes.<br>2. Sauvegarder : `nft list ruleset > /root/backup/nft.rules`, `/etc/ssh/sshd_config`, `/etc/vsftpd.conf`, `/etc/cron.d/`, `/etc/run.sh`, `/etc/logicorp/`, la liste des paquets (`dpkg -l`).<br>3. Copier les sauvegardes **hors de la machine**.<br>4. Lire le port de la base dans `/etc/logicorp/db.conf` et reporter la valeur dans `$DB_PORT` (FIREWALL_POLICY §5).<br>5. Vérifier que le switch supporte le 802.1Q. |
| **Validation** | Connexion console réussie ; sauvegardes présentes sur une machine tierce ; port SGBD connu. |
| **Rollback** | Sans objet (aucun changement). |
| **No-Go si** | Pas d'accès console ou switch non manageable : **arrêt**, le plan doit être revu. |

### Étape 1 : confinement

| | |
|---|---|
| **Actions** | 1. **Backdoor (D7)** : copier `/etc/cron.d/logicorp` comme pièce à conviction (hors machine), puis le supprimer. Tuer les `curl` en attente.<br>2. **Telnet (D8)** : `apt purge telnetd`.<br>3. **Permissions (D9)** : `chown -R root:root /etc/logicorp`, `chmod 750` sur le dossier, `chmod 640` sur les fichiers.<br>4. **Identifiants** : changer les mots de passe root, student, FTP et base de données (`db.conf` était lisible par tous, donc considéré comme exposé).<br>5. Rechercher d'autres persistances : `authorized_keys` de tous les comptes, fichiers modifiés récemment (`find / -mtime -30 -type f`), services inconnus. |
| **Validation** | `ls /etc/cron.d/` ne contient plus `logicorp` ; `ps aux` ne montre plus de `curl` vers `192.168.1.200` ; `dpkg -l telnetd` = absent ; `ls -l /etc/logicorp` = pas de lecture pour « others » ; l'application métier se connecte à la base avec le nouveau mot de passe. |
| **Rollback** | Permissions : restaurer depuis la sauvegarde. Identifiants : si l'application ne se connecte plus, corriger `db.conf` (le mot de passe ne revient **jamais** à l'ancien). La backdoor et Telnet ne sont **jamais** restaurés. |
| **Alerte** | Si l'étape 5 révèle une compromission plus profonde (binaires modifiés, rootkit) : arrêt du plan et **reconstruction** de la passerelle (recommandation Phase 0 du Gap Analysis). |

### Étape 2 : durcissement SSH

| | |
|---|---|
| **Actions** | 1. Créer un compte admin nominatif avec `sudo`, et déposer sa clé publique SSH.<br>2. **Dans une nouvelle session** (garder la session actuelle ouverte), se connecter avec ce compte et la clé, puis tester `sudo -v`.<br>3. Seulement ensuite, dans `sshd_config` : `PermitRootLogin no`, `PasswordAuthentication no`.<br>4. `sshd -t` (vérification de syntaxe), puis `systemctl reload ssh`. |
| **Validation** | Nouvelle session avec la clé : OK. `ssh root@...` : refusé. Connexion par mot de passe : refusée. |
| **Rollback** | Depuis la session restée ouverte (ou la console) : restaurer `sshd_config` sauvegardé, puis `reload`. |

### Étape 3 : déploiement du VPN

| | |
|---|---|
| **Actions** | 1. Installer WireGuard, générer la paire de clés du serveur.<br>2. Créer `wg0` (`10.8.0.1/24`, port 51820) selon VPN_DESIGN.md.<br>3. Ajouter **un seul pair admin** (`10.8.0.10`) pour commencer.<br>4. Le firewall étant encore vide, rien ne bloque le port 51820. |
| **Validation** | Depuis le poste admin : `wg show` affiche un handshake récent ; `ping 10.8.0.1` répond ; `ssh admin@10.8.0.1` fonctionne. **C'est le nouveau chemin d'administration, il doit marcher avant l'étape 5.** |
| **Rollback** | `wg-quick down wg0`, désactiver le service. L'accès SSH direct est toujours ouvert à ce stade. |

### Étape 4 : firewall en mode observation

| | |
|---|---|
| **Actions** | 1. Charger le ruleset de FIREWALL_POLICY §5 avec les **policies INPUT et FORWARD en `accept`** temporairement. Les règles LOG (I8, F14) journalisent alors tout ce qui *serait* bloqué, sans rien bloquer.<br>2. Observer les logs (`journalctl -k \| grep -E "IN-DROP\|FWD-DROP"`) pendant une journée d'activité normale. |
| **Validation** | Chaque ligne de log est analysée : est-ce un flux légitime oublié (on ajoute une règle) ou un flux à bloquer (on ne fait rien) ? Aucun flux métier légitime dans les logs = Go. |
| **Rollback** | `nft flush ruleset` (retour à l'état d'origine). |

### Étape 5 : firewall en mode blocage

| | |
|---|---|
| **Actions** | 1. **Armer le dead man's switch** : `echo "nft -f /root/backup/nft.rules" \| at now + 10 minutes`. Si on perd l'accès, l'ancien ruleset est restauré automatiquement.<br>2. Passer les policies INPUT et FORWARD à `drop`, recharger le ruleset.<br>3. **Ouvrir une nouvelle session SSH via le VPN** (garder l'ancienne ouverte).<br>4. Si tout fonctionne : désarmer avec `atrm <job>`. |
| **Validation** | SSH via VPN : OK. SSH depuis le WAN : timeout. Depuis l'extérieur, `nmap` sur l'IP WAN ne montre plus 21 ni 22. Comptables : FTP via l'ancien chemin toujours fonctionnel jusqu'à l'étape 7 (règle temporaire si besoin). |
| **Rollback** | Automatique au bout de 10 minutes si l'accès est perdu. Manuel : `nft -f /root/backup/nft.rules` depuis la console. |

### Étape 6 : segmentation VLAN

Migration **zone par zone**, en commençant par la moins critique : Guest → Office → Finance → Database. Une seule zone à la fois.

| | |
|---|---|
| **Actions (par zone)** | 1. Créer la sous-interface (`eth2.30` etc.) avec l'IP passerelle `10.50.X.1/24`, puis le scope DHCP correspondant.<br>2. Sur le switch : créer le VLAN, le taguer sur le port trunk vers `eth2`.<br>3. Basculer **un seul poste test** dans le VLAN. Vérifier : IP obtenue, accès Internet, et accès refusés (ex. Guest → `10.50.50.50` en échec).<br>4. Basculer les autres postes.<br>5. **Database en dernier** : assigner `10.50.50.50` en statique, mettre à jour `db.conf` et la configuration des postes métier, tester l'application. |
| **Validation** | Pour chaque zone, tester les accès autorisés **et** refusés de FIREWALL_POLICY. Guest : Internet OK, tout le reste KO. Office/Finance : Internet OK, DB OK sur son port, DB KO sur les autres ports. |
| **Rollback** | Remettre les ports switch concernés dans l'ancien VLAN plat. Les postes récupèrent leur ancienne adresse. Les autres zones ne sont pas touchées. |

### Étape 7 : migration du FTP en DMZ

| | |
|---|---|
| **Actions** | 1. Installer le nouveau serveur `10.50.60.40` (VLAN 60) avec la configuration vsftpd durcie (VPN_DESIGN §8.4).<br>2. Copier les comptes et les fichiers existants.<br>3. Générer les configurations WireGuard des comptables (`10.8.0.100+`), puis les envoyer avec un guide pas à pas.<br>4. **Pilote** : un seul comptable teste VPN + dépôt + la Finance récupère le fichier.<br>5. Bascule de tous les comptables.<br>6. Arrêter et désactiver le vsftpd de la passerelle (ne pas le désinstaller avant 2 semaines). |
| **Validation** | Comptable via VPN : dépôt OK. Finance : récupération OK. Depuis Internet : port 21 de l'IP WAN fermé. Depuis la DMZ : `curl` vers Internet ou vers `10.50.20.x` en échec (F4). |
| **Rollback** | Réactiver le vsftpd de la passerelle et sa règle temporaire ; les comptables reprennent l'ancienne adresse. Les fichiers déposés entre-temps sont recopiés depuis `10.50.60.40`. |

### Étape 8 : OUTPUT en DROP

| | |
|---|---|
| **Actions** | 1. Analyser le trafic émis par la passerelle pendant les étapes précédentes, puis compléter O1 à O6 si besoin (adresse du collecteur syslog).<br>2. Armer le dead man's switch (comme à l'étape 5).<br>3. Passer la policy OUTPUT à `drop`. |
| **Validation** | `apt update` OK, résolution DNS OK, NTP synchronisé, DHCP distribué, VPN et SSH OK. Pas de `OUT-DROP` inattendu pendant 24 h. |
| **Rollback** | Repasser la policy OUTPUT à `accept`. |

### Étape 9 : persistance et supervision

| | |
|---|---|
| **Actions** | 1. **Supprimer `nft flush ruleset` de `/etc/run.sh`** : sans cela, tout le firewall disparaît au prochain démarrage (cause du finding D6).<br>2. Enregistrer le ruleset dans `/etc/nftables.conf` et le charger au démarrage.<br>3. Activer WireGuard au démarrage.<br>4. **Suricata (D10)** : supprimer l'écriture factice de `fast.log` dans `run.sh`, configurer Suricata sur `eth1` et le démarrer réellement.<br>5. Exporter les logs (firewall, SSH, FTP, Suricata) vers le collecteur distant (MON-03).<br>
| **Validation** | **Reboot de test** dans la fenêtre de maintenance : après redémarrage, `nft list ruleset` affiche les règles, `wg show` montre l'interface, Suricata tourne (`ps aux`), les logs arrivent sur le collecteur. |
| **Rollback** | Restaurer `run.sh` depuis la sauvegarde. Le firewall redevient non persistant, mais l'accès est préservé. |