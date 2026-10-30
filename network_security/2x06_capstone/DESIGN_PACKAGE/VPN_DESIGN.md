# VPN DESIGN : LogiCorp Gateway

## 1. Objectifs

| Besoin | Gap couvert |
|---|---|
| Les comptables distants déposent leurs factures en FTP **sans changer leur logiciel** | ACC-05, ENC-01 (contrainte métier) |
| Les administrateurs gèrent la passerelle et les serveurs sans exposer SSH à Internet | ACC-02, ACC-03 |
| Un seul point d'entrée chiffré et authentifié depuis Internet | ENC-02 |

## 2. Choix technologique : WireGuard

| Critère | WireGuard | OpenVPN |
|---|---|---|
| Surface d'attaque | ~4 000 lignes de code, intégré au noyau Linux | Très volumineux, dépend d'OpenSSL |
| Exposition | Silencieux : ne répond à aucun paquet sans clé valide, invisible aux scans | Répond aux handshakes TLS |
| Cryptographie | Moderne et fixe (Curve25519, ChaCha20-Poly1305), pas de négociation à mal configurer | Configurable, donc risque de suites faibles |
| Configuration | Un fichier par pair, quelques lignes | PKI complète (CA, certificats, CRL) |
| Limites | Pas de MFA natif, pas d'annuaire utilisateur | MFA et LDAP possibles |

**Décision : WireGuard.** Pour une PME sans administrateur sécurité dédié depuis 10 ans, la simplicité réduit le risque d'erreur de configuration. L'absence de MFA est traitée en §7.

## 3. Topologie

Topologie **remote access en étoile (hub-and-spoke)** : chaque client se connecte à la passerelle, et les clients ne communiquent pas entre eux.

```
   Comptable (domicile)        Admin (domicile / astreinte)
   192.168.1.x (box)           réseau quelconque
          │                            │
          │  UDP 51820 chiffré         │  UDP 51820 chiffré
          └──────────┐      ┌──────────┘
                     ▼      ▼
              eth1 (WAN) ── Passerelle LogiCorp
                     wg0 = 10.8.0.1/24
                     │
        ┌────────────┼──────────────────────┐
        ▼            ▼                      ▼
   FTP 10.50.60.40   Passerelle :22    DB 10.50.50.50:22
   (DMZ, VLAN 60)    (admins)          FTP 10.50.60.40:22 (admins)
      ▲
      └── comptables uniquement
```

Il n'y a pas de VPN site-to-site : LogiCorp n'a qu'un site.

## 4. Adressage

Subnet VPN : **`10.8.0.0/24`**, interface `wg0`.

Choix du subnet :
- hors de l'espace interne `10.50.0.0/16` ;
- hors du réseau du lab `10.42.0.0/16` ;
- hors des plages des box domestiques (`192.168.0.x`, `192.168.1.x`), sans quoi le poste d'un comptable ne saurait pas si `192.168.1.10` désigne son imprimante ou une machine de LogiCorp.

| Plage | Usage |
|---|---|
| `10.8.0.1` | Passerelle (`wg0`) |
| `10.8.0.10 – 10.8.0.19` | Administrateurs (10 pairs max) |
| `10.8.0.100 – 10.8.0.149` | Comptables (50 pairs max) |
| reste | Réservé |

Chaque pair a une **IP fixe**, attachée à sa clé publique (`AllowedIPs = 10.8.0.x/32` côté serveur). WireGuard rejette tout paquet du tunnel dont l'IP source ne correspond pas à la clé qui l'a chiffré. **Un comptable ne peut donc pas usurper une IP admin** : c'est ce qui rend fiables les règles firewall basées sur les plages (I5, F9, F10, F13).

## 5. Contrôle d'accès (qui accède à quoi)

| Groupe | IP VPN | Accès autorisés | Règles | Tout le reste |
|---|---|---|---|---|
| Comptables | `10.8.0.100–149` | FTP `10.50.60.40` : TCP 21 + 30000–30100 | F9, F10 | DROP |
| Administrateurs | `10.8.0.10–19` | Passerelle TCP 22 ; DB et FTP TCP 22 | I5, F13 | DROP |

Aucun utilisateur VPN n'accède aux zones Office, Finance ou Guest, ni à Internet via le tunnel.

## 6. Split tunnel

**Décision : split tunnel.** Seul le trafic à destination de LogiCorp passe dans le tunnel :

| Pair | `AllowedIPs` côté client |
|---|---|
| Comptable | `10.50.60.40/32` |
| Administrateur | `10.8.0.1/32, 10.50.50.50/32, 10.50.60.40/32` |

| | Split tunnel (retenu) | Full tunnel |
|---|---|---|
| Navigation perso de l'utilisateur | Passe par sa propre box | Passe par LogiCorp (bande passante, responsabilité) |
| Ce que le poste peut joindre via le tunnel | Uniquement les IP utiles | Tout, filtré par le firewall |
| Risque | Le poste est connecté à Internet et au tunnel en même temps | Moins de risque de pont, mais charge et complexité |

Le firewall applique de toute façon le moindre privilège (§5). `AllowedIPs` est une **seconde couche** : même si une règle firewall était trop large, le client n'enverrait rien d'autre dans le tunnel.

## 7. Authentification et gestion des clés

- **Une paire de clés par personne et par appareil.** Jamais de clé partagée : chaque connexion est attribuable (corrige le manque de traçabilité d'ACC-03).
- **Clé pré-partagée (PSK)** par pair en plus : défense contre un futur cassage de Curve25519 (post-quantique).
- La clé privée est générée **sur le poste du client** et ne quitte jamais le poste. Seule la clé publique est transmise à l'admin.
- **Révocation** : suppression du bloc `[Peer]` sur la passerelle, puis `wg syncconf`. Effet immédiat. À faire le jour du départ d'un employé ou de la perte d'un appareil.
- **Revue trimestrielle** des pairs actifs (`wg show` : date du dernier handshake). Un pair inactif depuis plus de 90 jours est supprimé.
- **Pas de MFA natif** (limite de WireGuard). Mesures compensatoires :
  - pairs admin : la clé VPN **et** une clé SSH sont nécessaires (deux secrets distincts) ;
  - pairs comptables : la clé VPN **et** l'identifiant FTP sont nécessaires ; accès limité à un seul serveur.
  - Évolution possible : un portail MFA en amont (ex. firezone, netbird). Hors périmètre de la semaine.

Configuration serveur (extrait) :

```ini
[Interface]
Address    = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <clé privée serveur>

# Admin - J. Dupont - laptop
[Peer]
PublicKey    = <clé publique>
PresharedKey = <PSK>
AllowedIPs   = 10.8.0.10/32

# Compta - M. Martin - PC domicile
[Peer]
PublicKey    = <clé publique>
PresharedKey = <PSK>
AllowedIPs   = 10.8.0.100/32
```

Le serveur n'a pas de `PostUp` avec iptables : le filtrage est entièrement géré par le ruleset nftables (FIREWALL_POLICY.md), pour avoir une seule source de vérité.

---

## 8. Legacy App : FTP

### 8.1 Contrainte

Les comptables distants utilisent un logiciel qui **ne parle que FTP** et qui **ne peut pas être modifié**. FTP transmet identifiants et fichiers **en clair**. Exposé sur Internet (situation actuelle, D5), n'importe quel intermédiaire peut lire les factures et rejouer les mots de passe.

### 8.2 Approche : tunneling

Le logiciel est conservé tel quel, mais il ne voit plus Internet : il parle à `10.50.60.40`, une adresse qui n'est joignable **que dans le tunnel WireGuard**.

```
Logiciel compta ──FTP en clair──► wg0 (client) ══ chiffré ChaCha20 ══► wg0 (passerelle) ──FTP en clair──► FTP 10.50.60.40
     (poste)                                         Internet                                (DMZ)
```

- Sur Internet, on ne voit que de l'UDP 51820 chiffré : ENC-01 est corrigé sur le segment le plus exposé.
- Le serveur FTP n'est plus joignable depuis le WAN (F3, et aucun DNAT).
- Le seul changement côté utilisateur : activer le VPN, puis saisir `10.50.60.40` comme adresse du serveur.

**Pourquoi pas FTPS ou SFTP ?** SFTP est un autre protocole que le logiciel ne supporte pas. FTPS dépend du support du client, inconnu à ce jour. Le tunnel fonctionne quel que soit le client. Si le logiciel supporte FTPS, on l'active **en plus** (défense en profondeur).

### 8.3 Pourquoi en DMZ

FTP est un protocole ancien, en clair, et le serveur **reçoit des fichiers venus de l'extérieur**, potentiellement piégés. C'est le service le plus susceptible d'être compromis. On l'isole donc en DMZ : s'il est compromis, la règle **F4** l'empêche d'initier la moindre connexion vers Office, Finance, la Database ou Internet. L'attaquant ne peut ni rebondir (mouvement latéral) ni exfiltrer.

### 8.4 Durcissement du serveur vsftpd

| Paramètre | Valeur | Raison |
|---|---|---|
| `listen_address` | `10.50.60.40` | N'écoute que sur son interface DMZ (aujourd'hui : `0.0.0.0`, audit §3) |
| `anonymous_enable` | `NO` | Aucun accès sans compte |
| `chroot_local_user` | `YES` | Chaque comptable est enfermé dans son répertoire |
| `pasv_enable` / `pasv_min_port` / `pasv_max_port` | `YES` / `30000` / `30100` | Plage passive fixe, correspond à F10/F11 |
| `port_enable` | `NO` | Mode actif désactivé : le serveur n'initie pas de connexion (cohérent avec F4) |
| `userlist_enable` + `userlist_deny=NO` | liste blanche | Seuls les comptes comptables listés peuvent se connecter |
| `xferlog_enable` / `log_ftp_protocol` | `YES` | Traçabilité des dépôts et retraits |

Les fichiers déposés sont analysés par antivirus (ClamAV) avant leur récupération par la Finance.

### 8.5 Acceptation du risque résiduel

| Élément | Contenu |
|---|---|
| **Risque résiduel** | Le FTP reste en clair **entre la passerelle et le serveur** (VLAN 60) et entre le serveur et la Finance (F11). Un attaquant déjà présent sur la passerelle ou dans la DMZ pourrait lire identifiants et factures. Un poste comptable compromis transmet ses fichiers piégés dans le tunnel |
| **Probabilité** | Faible : il faut d'abord compromettre la passerelle ou la DMZ, toutes deux durcies et journalisées |
| **Impact** | Élevé : données financières, identifiants FTP |
| **Mesures compensatoires** | Tunnel chiffré sur Internet ; FTP isolé en DMZ sans connexion sortante (F4) ; accès VPN limité au groupe compta (F9, F10) ; chroot + liste blanche ; logs FTP et firewall ; antivirus sur les dépôts ; identifiants FTP distincts de tout autre mot de passe |
| **Propriétaire du risque** | Direction de LogiCorp (CEO), sur recommandation de l'équipe sécurité |
| **Date de revue** | 6 mois après le déploiement, ou immédiatement en cas d'incident |
| **Plan de sortie** | Demander à l'éditeur du logiciel le support de FTPS/SFTP ; à défaut, évaluer un remplacement. Dès qu'un protocole chiffré est disponible : l'activer, puis fermer TCP 21 en clair |
