# FIREWALL POLICY : LogiCorp Gateway

## 0. Référentiel réseau

### Interfaces de la passerelle

| Interface | Rôle | Remarque |
|---|---|---|
| `eth1` | WAN (sortie Internet) | IP fournie par le FAI/modem (lab : `10.42.166.24/16`, passerelle `10.42.0.1` — cf. audit §2) |
| `eth2` | Trunk 802.1Q vers le switch | Ne porte aucune IP, uniquement les sous-interfaces VLAN |
| `eth2.10` / `.20` / `.30` / `.50` / `.60` | Une sous-interface par zone | Chaque zone ne communique avec les autres **qu'à travers la passerelle** |
| `wg0` | Tunnel VPN WireGuard | `10.8.0.1/24` |
| `eth0` | Lien link-local de l'hébergeur | Hors périmètre LogiCorp (cf. §6) |

### Plan d'adressage

Convention : le 3ᵉ octet du subnet = l'ID du VLAN. `.1` = passerelle, `.2–.49` = statiques, `.100–.199` = DHCP.
Espace interne global : `10.50.0.0/16` (utilisé pour la documentation uniquement, **jamais** comme cible d'une règle ACCEPT).

| Zone | VLAN | Subnet | Passerelle | DHCP | Statiques | Interface |
|---|---|---|---|---|---|---|
| Office PC | 10 | `10.50.10.0/24` | `10.50.10.1` | `.100–.199` | — | `eth2.10` |
| Finance PC | 20 | `10.50.20.0/24` | `10.50.20.1` | `.100–.199` | — | `eth2.20` |
| Guest Wi-Fi | 30 | `10.50.30.0/24` | `10.50.30.1` | `.100–.199` | — | `eth2.30` |
| Database | 50 | `10.50.50.0/24` | `10.50.50.1` | aucun | DB : `10.50.50.50` | `eth2.50` |
| DMZ | 60 | `10.50.60.0/24` | `10.50.60.1` | aucun | FTP : `10.50.60.40` | `eth2.60` |
| VPN | — | `10.8.0.0/24` | `10.8.0.1` | — | par pair (cf. VPN_DESIGN.md) | `wg0` |

Pas de DHCP dans les zones Database et DMZ : elles ne contiennent que des serveurs à IP fixe, et une machine pirate branchée sur ces VLAN n'obtient pas d'adresse automatiquement.

---

## 1. Default Policies

| Chaîne | Trafic concerné | Politique cible | Justification |
|---|---|---|---|
| INPUT | Trafic destiné à la passerelle elle-même | **DROP** | Zero Trust : seuls le VPN, le SSH via VPN et les services d'infrastructure (DHCP) sont ouverts |
| FORWARD | Trafic qui traverse la passerelle (zone → zone) | **DROP** | Aucune zone ne parle à une autre sans règle explicite |
| OUTPUT | Trafic généré par la passerelle | **DROP** (après une phase transitoire en ACCEPT) | La passerelle a hébergé une backdoor (cron qui « appelle la maison ») : sa propre sortie doit aussi être contrôlée |

OUTPUT reste en ACCEPT pendant le déploiement (étapes 1 à 7 de l'IMPLEMENTATION_PLAN). Il ne passe en DROP qu'en dernier, une fois les flux sortants légitimes de la passerelle identifiés dans les logs.

---

## 2. Règles

Notation : `iif` = interface d'entrée, `oif` = interface de sortie.
« Vers Internet » s'écrit toujours `oif eth1`, jamais `destination any` : sinon une règle « Guest → any 443 » autoriserait aussi Guest → Database en 443.

### 2.1 INPUT (vers la passerelle)

| # | Source | Destination | Proto/Port | Action | Justification |
|---|---|---|---|---|---|
| I1 | any | passerelle | état établi/lié | ACCEPT | Réponses aux connexions déjà autorisées. En premier : c'est le trafic le plus volumineux, et cela évite de casser les sessions en cours |
| I2 | any | passerelle | état invalide | DROP | Paquets hors de toute connexion connue (scans, paquets forgés) |
| I3 | `lo` | passerelle | any | ACCEPT | Communication interne de la machine (services locaux) |
| I4 | `iif eth1` (WAN) | passerelle | UDP 51820 | ACCEPT | Seul point d'entrée depuis Internet : WireGuard. Silencieux pour qui n'a pas de clé valide |
| I5 | `iif wg0`, admins VPN `10.8.0.10–10.8.0.19` | passerelle | TCP 22 | ACCEPT | Administration SSH **uniquement** via le VPN et **uniquement** pour les pairs admin (corrige ACC-02) |
| I6 | `iif eth2.10, eth2.20, eth2.30` | passerelle | UDP 67 | ACCEPT | Serveur DHCP des zones utilisateurs. Pas dans les zones DB/DMZ (pas de DHCP) |
| I7 | `iif eth2.*, wg0` | passerelle | ICMP echo-request, limité à 5/s | ACCEPT | Diagnostic interne (ping de la passerelle). Limité contre le flood. Non ouvert côté WAN |
| I8 | any | passerelle | any | LOG `"IN-DROP: "` (limité) | Trace des tentatives refusées avant la politique DROP (MON-01) |
| — | | | | **policy DROP** | |

### 2.2 FORWARD (entre zones)

| # | Source | Destination | Proto/Port | Action | Justification |
|---|---|---|---|---|---|
| F1 | any | any | état établi/lié | ACCEPT | Réponses aux connexions autorisées. Permet aussi les données FTP passives déjà associées |
| F2 | any | any | état invalide | DROP | Idem I2 |
| F3 | `iif eth1` (WAN) | FTP `10.50.60.40` | TCP 21 | LOG + DROP | Redondant avec la policy, mais explicite pour la traçabilité : le FTP en clair n'est jamais exposé à Internet (corrige ACC-05). Le préfixe de log dédié permet de repérer les tentatives |
| F4 | `iif eth2.60` (DMZ) | any | any | LOG + DROP | Si le FTP est compromis, il ne peut **initier** aucune connexion : ni vers Office/Finance/Database (mouvement latéral, NET-01), ni vers Internet (exfiltration). Ses réponses légitimes passent par F1 |
| F5 | `iif eth2.30` (Guest) | `oif` ≠ `eth1` | any | LOG + DROP | Le Guest n'atteint aucune zone interne (corrige NET-02). Placée **avant** F8 pour que l'isolation ne dépende pas de l'ordre des règles d'accès |
| F6 | `iif eth2.10` (Office) | `oif eth1` (Internet) | TCP 443, UDP+TCP 53 | ACCEPT | Navigation HTTPS + DNS. UDP 53 = requêtes DNS normales, TCP 53 = réponses volumineuses |
| F7 | `iif eth2.20` (Finance) | `oif eth1` (Internet) | TCP 443, UDP+TCP 53 | ACCEPT | Idem F6. Règle séparée : compteurs et logs par zone, et droits modifiables indépendamment |
| F8 | `iif eth2.30` (Guest) | `oif eth1` (Internet) | TCP 443, UDP+TCP 53 | ACCEPT | Idem F6. Le Guest n'a **que** cet accès |
| F9 | `iif wg0`, comptables VPN `10.8.0.100–10.8.0.149` | FTP `10.50.60.40` | TCP 21 | ACCEPT | Canal de contrôle FTP, accessible uniquement aux comptables via le tunnel chiffré (corrige ENC-01 sur Internet) |
| F10 | `iif wg0`, comptables VPN `10.8.0.100–10.8.0.149` | FTP `10.50.60.40` | TCP 30000–30100 | ACCEPT | Plage passive FTP (`pasv_min_port` / `pasv_max_port` de vsftpd), où transitent les fichiers |
| F11 | `iif eth2.20` (Finance) | FTP `10.50.60.40` | TCP 21, TCP 30000–30100 | ACCEPT | La Finance récupère les factures déposées par les comptables distants |
| F12 | `iif eth2.10, eth2.20` | DB `10.50.50.50` | TCP `<port SGBD>` | ACCEPT | Seuls les postes métier atteignent la base, et uniquement sur son port de service (corrige NET-03). **Port à confirmer dans `db.conf`** (ex. 5432 PostgreSQL / 3306 MySQL) |
| F13 | `iif wg0`, admins VPN `10.8.0.10–10.8.0.19` | `10.50.50.50`, `10.50.60.40` | TCP 22 | ACCEPT | Administration des serveurs DB et FTP, depuis le VPN admin uniquement |
| F14 | any | any | any | LOG `"FWD-DROP: "` (limité) | Trace de tout flux non prévu : sert aussi à découvrir un flux légitime oublié pendant le déploiement |
| — | | | | **policy DROP** | |

Aucune règle « VPN → LAN selon besoins » : chaque population VPN n'atteint que ce dont elle a besoin (F9, F10, F13).
Le port 80 n'est pas ouvert aux postes (HTTPS uniquement). Conséquence assumée : les rares sites encore en HTTP ne fonctionnent plus. Si un besoin métier apparaît, on ajoute TCP 80 à F6/F7 uniquement, pas au Guest.

### 2.3 OUTPUT (émis par la passerelle) — cible finale

| # | Source | Destination | Proto/Port | Action | Justification |
|---|---|---|---|---|---|
| O1 | passerelle | any | état établi/lié | ACCEPT | Réponses (SSH, WireGuard, ping) |
| O2 | passerelle | `lo` | any | ACCEPT | Communication interne |
| O3 | passerelle | `oif eth1` | UDP+TCP 53, UDP 123 | ACCEPT | Résolution DNS et synchronisation horaire (NTP, indispensable à la corrélation des logs) |
| O4 | passerelle | `oif eth1` | TCP 80, 443 | ACCEPT | Mises à jour système (`apt` utilise des miroirs en HTTP) |
| O5 | passerelle (UDP 67) | `oif eth2.10, eth2.20, eth2.30` | UDP 68 | ACCEPT | Réponses du serveur DHCP |
| O6 | passerelle | collecteur de logs (à définir) | TCP 6514 (syslog TLS) | ACCEPT | Envoi des logs hors de la machine (MON-03) |
| O7 | passerelle | any | any | LOG `"OUT-DROP: "` | Toute sortie inattendue (balise de backdoor, outil d'attaquant) devient visible |
| — | | | | **policy DROP** | |

Limite connue : O4 laisserait passer la balise de la backdoor si elle visait une IP publique en HTTP. Le filtrage OUTPUT ne remplace donc pas la suppression du cron (IMPLEMENTATION_PLAN, étape 1). Il la complète par la journalisation.

### 2.4 NAT

| Table | Règle | Justification |
|---|---|---|
| nat / postrouting | `oif eth1` → masquerade | Les zones internes utilisent des IP privées (RFC 1918), non routables sur Internet. La passerelle remplace l'IP source par la sienne en sortie |

Il n'y a **aucune redirection de port** (DNAT) depuis le WAN : aucun service interne n'est publié sur Internet.

---

## 3. Justification de l'ordre des règles

1. **État établi/lié en premier (I1, F1, O1)** : la grande majorité des paquets appartient à une connexion déjà acceptée. Les traiter d'abord est plus performant et garantit qu'aucune règle ajoutée plus bas ne coupe une session en cours.
2. **États invalides ensuite (I2, F2)** : on écarte les paquets incohérents avant toute évaluation.
3. **Règles anti-lockout tôt (I4, I5)** : l'accès VPN et SSH admin est évalué avant toute règle de blocage. Une erreur plus bas ne peut pas couper l'administrateur.
4. **DROP explicites avant les ACCEPT (F3–F5)** : les isolations critiques (DMZ, Guest, FTP vers WAN) ne dépendent pas de l'absence d'une règle. Si quelqu'un ajoute plus tard une règle trop large, l'isolation tient toujours.
5. **ACCEPT du plus général au plus spécifique, regroupés par zone source (F6–F13)** : lecture et audit facilités.
6. **LOG juste avant la policy (I8, F14, O7)** : seul le trafic qui n'a correspondu à aucune règle est journalisé, ce qui évite de noyer les logs sous le trafic légitime. Limitation de débit pour qu'un flood ne remplisse pas le disque.

---

## 4. Implémentation de référence (nftables)

```nft
#!/usr/sbin/nft -f
flush ruleset

define ADMINS     = 10.8.0.10-10.8.0.19
define COMPTA     = 10.8.0.100-10.8.0.149
define FTP        = 10.50.60.40
define DB         = 10.50.50.50
define DB_PORT    = 5432            # à confirmer dans /etc/logicorp/db.conf
define FTP_PASV   = 30000-30100

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept                                    # I1
    ct state invalid drop                                                  # I2
    iif lo accept                                                          # I3
    iifname "eth1" udp dport 51820 accept                                  # I4
    iifname "wg0" ip saddr $ADMINS tcp dport 22 accept                     # I5
    iifname { "eth2.10", "eth2.20", "eth2.30" } udp dport 67 accept        # I6
    iifname { "eth2.*", "wg0" } icmp type echo-request limit rate 5/second accept   # I7
    limit rate 10/minute log prefix "IN-DROP: "                           # I8
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept                                    # F1
    ct state invalid drop                                                  # F2
    iifname "eth1" ip daddr $FTP tcp dport 21 log prefix "WAN-FTP: " drop  # F3
    iifname "eth2.60" log prefix "DMZ-OUT: " drop                          # F4
    iifname "eth2.30" oifname != "eth1" log prefix "GUEST-LAT: " drop      # F5
    iifname { "eth2.10", "eth2.20", "eth2.30" } oifname "eth1" tcp dport { 53, 443 } accept   # F6-F8
    iifname { "eth2.10", "eth2.20", "eth2.30" } oifname "eth1" udp dport 53 accept           # F6-F8
    iifname "wg0" ip saddr $COMPTA ip daddr $FTP tcp dport { 21, $FTP_PASV } accept           # F9-F10
    iifname "eth2.20" ip daddr $FTP tcp dport { 21, $FTP_PASV } accept                        # F11
    iifname { "eth2.10", "eth2.20" } ip daddr $DB tcp dport $DB_PORT accept                   # F12
    iifname "wg0" ip saddr $ADMINS ip daddr { $DB, $FTP } tcp dport 22 accept                 # F13
    limit rate 10/minute log prefix "FWD-DROP: "                          # F14
  }

  chain output {
    type filter hook output priority 0; policy accept;   # passe à "drop" à l'étape 8
    ct state established,related accept                                    # O1
    oif lo accept                                                          # O2
    oifname "eth1" udp dport { 53, 123 } accept                            # O3
    oifname "eth1" tcp dport { 53, 80, 443 } accept                        # O3-O4
    oifname { "eth2.10", "eth2.20", "eth2.30" } udp sport 67 udp dport 68 accept   # O5
    # O6 : ajouter le collecteur syslog une fois son adresse définie
    limit rate 10/minute log prefix "OUT-DROP: "                          # O7
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "eth1" masquerade
  }
}
```

F6 à F8 sont regroupées ici pour la lisibilité. En production, les séparer par zone permet d'avoir des compteurs distincts (`nft list ruleset` affiche les compteurs par règle si `counter` est ajouté).

---

## 5. Limites liées à l'environnement de lab

- Le conteneur n'a pas `CAP_NET_ADMIN` (audit §4) : ce ruleset ne peut pas être chargé sur la cible de lab. Il décrit l'état cible de la passerelle LogiCorp.
- `eth0` (link-local) et les ports 3000/3001 (openvscode-server, ttyd) appartiennent à l'infrastructure de l'école. Sur un hôte de lab, appliquer la policy INPUT DROP sans exception pour `eth0` couperait l'accès à la console. Ils sont hors périmètre du scénario LogiCorp.
