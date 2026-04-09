import socket
import struct
import re
from pathlib import Path
import paramiko  # because all ssh key exchange are tough to write in pure python
import typer
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from json import load
from hashlib import sha256


PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "algorithms"
SIGNATURE_FILE = Path.cwd() / "signature_file"


letters = {
    "error": "!",
    "info": "i",
    "bad": "x",
    "result": "-",
    "good": "+",
    "warn": "w",
    "optimal": "o",
    "signature": "s",
}

colour_map = {
    "error": typer.colors.RED,
    "bad": typer.colors.BRIGHT_RED,
    "info": typer.colors.WHITE,
    "good": typer.colors.BRIGHT_GREEN,
    "optimal": typer.colors.GREEN,
    "result": typer.colors.BRIGHT_BLUE,
    "warn": typer.colors.YELLOW,
    "default": typer.colors.MAGENTA,
    "signature": typer.colors.WHITE,
}


def pprint(msg: str = "", msg_t: str = "") -> None:
    msg_letter = letters.get(msg_t, "?")
    colour = colour_map.get(msg_t, typer.colors.WHITE)
    typer.secho(f"[{msg_letter}] {msg}", fg=colour)


@dataclass
class Algorithm:
    name: str
    status: str
    label: Optional[str] = None
    
    @property
    def only_algo(self):
        return name.split("@")[0]


@dataclass
class IanaAlgorithms:
    algodir: str = "default"
    _cache: Dict[str, Dict] = field(default_factory=dict, init=False, repr=False)

    def _load_registry(self, name: str, filename: str) -> Dict:
        """Charge les valeurs depuis le json"""
        if name not in self._cache:
            path = DATA_DIR / self.algodir / filename

            if not path.is_file():
                pprint(
                    f"Could not find file {filename} in subdirectory {self.algodir}",
                    "warn",
                )
                return {}

            with path.open("r", encoding="utf-8") as f:
                data = load(f)

            self._cache[name] = {k: Algorithm(k, **v) for k, v in data.items()}
        return self._cache[name]

    @property
    def kex(self):
        return self._load_registry("kex", "kex_algorithms.json")

    @property
    def hostkeys(self):
        return self._load_registry("hostkeys", "hostkey_algorithms.json")

    @property
    def ciphers(self):
        return self._load_registry("ciphers", "cipher_algorithms.json")

    @property
    def macs(self):
        return self._load_registry("macs", "mac_algorithms.json")

    @property
    def compression(self):
        return self._load_registry("compression", "compression_algorithms.json")

    def __getattr__(self, name):
        return self._handle_missing_value(name)

    def _handle_missing_value(self, name):
        print(f"{name} asked")
        return None


def special_parse(values: List[str], algorithms: Dict[str, Algorithm]) -> None:
    print(values)
    for algorithm in values:
        only_algorithm = algorithm.split("@")[0]
        
        algo_obj = algorithms.get(
            only_algorithm, Algorithm(algorithm, "bad", "(Unknown Algorithm)")
        )
        pprint(f"\t{algorithm} {algo_obj.label}", algo_obj.status)


def parse_ssh_string(data, offset: int) -> Tuple[List[str], int]:
    if offset + 4 > len(data):
        return [], offset
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    string_data = data[offset : offset + length].decode("utf-8", errors="ignore")
    return string_data.split(","), offset + length


def build_ssh_packet(payload):
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8

    total_len = len(payload) + pad_len + 1
    packet = struct.pack(">IB", total_len, pad_len) + payload + (b"\x00" * pad_len)
    return packet


SSH_BANNER_RE = re.compile(
    r"^SSH-(?P<proto>[12]\.[0-9]+)-(?P<software>[^ ]+)(?:\s+(?P<comments>.+))?$"
)


def perform_banner_exchange(s, copy_banner: bool = False) -> str:
    raw_banner = b""
    length = 0
    try:
        while (length < 1024) and (raw_banner[-2:] != b"\x0d\x0a"):
            raw_banner += s.recv(1)
            length += 1
        # raw_banner = s.recv(1024) # Marche pas si le serveur n'attends pas le retour de banière.
    except OSError:
        pprint("Connection lost during banner exchange.", "error")
        return ""

    if not raw_banner:
        pprint("No banner received from server.", "error")
        return ""

    clean_banner = raw_banner.decode("utf-8", errors="ignore").strip()
    pprint(f"Raw Server Banner: {clean_banner}", "info")
    match = SSH_BANNER_RE.search(clean_banner)

    if match:
        proto = match.group("proto")
        software = match.group("software")
        with (DATA_DIR / "openssh_versions.json").open("r", encoding="utf-8") as fp:
            versions = load(fp)

        comments = match.group("comments")

        release_date = "no release date matches advertised version"
        if "OpenSSH" in software:
            release_date = versions.get(software.split('_', 1)[1].split('p')[0], 'Could not get release date')

        pprint("Banner Conformity: RFC 4253 Compliant", "good")
        pprint(f"Protocol Version: {proto}", "result")
        pprint(
            f"Software Version: {software} ({release_date})",
            "result",
        )

        if comments:
            pprint(f"Optional Comments: {comments}", "result")
        else:
            pprint("Optional Comments: None provided", "info")

        if proto == "1.99":
            pprint("Note: Protocol 1.99 indicates support for both v1 and v2.", "info")
        elif proto.startswith("1."):
            pprint("Warning: Server is using legacy SSHv1.", "warn")

    else:
        pprint("Banner Breakdown: Non-conformant format.", "bad")
        pprint(
            "The string does not follow the 'SSH-protoversion-softwareversion' structure.",
            "warn",
        )

    if copy_banner:
        s.sendall(raw_banner)
    else:
        s.sendall(b"SSH-2.0-Chelinka_SSH_Scanner_1.1\r\n")
    return clean_banner


def analyze_algorithms(s, algodir: str = "default") -> str:
    try:
        raw_packet_len = s.recv(4)
        if not raw_packet_len:
            pprint("Connection closed before KEXINIT.", "bad")
            return ""

        packet_len = struct.unpack(">I", raw_packet_len)[0]
        data = s.recv(packet_len)

        if len(data) > 1 and data[1] == 20:
            pprint("SSH_MSG_KEXINIT received. Parsing protocol lists...", "info")

            offset = 18

            kex, offset = parse_ssh_string(data, offset)
            hkey, offset = parse_ssh_string(data, offset)
            enc_ctos, offset = parse_ssh_string(data, offset)
            enc_stoc, offset = parse_ssh_string(data, offset)
            mac_ctos, offset = parse_ssh_string(data, offset)
            mac_stoc, offset = parse_ssh_string(data, offset)
            comp_ctos, offset = parse_ssh_string(data, offset)
            comp_stoc, offset = parse_ssh_string(data, offset)

            path = DATA_DIR / algodir

            if not path.is_dir():
                pprint(
                    f"Reference subdirectory {algodir} could not be found. Defaulting to no colors.",
                    "warn",
                )

            ianaDicos = IanaAlgorithms(algodir=algodir)

            pprint("Key Exchange:", "result")
            special_parse(kex, ianaDicos.kex)

            if "kex-strict-s-v00@openssh.com" in kex:
                pprint("Server seems resilient against Terrapin attack.", "good")
            else:
                pprint(
                    "Server does not seems resilient against Terrapin attack.", "bad"
                )

            pprint("Host Key Algs:", "result")
            special_parse(hkey, ianaDicos.hostkeys)

            if enc_ctos == enc_stoc:
                pprint("Ciphers (C->S->C):", "result")
                special_parse(enc_ctos, ianaDicos.ciphers)
            else:
                pprint("Cipher (C->S):", "result")
                special_parse(enc_ctos, ianaDicos.ciphers)
                pprint("Cipher (S->C):", "result")
                special_parse(enc_stoc, ianaDicos.ciphers)

            if mac_ctos == mac_stoc:
                pprint("MACs (C->S->C)", "result")
                special_parse(mac_ctos, ianaDicos.macs)
            else:
                pprint("MACs (C->S):", "result")
                special_parse(mac_ctos, ianaDicos.macs)
                pprint("MACs (S->C):", "result")
                special_parse(mac_stoc, ianaDicos.macs)

            if comp_ctos == comp_stoc:
                pprint("Compression (C->S->C):", "result")
                special_parse(comp_stoc, ianaDicos.compression)
            else:
                pprint("Compression (C->S):", "result")
                special_parse(comp_stoc, ianaDicos.compression)
                pprint("Compression (S->C):", "result")
                special_parse(comp_stoc, ianaDicos.compression)

            vuln_kex = []
            for kx in kex:
                if ianaDicos.kex[kx.split("@")[0]].status not in ["good", "optimal"]:
                    vuln_kex.append(kx)

            vuln_hkeys = []
            for hk in hkey:
                if ianaDicos.hostkeys[hk.split("@")[0]].status not in [
                    "good",
                    "optimal",
                ]:
                    vuln_hkeys.append(hk)

            vuln_ciphers = []
            for cipher in set(enc_stoc + enc_ctos):
                if ianaDicos.ciphers[cipher.split("@")[0]].status not in [
                    "good",
                    "optimal",
                ]:
                    vuln_ciphers.append(cipher)

            vuln_macs = []
            for mac in set(mac_stoc + mac_ctos):
                if ianaDicos.macs[mac.split("@")[0]].status not in ["good", "optimal"]:
                    vuln_macs.append(mac)

            if offset < len(data):
                first_kex_follows = data[offset]
                pprint(f"First KEX Packet Follows: {bool(first_kex_follows)}", "info")

            all_lists = ":".join(
                [
                    ",".join(inlist)
                    for inlist in [
                        kex,
                        hkey,
                        enc_ctos,
                        enc_stoc,
                        mac_ctos,
                        mac_stoc,
                        comp_ctos,
                        comp_stoc,
                    ]
                ]
            )
            return sha256(all_lists.encode()).hexdigest()

        else:
            pprint(
                f"Unexpected packet type: {data[1] if len(data) > 1 else 'Unknown'}",
                "warn",
            )

    except Exception as e:
        pprint(f"Error during algorithm negotiation: {e}", "error")

    return ""


def discover_auth_methods(host: str = "", port: int = 22) -> str:
    pprint("Probing for authentication methods via Transport...", "info")
    transport = None
    try:
        transport = paramiko.Transport((host, port))

        transport.start_client()

        try:
            transport.auth_none("")
            methods = ["none"]
        except paramiko.BadAuthenticationType as err:
            methods = err.allowed_types

        if methods == []:
            pprint(
                "Server returned an empty list of methods or session closed.", "warn"
            )
            return ""

        pprint(f"Authorized Methods: {', '.join(methods)}", "result")

        auth_methods_map = {
            "publickey": ["Public Key (RFC 4252)", "optimal"],
            "password": ["Password (RFC 4252)", "bad"],
            "hostbased": ["Host-Based (RFC 4252)", "bad"],
            "none": ["None / Recon (RFC 4252)", "error"],
            "keyboard-interactive": ["Challenge-Response / PAM (RFC 4256)", "good"],
            "gssapi-with-mic": ["GSSAPI with MIC / Kerberos (RFC 4462)", "good"],
            "gssapi-keyex": ["GSSAPI Key Exchange (RFC 4462)", "good"],
            "gssapi": ["GSSAPI Generic (RFC 4462)", "good"],
            "external-keyx": ["External Key Exchange (RFC 4462)", "good"],
        }

        for method in methods:
            label = auth_methods_map.get(method, ["Unknown method", "info"])
            pprint(f"{label[0]:22}", label[1])

        return ",".join(methods)

    except Exception as e:
        pprint(f"Auth Discovery Error: {type(e).__name__} - {e}", "error")
    finally:
        if transport:
            transport.close()
    return ""


def make_fingerprint(
    host: str = "",
    port: int = 22,
    banner: str = "",
    fingerprint: str = "",
    methods: str = "",
    write_to_file: bool = False,
) -> None:
    signature = f"{host}:{port};{banner};{fingerprint};{methods}\n"
    pprint(signature.strip(), "signature")
    if write_to_file:
        with SIGNATURE_FILE.open("a", encoding="utf-8") as fp:
            fp.write(signature)


def fingerprint_check(fingerprint: str) -> None:
    with (DATA_DIR / "known_hashes.json").open("r", encoding="utf-8") as fp:
        data = load(fp)
        if fingerprint in data.keys():
            matches = "\n\t".join(data[fingerprint])
            pprint(
                f"Fingerprint found in database. Corresponding to :\n\t{matches}",
                "result",
            )
        else:
            pprint("Fingerprint not found in database.", "result")


def analyze_ssh(
    host: str,
    port: int = 22,
    algodir: str = "default",
    add_signature: bool = False,
    copy_banner: bool = False,
    enable_auth: bool = False,
    timeout: int = 5,
) -> None:
    try:
        if not (1 <= port <= 65535):
            raise ValueError("Invalid port number")
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            pprint(f"Could not resolve hostname: {host}", "error")
            raise RuntimeError("Unresolvable hostname") from e

        if host == resolved_ip:
            conn_msg = f"Connecting to {resolved_ip}:{port}..."
        else:
            conn_msg = f"Connecting to ({host}) {resolved_ip}:{port}..."

        pprint(conn_msg, "info")
        with socket.create_connection((resolved_ip, port), timeout=timeout) as s:
            try:
                banner = perform_banner_exchange(s, copy_banner)
            except Exception as e:
                raise RuntimeError(f"Error in the banner exchange : {e}") from e

            try:
                fingerprint = analyze_algorithms(s, algodir.lower())
            except Exception as e:
                raise RuntimeError(f"Error in the algorithm analysis : {e}") from e

        if enable_auth:
            try:
                methods = discover_auth_methods(host, port)
            except Exception as e:
                raise RuntimeError(f"Error in the auth discovery : {e}") from e
            try:
                make_fingerprint(
                    host, port, banner, fingerprint, methods, add_signature
                )
            except Exception as e:
                raise RuntimeError(
                    f"Error in the complex fingerprinter maker : {e}"
                ) from e
        else:
            try:
                make_fingerprint(host, port, banner, fingerprint, "", add_signature)
            except Exception as e:
                raise RuntimeError(
                    f"Error in the simple fingerprinter maker : {e}"
                ) from e

        try:
            fingerprint_check(fingerprint)
        except Exception as e:
            raise RuntimeError(f"Error in the fingerprinter checker: {e}") from e

    except (socket.timeout, TimeoutError):
        pprint(f"Connection timed out to {host}:{port}", "error")
    except ConnectionRefusedError:
        pprint(f"Connection refused by {host}:{port}", "bad")
    except Exception as e:
        pprint(f"An unexpected error occurred: {e}", "error")


def main() -> None:
    typer.run(analyze_ssh)


if __name__ == "__main__":
    main()
