import socket
import struct
import re
import sys
import paramiko # because all ssh key exchange are tough to write in pure python 
import typer
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from json import load, dumps
from os.path import join,isfile,isdir, normpath
from hashlib import sha256

## affichage de Chelinka
letters = {"error": "!", "info": "i", "bad": "x", "result": "-", "good": "+", "warn": "w", "optimal":"o", "signature":"s"}

colour_map = {
    "error":     typer.colors.RED,            # Dark Red
    "bad":       typer.colors.BRIGHT_RED,     # Light Red
    "info":      typer.colors.WHITE,          # Gray (Light Gray for dark backgrounds)
    "good":      typer.colors.BRIGHT_GREEN,   # Green
    "optimal":   typer.colors.GREEN,          # Dark Green
    "result":    typer.colors.BRIGHT_BLUE,    # Light Blue
    "warn":      typer.colors.YELLOW,         # Yellowish-Orange
    "default":   typer.colors.MAGENTA,        # Pink (Light Magenta)
    "signature": typer.colors.WHITE,          # No color
}

def pprint(msg: str = None, msg_t: str = None) -> None:
    msg_letter = letters.get(msg_t, "?")
    colour = colour_map.get(msg_t, typer.colors.WHITE)
    typer.secho(f"[{msg_letter}] {msg}", fg=colour)

@dataclass
class Algorithm:
    name: str
    status:str
    label: Optional[str] = None

@dataclass
class IanaAlgorithms:
    algodir:str="default"
    _cache: Dict[str, Dict] = field(default_factory=dict, init=False, repr=False)

    def _load_registry(self, name:str, filename:str) -> Dict:
        """Charge les valeurs depuis le json"""
        if name not in self._cache:
            path = join("algorithms", self.algodir, filename)
    
            if not isfile(path):
                pprint(f"Could not find file {filename} in subdirectory {self.algodir}", "warn")
                return {}
            
            with open(path, 'r') as f:
                data = load(f)
                self._cache[name] = {
                    k: Algorithm(k, **v) for k, v in data.items()
                }
        return self._cache[name]
    
    @property
    def kex(self): return self._load_registry("kex", "kex_algorithms.json")

    @property
    def hostkeys(self): return self._load_registry("hostkeys", "hostkey_algorithms.json")

    @property
    def ciphers(self): return self._load_registry("ciphers", "cipher_algorithms.json")

    @property
    def macs(self): return self._load_registry("macs", "mac_algorithms.json")

    @property
    def compression(self): return self._load_registry("compression", "compression_algorithms.json")

    def __getattr__(self, name):
        return self._handle_missing_value(name)

    def _handle_missing_value(self, name):
        print(f"{name} asked")
        return None


### Listes
# TODO: Add support for -* algorithms [https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-17]
# TODO: Diffie-hellman-group14-sha256 MUST be implemented according to IANA. Add a check to verify if present.
# TODO: Check if when using AEAD the mac cannot be changed, this would break up the connection big time.

def special_parse(values:list=[], algorithms:dict=None) -> None:   # TODO Add type 
    for algorithm in values:
        only_algorithm = algorithm.split("@")[0] 
        algo_obj = algorithms.get(only_algorithm, Algorithm(algorithm, 'bad', '(Unknown Algorithm)'))
        pprint(f"\t{algo_obj.name} {algo_obj.label}", algo_obj.status)

### Fonctions
def parse_ssh_string(data, offset):
    if offset + 4 > len(data):
        return "", offset
    length = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    string_data = data[offset:offset+length].decode('utf-8', errors='ignore')
    return string_data.split(","), offset + length

def build_ssh_packet(payload):
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    
    total_len = len(payload) + pad_len + 1
    packet = struct.pack(">IB", total_len, pad_len) + payload + (b'\x00' * pad_len)
    return packet


SSH_BANNER_RE = re.compile(
    r"^SSH-(?P<proto>[12]\.[0-9]+)-(?P<software>[^ ]+)(?:\s+(?P<comments>.+))?$"
)

def perform_banner_exchange(s): # C'est quoi le type de ce truc ?
    """
    Handles the SSH banner exchange. Returns the formatted banner string or None if it fails.
    """
    try:
        raw_banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
    except OSError:
        pprint("Connection lost during banner exchange.", "error")
    
    if not raw_banner:
        pprint("No banner received from server.", "error")
        return

    pprint(f"Raw Server Banner: {raw_banner}", "info")
    match = SSH_BANNER_RE.search(raw_banner)

    if match:
        proto = match.group('proto')
        software = match.group('software')
        comments = match.group('comments')

        pprint("Banner Conformity: RFC 4253 Compliant", "good")
        pprint(f"Protocol Version: {proto}", "result")
        pprint(f"Software Version: {software}", "result")
        #write_vuln(f"Version logicielle partagée: {software}")
        
        if comments:
            pprint(f"Optional Comments: {comments}", "result")
        else:
            pprint("Optional Comments: None provided", "info")

        if proto == "1.99":
            pprint("Note: Protocol 1.99 indicates support for both v1 and v2.", "info")
            #write_vuln("SSHv1 toujours disponible")
        elif proto.startswith("1."):
            pprint("Warning: Server is using legacy SSHv1.", "warn")
            #write_vuln(f"SSHv1 toujours utilisé. Version {proto}")
            
    else:
        pprint("Banner Breakdown: Non-conformant format.", "bad")
        pprint("The string does not follow the 'SSH-protoversion-softwareversion' structure.", "warn")

    s.sendall(b"SSH-2.0-Chelinka_SSH_Scanner_1.0\r\n")
    return f"SSH-{proto}-{software} {comments}"

def analyze_algorithms(s, algodir:str="default"):
    try:
        raw_packet_len = s.recv(4)
        if not raw_packet_len:
            pprint("Connection closed before KEXINIT.", "bad")
            return
        
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

            # Checking if reference directory exists
            path = normpath(f"algorithms/{algodir}")

            if not isdir(path):
                pprint(f"Reference subdirectory {algodir} could not be found. Defaulting to no colors.", "warn")

            # Creating dico nonethless
            ianaDicos = IanaAlgorithms(algodir=algodir)

            # Checking Key Exchange types
            pprint(f"Key Exchange:", "result")
            special_parse(kex, ianaDicos.kex)

            # Add a check for the terrapin vulnerability
            if "kex-strict-s-v00@openssh.com" in kex:
                pprint("Server seems resilient against Terrapin attack.","good")
            else:
                pprint("Server does not seems resilient against Terrapin attack.","bad")
                #write_vuln("Absence de protections supplémentaires contre l'attaque Terrapin")
            
            # Checking host key algorithms
            pprint(f"Host Key Algs:", "result")
            special_parse(hkey, ianaDicos.hostkeys)

            # Checking Cipher types
            if enc_ctos == enc_stoc: # Somehow in python it checks for order of objects ??? No edge case ?
                pprint(f"Ciphers (C->S->C):", "result")
                special_parse(enc_ctos, ianaDicos.ciphers)
            else:
                pprint(f"Cipher (C->S):", "result")
                special_parse(enc_ctos, ianaDicos.ciphers)
                pprint(f"Cipher (S->C):", "result")
                special_parse(enc_stoc, ianaDicos.ciphers)
            
            # Checking Macs types 
            if mac_ctos == mac_stoc:
                pprint(f"MACs (C->S->C)", "result")
                special_parse(mac_ctos, ianaDicos.macs)
            else:
                pprint(f"MACs (C->S):", "result")
                special_parse(mac_ctos, ianaDicos.macs)
                pprint(f"MACs (S->C):", "result")
                special_parse(mac_stoc, ianaDicos.macs)
            
            # Checking compression types
            if comp_ctos == comp_stoc:
                pprint(f"Compression (C->S->C):", "result")
                special_parse(comp_stoc, ianaDicos.compression)
            else:
                pprint(f"Compression (C->S):", "result")
                special_parse(comp_stoc, ianaDicos.compression)
                pprint(f"Compression (S->C):", "result")
                special_parse(comp_stoc, ianaDicos.compression)
            
            # Creating list of bad algorithms for futher export
            vuln_kex = list()
            for kx in kex:
                if ianaDicos.kex[kx.split("@")[0]].status not in ["good", "optimal"]:
                    vuln_kex.append(kx)
            
            vuln_hkeys = list()
            for hk in hkey:
                if ianaDicos.hostkeys[hk.split("@")[0]].status not in ["good","optimal"]:
                    vuln_hkeys.append(hk)
            
            vuln_ciphers = list()
            for cipher in set(enc_stoc + enc_ctos):
                if ianaDicos.ciphers[cipher.split("@")[0]].status not in ["good","optimal"]:
                    vuln_ciphers.append(cipher)
            
            vuln_macs = list()
            for mac in set(mac_stoc + mac_ctos):
                if ianaDicos.macs[mac.split("@")[0]].status not in ["good","optimal"]:
                    vuln_macs.append(mac)
            
            #write_vuln(f"Algorithmes d'échange de clefs: {','.join(vuln_kex)}\nAlgorithmes de chiffrement pas bons: {','.join(vuln_ciphers)}\nAlgorithmes de clefs privées pas bons: {','.join(vuln_hkeys)}\nAlgorithmes de signature de paquet pas bons: {','.join(vuln_macs)}")

            if offset < len(data):
                first_kex_follows = data[offset]
                pprint(f"First KEX Packet Follows: {bool(first_kex_follows)}", "info")
            
            all_lists = ":".join([",".join(inlist) for inlist in [kex, hkey, enc_ctos, enc_stoc, mac_ctos, mac_stoc, comp_ctos, comp_stoc]])
            return sha256(all_lists.encode()).hexdigest()

        else:
            pprint(f"Unexpected packet type: {data[1] if len(data) > 1 else 'Unknown'}", "warn")
            
    except Exception as e:
        pprint(f"Error during algorithm negotiation: {e}", "error")

def discover_auth_methods(host:str=None, port:int=22) -> str:
    pprint("Probing for authentication methods via Transport...", "info")
    transport = None
    try:
        transport = paramiko.Transport((host, port))
        
        transport.start_client()
        
        try:
            transport.auth_none('')
        except paramiko.BadAuthenticationType as err:
            methods = err.allowed_types

        if methods == []:
            pprint("Server returned an empty list of methods or session closed.", "warn")
            return

        pprint(f"Authorized Methods: {', '.join(methods)}", "result")
        
        # TODO: Replace this shit
        auth_methods_map = {
            "publickey":            ["Public Key (RFC 4252)","optimal"],
            "password":             ["Password (RFC 4252)","bad"],
            "hostbased":            ["Host-Based (RFC 4252)","bad"],
            "none":                 ["None / Recon (RFC 4252)","error"],
            "keyboard-interactive": ["Challenge-Response / PAM (RFC 4256)","good"],
            "gssapi-with-mic":      ["GSSAPI with MIC / Kerberos (RFC 4462)","good"],
            "gssapi-keyex":         ["GSSAPI Key Exchange (RFC 4462)","good"],
            "gssapi":               ["GSSAPI Generic (RFC 4462)","good"],
            "external-keyx":        ["External Key Exchange (RFC 4462)","good"]
        }
        
        for method in methods:
            label = auth_methods_map.get(method, ["Unknown method","info"])
            pprint(f"{label[0]:22}", label[1])

    except Exception as e:
        pprint(f"Auth Discovery Error: {type(e).__name__} - {e}", "error")
    finally:
        if transport:
            transport.close()
    return ",".join(methods)

def make_fingerprint(host:str=None, port:int=22, banner:str="", fingerprint:str="", methods:str="", write_to_file:bool=False):
    signature = f"{host}:{port};{banner};{fingerprint};{methods}\n"
    pprint(signature.strip(), "signature")
    if write_to_file:
        with open("signature_file", "a") as fp:
            fp.write(signature)

def fingerprint_check(fingerprint:str):
    
    with open("algorithms/known_hashes.json", "r") as fp:
        data = load(fp)
        if fingerprint in data.keys():
            pprint(f"Fingerprint found in database. Corresponding to :\n\t{'\n\t'.join(data[fingerprint])}", "result")
        else:
            pprint(f"Fingerprint not found in database.", "result")

# --- Logique principale ---
def analyze_ssh(host:str, port:int=22, algodir:str="default", add_signature:bool=False) -> None:
    try:
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror:
            pprint(f"Could not resolve hostname: {host}", "error")
            return

        if host == resolved_ip:
            conn_msg = f"Connecting to {resolved_ip}:{port}..."
        else:
            conn_msg = f"Connecting to ({host}) {resolved_ip}:{port}..."

        pprint(conn_msg, "info")
        with socket.create_connection((resolved_ip, port), timeout=1) as s:
            banner = perform_banner_exchange(s)
            fingerprint = analyze_algorithms(s, algodir)
            methods = discover_auth_methods(host, port)
            make_fingerprint(host, port, banner, fingerprint, methods, add_signature)
            fingerprint_check(fingerprint)
            
    except socket.timeout:
        pprint(f"Connection timed out to {host}:{port}", "error")
    except ConnectionRefusedError:
        pprint(f"Connection refused by {host}:{port}", "bad")
    except Exception as e:
        pprint(f"An unexpected error occurred: {e}", "error")

if __name__ == "__main__":
    typer.run(analyze_ssh)
