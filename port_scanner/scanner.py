"""Motor del escáner: no depende de la interfaz, así se puede probar por separado."""

from __future__ import annotations

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Optional

# Servicios habituales. Si un puerto no está aquí, se pregunta al sistema operativo.
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Puertos que suelen indicar un riesgo si están abiertos hacia Internet.
RISK_NOTES = {
    21: "FTP envía usuario y contraseña sin cifrar",
    23: "Telnet no cifra nada; debería usarse SSH",
    135: "MS-RPC expuesto, usado en muchos ataques a Windows",
    139: "NetBIOS expuesto, puede revelar información del equipo",
    445: "SMB expuesto, vector de ransomware como WannaCry",
    1433: "Base de datos MSSQL accesible desde la red",
    3306: "Base de datos MySQL accesible desde la red",
    3389: "Escritorio remoto expuesto, objetivo de fuerza bruta",
    5432: "Base de datos PostgreSQL accesible desde la red",
    5900: "VNC expuesto, a menudo con contraseñas débiles",
    6379: "Redis no pide autenticación por defecto",
    9200: "Elasticsearch suele exponer datos sin autenticación",
    27017: "MongoDB expuesto, causa habitual de filtraciones",
}

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
BANNER_TIMEOUT = 3.0

PORT_PRESETS = {
    "Comunes": sorted(COMMON_SERVICES),
    "1-1024": list(range(1, 1025)),
    "Todos": list(range(1, 65536)),
}

# Objetivo público pensado para practicar: el proyecto Nmap permite escanearlo.
PRACTICE_HOSTS = {"scanme.nmap.org"}


@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""
    risk: str = ""


def parse_ports(text: str) -> list[int]:
    """Convierte '22,80,1000-1010' en una lista ordenada de puertos sin repetir."""
    ports: set[int] = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            if not (start_s.isdigit() and end_s.isdigit()):
                raise ValueError(f"Rango no válido: '{part}'")
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        elif part.isdigit():
            ports.add(int(part))
        else:
            raise ValueError(f"Puerto no válido: '{part}'")
    if not ports:
        raise ValueError("No se ha indicado ningún puerto")
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Los puertos deben estar entre 1 y 65535 (encontrado {bad[0]})")
    return sorted(ports)


def resolve_target(target: str) -> str:
    """Devuelve la IP de un dominio o de una IP escrita como texto."""
    target = target.strip()
    if not target:
        raise ValueError("Escribe una IP o un dominio")
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"No se pudo resolver '{target}'") from exc


def needs_authorization_warning(target: str, ip: str) -> bool:
    """True si el objetivo es público y no es un host de práctica."""
    if target.strip().lower() in PRACTICE_HOSTS:
        return False
    addr = ipaddress.ip_address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Desconocido"


def grab_banner(sock: socket.socket, port: int, host: str) -> str:
    """Intenta leer el mensaje de bienvenida del servicio (banner grabbing)."""
    try:
        # Algunos servicios (como SSH con comprobaciones de DNS) tardan varios
        # segundos en saludar. Solo afecta a los puertos abiertos, que son pocos.
        sock.settimeout(BANNER_TIMEOUT)
        if port in HTTP_PORTS:
            # Los servidores web no saludan: hay que hacerles una petición.
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            data = sock.recv(1024).decode(errors="replace")
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return data.splitlines()[0].strip() if data else ""
        data = sock.recv(1024).decode(errors="replace")
        return data.strip().splitlines()[0][:80] if data.strip() else ""
    except (OSError, IndexError):
        return ""


def scan_port(ip: str, port: int, timeout: float, host: str = "",
              banners: bool = True) -> Optional[PortResult]:
    """Devuelve un PortResult si el puerto está abierto, o None si no lo está."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = grab_banner(sock, port, host or ip) if banners else ""
    except OSError:
        return None
    return PortResult(port, service_name(port), banner, RISK_NOTES.get(port, ""))


class PortScanner:
    """Escanea una lista de puertos en paralelo y se puede detener a mitad."""

    def __init__(self, threads: int = 100, timeout: float = 1.0, banners: bool = True):
        self.threads = threads
        self.timeout = timeout
        self.banners = banners
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def scan(self, ip: str, ports: list[int], host: str = "",
             on_open: Callable[[PortResult], None] = lambda r: None,
             on_progress: Callable[[int, int], None] = lambda done, total: None,
             ) -> list[PortResult]:
        self._stop.clear()
        total = len(ports)
        results: list[PortResult] = []
        done = 0
        lock = threading.Lock()

        def worker(port: int) -> None:
            nonlocal done
            if self._stop.is_set():
                return
            result = scan_port(ip, port, self.timeout, host, self.banners)
            with lock:
                done += 1
                if result:
                    results.append(result)
                    on_open(result)
                on_progress(done, total)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            for port in ports:
                if self._stop.is_set():
                    break
                pool.submit(worker, port)
            # Al salir del with se espera a los hilos que ya estaban en marcha;
            # los que aún no habían empezado ven la señal de stop y salen al momento.
        return sorted(results, key=lambda r: r.port)

