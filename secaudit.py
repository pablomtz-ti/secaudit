#!/usr/bin/env python3
"""
secaudit.py — Auditor de seguridad defensiva para sistemas Linux.

Escanea TU PROPIO equipo en busca de configuraciones débiles, software
desactualizado, permisos inseguros, servicios expuestos y desviaciones de las
buenas prácticas de hardening. No explota nada: solo lee el estado del sistema
y produce un informe con hallazgos y recomendaciones.

Uso:
    python3 secaudit.py                      # informe en consola
    sudo python3 secaudit.py                 # recomendado (más comprobaciones)
    python3 secaudit.py --html informe.html  # exporta informe HTML
    python3 secaudit.py --json informe.json  # exporta informe JSON
    python3 secaudit.py --txt informe.txt    # exporta informe de texto plano
    python3 secaudit.py --md informe.md      # exporta informe Markdown
    python3 secaudit.py --only ssh,firewall  # ejecuta solo ciertos módulos
    python3 secaudit.py --diff base.json     # compara con una línea base

Solo usa la librería estándar de Python 3. Sin dependencias externas.
Pensado para auditar máquinas propias o con autorización explícita.
"""

from __future__ import annotations

__version__ = "1.0.0"

import argparse
import datetime
import glob
import html
import json
import os
import platform
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Callable

# --------------------------------------------------------------------------- #
# Modelo de datos
# --------------------------------------------------------------------------- #

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Colores ANSI para la salida en consola
COLORS = {
    "CRITICAL": "\033[1;37;41m",  # blanco sobre rojo
    "HIGH": "\033[1;31m",         # rojo
    "MEDIUM": "\033[1;33m",       # amarillo
    "LOW": "\033[1;36m",          # cian
    "INFO": "\033[1;32m",         # verde
    "RESET": "\033[0m",
    "DIM": "\033[2m",
    "BOLD": "\033[1m",
}


@dataclass
class Finding:
    severity: str            # uno de SEVERITIES
    category: str            # módulo que lo generó (ssh, firewall, ...)
    title: str               # resumen corto del hallazgo
    detail: str = ""         # explicación / evidencia
    recommendation: str = "" # qué hacer al respecto

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Severidad inválida: {self.severity}")


@dataclass
class CheckResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    skipped: str | None = None  # motivo si se omitió (p.ej. falta root)


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #

def is_root() -> bool:
    return os.geteuid() == 0


def run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Ejecuta un comando de forma segura (sin shell) y devuelve (rc, out, err)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"no encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def read_text(path: str) -> str | None:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return None


# --------------------------------------------------------------------------- #
# Módulos de comprobación
# Cada función recibe nada y devuelve un CheckResult.
# --------------------------------------------------------------------------- #

def check_system_info() -> CheckResult:
    r = CheckResult("system")
    uname = platform.uname()
    r.findings.append(Finding(
        "INFO", "system", "Información del sistema",
        detail=(f"Host: {uname.node} | Kernel: {uname.release} | "
                f"Arquitectura: {uname.machine}"),
    ))

    osr = read_text("/etc/os-release") or ""
    m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', osr)
    if m:
        r.findings.append(Finding(
            "INFO", "system", "Distribución",
            detail=m.group(1),
        ))

    # Tiempo de actividad: un uptime muy alto puede implicar kernel sin parchear.
    upt = read_text("/proc/uptime")
    if upt:
        try:
            days = float(upt.split()[0]) / 86400
            sev = "MEDIUM" if days > 180 else "INFO"
            r.findings.append(Finding(
                sev, "system", f"Tiempo de actividad: {days:.0f} días",
                detail=("Un uptime prolongado suele indicar que no se han "
                        "aplicado parches de kernel que requieren reinicio."
                        if days > 180 else ""),
                recommendation=("Reinicia tras aplicar actualizaciones de "
                                "kernel." if days > 180 else ""),
            ))
        except ValueError:
            pass
    return r


def check_updates() -> CheckResult:
    r = CheckResult("updates")
    if have("apt"):
        # 'apt-get -s upgrade' usa las listas locales: si nadie ejecuta
        # 'apt update', el resultado "al día" puede ser falso.
        lists = "/var/lib/apt/lists"
        try:
            age_days = (datetime.datetime.now().timestamp()
                        - os.stat(lists).st_mtime) / 86400
            if age_days > 7:
                r.findings.append(Finding(
                    "LOW", "updates",
                    f"Listas de paquetes sin refrescar desde hace {age_days:.0f} días",
                    detail="El recuento de actualizaciones puede estar desfasado.",
                    recommendation="Ejecuta 'sudo apt update' o activa unattended-upgrades.",
                ))
        except OSError:
            pass
        rc, out, _ = run(["apt-get", "-s", "upgrade"])
        if rc == 0:
            pkgs = [ln for ln in out.splitlines() if ln.startswith("Inst ")]
            sec = [ln for ln in pkgs if "security" in ln.lower()]
            if sec:
                r.findings.append(Finding(
                    "HIGH", "updates",
                    f"{len(sec)} actualizaciones de SEGURIDAD pendientes",
                    detail="; ".join(p.split()[1] for p in sec[:15]),
                    recommendation="Ejecuta: sudo apt update && sudo apt upgrade",
                ))
            other = [p for p in pkgs if p not in sec]
            if other:
                r.findings.append(Finding(
                    "MEDIUM", "updates",
                    f"{len(other)} actualizaciones pendientes (no seguridad)",
                    detail="; ".join(p.split()[1] for p in other[:15]),
                    recommendation="Mantén el sistema al día con apt upgrade.",
                ))
            if not pkgs:
                r.findings.append(Finding(
                    "INFO", "updates", "Sistema al día (apt)",
                ))
    elif have("dnf"):
        rc, out, _ = run(["dnf", "-q", "check-update"])
        # dnf devuelve 100 si hay actualizaciones
        lines = [ln for ln in out.splitlines() if ln and not ln.startswith(" ")]
        if rc == 100 and lines:
            r.findings.append(Finding(
                "MEDIUM", "updates",
                f"{len(lines)} actualizaciones pendientes (dnf)",
                recommendation="Ejecuta: sudo dnf upgrade",
            ))
        elif rc == 0:
            r.findings.append(Finding("INFO", "updates", "Sistema al día (dnf)"))
    else:
        r.skipped = "Gestor de paquetes no soportado (ni apt ni dnf)."
    return r


def check_users() -> CheckResult:
    r = CheckResult("users")

    # Cuentas con UID 0 distintas de root
    uid0 = [u.pw_name for u in pwd.getpwall() if u.pw_uid == 0 and u.pw_name != "root"]
    if uid0:
        r.findings.append(Finding(
            "CRITICAL", "users",
            "Cuentas con privilegios de root (UID 0) además de root",
            detail=", ".join(uid0),
            recommendation="Investiga y elimina cuentas UID 0 no autorizadas.",
        ))

    # Contraseñas vacías en /etc/shadow (requiere root)
    shadow = read_text("/etc/shadow")
    if shadow is None:
        r.findings.append(Finding(
            "INFO", "users",
            "No se pudo leer /etc/shadow (ejecuta con sudo para más detalle)",
        ))
    else:
        empty = []
        for ln in shadow.splitlines():
            parts = ln.split(":")
            if len(parts) > 1 and parts[1] == "":
                empty.append(parts[0])
        if empty:
            r.findings.append(Finding(
                "CRITICAL", "users",
                "Cuentas con contraseña VACÍA",
                detail=", ".join(empty),
                recommendation="Asigna contraseña o bloquea: sudo passwd -l USUARIO",
            ))

    # Usuarios con shell de login y que pueden autenticarse
    login_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash",
                    "/usr/bin/zsh", "/bin/ksh", "/usr/bin/fish"}
    humans = [u.pw_name for u in pwd.getpwall()
              if u.pw_shell in login_shells and u.pw_uid >= 1000]
    if humans:
        r.findings.append(Finding(
            "INFO", "users",
            f"{len(humans)} cuentas de usuario con shell de login",
            detail=", ".join(humans),
        ))
    return r


def parse_sshd_config(path: str, _depth: int = 0) -> dict[str, str]:
    """Interpreta sshd_config como lo hace sshd: la PRIMERA aparición de cada
    directiva gana, se siguen los 'Include' (p.ej. sshd_config.d/*.conf, que
    Debian/Ubuntu incluyen al principio) y se ignoran los bloques 'Match'.
    Devuelve {directiva_en_minúsculas: valor}."""
    values: dict[str, str] = {}
    text = read_text(path)
    if text is None or _depth > 5:
        return values
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) == 2 else ""
        if key == "match":
            break  # lo que sigue solo aplica condicionalmente
        if key == "include":
            for pattern in val.split():
                if not os.path.isabs(pattern):
                    pattern = os.path.join("/etc/ssh", pattern)
                for inc in sorted(glob.glob(pattern)):
                    for k, v in parse_sshd_config(inc, _depth + 1).items():
                        values.setdefault(k, v)
            continue
        values.setdefault(key, val)
    return values


def effective_sshd_config() -> tuple[dict[str, str] | None, str]:
    """Configuración efectiva de sshd. Con root se usa 'sshd -T', que es la
    fuente de verdad (resuelve Includes, valores por defecto y alias). Sin
    root, se interpreta el fichero a mano."""
    if is_root() and have("sshd"):
        rc, out, _ = run(["sshd", "-T"])
        if rc == 0 and out.strip():
            vals = {}
            for ln in out.splitlines():
                parts = ln.split(None, 1)
                if len(parts) == 2:
                    vals.setdefault(parts[0].lower(), parts[1].strip())
            return vals, "sshd -T"
    if not os.path.exists("/etc/ssh/sshd_config"):
        return None, ""
    return parse_sshd_config("/etc/ssh/sshd_config"), "sshd_config"


def check_ssh() -> CheckResult:
    r = CheckResult("ssh")
    cfg, source = effective_sshd_config()
    if cfg is None:
        r.skipped = "No hay /etc/ssh/sshd_config (¿servidor SSH no instalado?)."
        return r

    def directive(name: str, default: str | None = None) -> str | None:
        return cfg.get(name.lower(), default)

    # 'without-password' es el alias antiguo de 'prohibit-password' (solo
    # permite root con clave), así que NO es equivalente a 'yes'.
    permit_root = (directive("PermitRootLogin", "prohibit-password") or "").lower()
    if permit_root == "yes":
        r.findings.append(Finding(
            "HIGH", "ssh", "PermitRootLogin = yes",
            detail=("Permite login directo de root con contraseña, lo que "
                    f"amplía la superficie de ataque. (fuente: {source})"),
            recommendation="Pon 'PermitRootLogin no' en sshd_config.",
        ))
    elif permit_root in ("prohibit-password", "without-password"):
        r.findings.append(Finding(
            "LOW", "ssh", f"PermitRootLogin = {permit_root}",
            detail="Root puede entrar por SSH con clave pública.",
            recommendation="Si no lo necesitas, usa 'PermitRootLogin no'.",
        ))

    pwauth = (directive("PasswordAuthentication", "yes") or "").lower()
    if pwauth == "yes":
        r.findings.append(Finding(
            "MEDIUM", "ssh", "Autenticación por contraseña habilitada en SSH",
            detail="Las contraseñas son vulnerables a fuerza bruta.",
            recommendation=("Usa claves y pon 'PasswordAuthentication no' "
                            "(asegúrate antes de tener tu clave funcionando)."),
        ))

    empty_pw = (directive("PermitEmptyPasswords", "no") or "").lower()
    if empty_pw == "yes":
        r.findings.append(Finding(
            "CRITICAL", "ssh", "PermitEmptyPasswords = yes",
            recommendation="Pon 'PermitEmptyPasswords no'.",
        ))

    proto = directive("Protocol")
    if proto and "1" in proto.split(","):
        r.findings.append(Finding(
            "CRITICAL", "ssh", "SSH Protocol 1 habilitado",
            detail="El protocolo SSHv1 está roto criptográficamente.",
            recommendation="Usa solo 'Protocol 2'.",
        ))

    x11 = (directive("X11Forwarding", "no") or "").lower()
    if x11 == "yes":
        r.findings.append(Finding(
            "LOW", "ssh", "X11Forwarding habilitado",
            recommendation="Desactívalo si no lo necesitas.",
        ))

    maxauth = directive("MaxAuthTries")
    if maxauth and maxauth.isdigit() and int(maxauth) > 6:
        r.findings.append(Finding(
            "LOW", "ssh", f"MaxAuthTries alto ({maxauth})",
            recommendation="Reduce a 3-4 para frenar fuerza bruta.",
        ))

    if not r.findings:
        r.findings.append(Finding("INFO", "ssh", "Configuración SSH sin hallazgos relevantes"))
    return r


def check_firewall() -> CheckResult:
    r = CheckResult("firewall")
    active = False

    if have("ufw"):
        rc, out, _ = run(["ufw", "status"])
        if rc == 0 and "Status: active" in out:
            active = True
            r.findings.append(Finding("INFO", "firewall", "Firewall UFW activo"))
    if not active and have("firewall-cmd"):
        rc, out, _ = run(["firewall-cmd", "--state"])
        if rc == 0 and "running" in out:
            active = True
            r.findings.append(Finding("INFO", "firewall", "firewalld activo"))
    if not active and have("nft"):
        rc, out, _ = run(["nft", "list", "ruleset"])
        if rc == 0 and out.strip():
            active = True
            r.findings.append(Finding("INFO", "firewall", "Reglas nftables presentes"))
    if not active and have("iptables"):
        rc, out, _ = run(["iptables", "-S"])
        if rc == 0:
            rules = [ln for ln in out.splitlines()
                     if ln and not ln.startswith("-P")]
            if rules:
                active = True
                r.findings.append(Finding(
                    "INFO", "firewall", f"iptables con {len(rules)} reglas"))

    if not active:
        r.findings.append(Finding(
            "HIGH", "firewall", "No se detectó ningún firewall activo",
            detail="Sin filtrado, los servicios en escucha quedan expuestos.",
            recommendation="Activa un firewall (p.ej. sudo ufw enable) "
                           "con política por defecto de denegar entrada.",
        ))
    return r


def ephemeral_port_start() -> int:
    """Primer puerto del rango efímero del kernel (32768 por defecto)."""
    rng = read_text("/proc/sys/net/ipv4/ip_local_port_range") or ""
    try:
        return int(rng.split()[0])
    except (IndexError, ValueError):
        return 32768


def parse_ss(out: str, ephemeral_start: int = 32768) -> tuple[
        list[tuple[str, str, str]], int]:
    """Interpreta la salida de 'ss -tulnp'.

    Devuelve (escuchas, sockets_udp_efímeros). Cada escucha es
    (protocolo, dirección:puerto, programas). Los programas se reducen a sus
    nombres, sin PID ni descriptor, porque esos números cambian en cada
    arranque y harían que '--diff' alertase siempre por lo mismo.
    Los sockets UDP en el rango efímero son clientes (navegadores, apps de
    chat, resolvedores) y no servicios ofrecidos a la red: se cuentan aparte.
    """
    listeners: list[tuple[str, str, str]] = []
    ephemeral_udp = 0
    for ln in out.splitlines()[1:]:
        cols = ln.split()
        if len(cols) < 5:
            continue
        proto, local = cols[0], cols[4]
        names = sorted(set(re.findall(r'\("([^"]+)"', ln)))
        try:
            port = int(local.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            port = 0
        if proto == "udp" and port >= ephemeral_start:
            ephemeral_udp += 1
            continue
        listeners.append((proto, local, ",".join(names)))
    return listeners, ephemeral_udp


def check_listening_ports() -> CheckResult:
    r = CheckResult("ports")
    listeners: list[tuple[str, str, str]] = []  # (proto, dirección, programas)
    ephemeral_udp = 0

    if have("ss"):
        rc, out, _ = run(["ss", "-tulnp"])
        if rc == 0:
            listeners, ephemeral_udp = parse_ss(out, ephemeral_port_start())

    # Puertos en escucha sobre 0.0.0.0 / :: (accesibles desde la red).
    # 'ss' puede añadir la interfaz: "0.0.0.0%eth0:68".
    exposed = []
    for proto, local, proc in listeners:
        addr = local.rsplit(":", 1)[0].split("%")[0]
        if addr in ("0.0.0.0", "*", "::", "[::]"):
            exposed.append((proto, local, proc))

    if ephemeral_udp:
        r.findings.append(Finding(
            "INFO", "ports",
            f"{ephemeral_udp} sockets UDP de clientes en puertos efímeros (no son servicios)"))
    if exposed:
        detail = "\n".join(f"{p:5} {l:24} {pr[:60]}".rstrip() for p, l, pr in exposed)
        r.findings.append(Finding(
            "MEDIUM", "ports",
            f"{len(exposed)} servicios en escucha en TODAS las interfaces",
            detail=detail,
            recommendation=("Vincula los servicios solo a 127.0.0.1 si no "
                            "necesitan acceso de red, y protégelos con firewall."),
        ))
    if listeners and not exposed:
        r.findings.append(Finding(
            "INFO", "ports",
            f"{len(listeners)} servicios en escucha (solo interfaces locales)"))
    if not listeners and not have("ss"):
        r.skipped = "Comando 'ss' no disponible."
    return r


def check_suid() -> CheckResult:
    r = CheckResult("suid")
    # Lista de binarios SUID/SGID conocidos como peligrosos si están presentes
    # de forma inesperada (referencia: proyecto GTFOBins).
    dangerous = {
        "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "mv",
        "awk", "man", "wget", "curl", "python", "python3", "perl", "ruby",
        "tar", "zip", "env", "ftp", "tclsh", "dmsetup", "pico",
    }
    found_suid: list[str] = []
    flagged: list[str] = []
    search_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                path = os.path.join(d, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    found_suid.append(path)
                    if name in dangerous:
                        flagged.append(path)
        except PermissionError:
            continue

    if flagged:
        r.findings.append(Finding(
            "HIGH", "suid",
            "Binarios SUID/SGID potencialmente peligrosos",
            detail="\n".join(flagged),
            recommendation=("Estos binarios con SUID permiten escalar "
                            "privilegios. Quita el bit si no es necesario: "
                            "sudo chmod u-s ARCHIVO"),
        ))
    r.findings.append(Finding(
        "INFO", "suid",
        f"{len(found_suid)} binarios SUID/SGID en total",
        detail=("\n".join(sorted(found_suid)) if found_suid else ""),
    ))
    return r


def check_world_writable() -> CheckResult:
    r = CheckResult("permissions")
    ww_files: list[str] = []
    ww_dirs_no_sticky: list[str] = []
    # Acotamos la búsqueda a rutas comunes para no tardar demasiado.
    roots = ["/etc", "/usr/local", "/opt", "/var/www", "/srv", "/home"]
    MAX_FILES = 200000  # cortafuegos de rendimiento
    count = 0
    truncated = False
    for root in roots:
        if truncated:
            break
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            # No seguir enlaces ni entrar en pseudo-FS
            dirnames[:] = [d for d in dirnames if not os.path.islink(
                os.path.join(dirpath, d))]
            for name in filenames:
                count += 1
                if count > MAX_FILES:
                    truncated = True
                    break
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if st.st_mode & stat.S_IWOTH:
                    ww_files.append(path)
            try:
                st = os.lstat(dirpath)
                if (st.st_mode & stat.S_IWOTH) and not (st.st_mode & stat.S_ISVTX):
                    ww_dirs_no_sticky.append(dirpath)
            except OSError:
                pass
            if truncated:
                # Detener el recorrido por completo, no solo el bucle de ficheros.
                dirnames[:] = []
                break

    if ww_files:
        r.findings.append(Finding(
            "HIGH", "permissions",
            f"{len(ww_files)} archivos escribibles por todos (world-writable)",
            detail="\n".join(ww_files[:40]) + (
                f"\n... (+{len(ww_files) - 40} más)" if len(ww_files) > 40 else ""),
            recommendation="Revisa y restringe: sudo chmod o-w ARCHIVO",
        ))
    if ww_dirs_no_sticky:
        r.findings.append(Finding(
            "MEDIUM", "permissions",
            f"{len(ww_dirs_no_sticky)} directorios world-writable sin sticky bit",
            detail="\n".join(ww_dirs_no_sticky[:40]),
            recommendation="Añade el sticky bit: sudo chmod +t DIRECTORIO",
        ))
    if truncated:
        r.findings.append(Finding(
            "INFO", "permissions",
            f"Escaneo truncado tras {MAX_FILES} archivos por rendimiento",
            detail="El análisis se detuvo antes de recorrer todas las rutas.",
            recommendation="Para un escaneo exhaustivo usa 'find / -xdev -perm -0002'.",
        ))
    if not ww_files and not ww_dirs_no_sticky and not truncated:
        r.findings.append(Finding(
            "INFO", "permissions",
            "Sin archivos/directorios world-writable problemáticos en rutas comunes"))
    return r


def check_sensitive_perms() -> CheckResult:
    r = CheckResult("sensitive")
    # (ruta, permisos máximos, severidad si se superan). sshd_config es 0644
    # por defecto en Debian/Ubuntu; CIS recomienda 0600, pero no es grave.
    targets = [
        ("/etc/shadow", 0o640, "HIGH"),
        ("/etc/gshadow", 0o640, "HIGH"),
        ("/etc/passwd", 0o644, "HIGH"),
        ("/etc/group", 0o644, "HIGH"),
        ("/etc/ssh/sshd_config", 0o600, "LOW"),
    ]
    for path, max_mode, sev in targets:
        try:
            st = os.stat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        if mode & ~max_mode & 0o777:
            r.findings.append(Finding(
                sev, "sensitive",
                f"Permisos demasiado abiertos en {path}",
                detail=f"Actual: {oct(mode)} | recomendado máx: {oct(max_mode)}",
                recommendation=f"sudo chmod {oct(max_mode)[2:]} {path}",
            ))
    if not r.findings:
        r.findings.append(Finding(
            "INFO", "sensitive", "Permisos de archivos sensibles correctos"))
    return r


def check_sysctl() -> CheckResult:
    r = CheckResult("kernel")
    # Parámetros de hardening recomendados: (clave, valor_esperado, severidad)
    checks = [
        ("net.ipv4.conf.all.rp_filter", "1", "LOW",
         "Filtrado de ruta inversa (anti-spoofing) desactivado"),
        ("net.ipv4.tcp_syncookies", "1", "MEDIUM",
         "SYN cookies desactivadas (protección anti SYN-flood)"),
        ("net.ipv4.conf.all.accept_redirects", "0", "LOW",
         "Se aceptan ICMP redirects (riesgo de MITM)"),
        ("net.ipv4.conf.all.send_redirects", "0", "LOW",
         "Se envían ICMP redirects"),
        ("net.ipv4.ip_forward", "0", "INFO",
         "Reenvío de IP activado (normal solo en routers/contenedores)"),
        ("kernel.randomize_va_space", "2", "MEDIUM",
         "ASLR no está al máximo (2)"),
        ("kernel.kptr_restrict", "1", "LOW",
         "Punteros de kernel no restringidos en /proc"),
        ("kernel.dmesg_restrict", "1", "LOW",
         "dmesg accesible a usuarios sin privilegios"),
    ]
    for key, expected, sev, msg in checks:
        path = "/proc/sys/" + key.replace(".", "/")
        val = read_text(path)
        if val is None:
            continue
        val = val.strip()
        if val != expected:
            # ip_forward activado solo es INFO; el resto según severidad
            r.findings.append(Finding(
                sev, "kernel", msg,
                detail=f"{key} = {val} (esperado {expected})",
                recommendation=f"Ajusta en /etc/sysctl.d/: {key} = {expected}",
            ))
    if not r.findings:
        r.findings.append(Finding(
            "INFO", "kernel", "Parámetros de hardening del kernel correctos"))
    return r


def check_cron() -> CheckResult:
    r = CheckResult("cron")
    suspicious = []
    cron_paths = ["/etc/crontab"]
    for d in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
              "/etc/cron.weekly", "/etc/cron.monthly"]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                cron_paths.append(os.path.join(d, f))

    writable_by_others = []
    for p in cron_paths:
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if st.st_mode & stat.S_IWOTH:
            writable_by_others.append(p)
        content = read_text(p) or ""
        # Patrones que suelen indicar persistencia maliciosa
        if re.search(r"(curl|wget)\s+[^|]*\|\s*(sh|bash)", content):
            suspicious.append((p, "descarga remota canalizada a shell"))
        if "/tmp/" in content and re.search(r"/tmp/\S+", content):
            suspicious.append((p, "ejecuta algo desde /tmp"))

    if writable_by_others:
        r.findings.append(Finding(
            "HIGH", "cron", "Archivos de cron escribibles por otros usuarios",
            detail="\n".join(writable_by_others),
            recommendation="Restringe permisos: sudo chmod 600/644 según el caso.",
        ))
    for p, why in suspicious:
        r.findings.append(Finding(
            "MEDIUM", "cron", f"Tarea cron sospechosa: {why}",
            detail=p,
            recommendation="Revisa manualmente que la tarea sea legítima.",
        ))
    if not r.findings:
        r.findings.append(Finding("INFO", "cron", "Sin anomalías evidentes en cron"))
    return r


def check_failed_logins() -> CheckResult:
    r = CheckResult("authlog")
    # Intentos fallidos recientes vía journalctl o /var/log/auth.log
    text = ""
    if have("journalctl"):
        rc, out, _ = run(["journalctl", "-u", "ssh", "-u", "sshd",
                          "--since", "-7 days", "--no-pager"], timeout=20)
        if rc == 0:
            text = out
    if not text:
        text = read_text("/var/log/auth.log") or read_text("/var/log/secure") or ""

    if not text:
        r.skipped = "No se pudo leer el registro de autenticación (prueba con sudo)."
        return r

    failed = len(re.findall(r"Failed password", text))
    invalid = len(re.findall(r"Invalid user", text))
    if failed or invalid:
        sev = "MEDIUM" if (failed + invalid) > 50 else "LOW"
        r.findings.append(Finding(
            sev, "authlog",
            f"{failed} contraseñas fallidas y {invalid} usuarios inválidos recientes",
            detail="Indicio de intentos de fuerza bruta contra SSH.",
            recommendation=("Considera fail2ban, claves SSH y restringir el "
                            "puerto por firewall."),
        ))
    else:
        r.findings.append(Finding(
            "INFO", "authlog", "Sin intentos de login fallidos relevantes"))
    return r


def check_integrity() -> CheckResult:
    """Verifica que los binarios instalados no se hayan modificado respecto a
    la versión empaquetada (detecta manipulación o reemplazo de binarios)."""
    r = CheckResult("integrity")
    if not is_root():
        r.skipped = "Requiere root para verificar integridad de paquetes."
        return r

    modified: list[tuple[str, str]] = []  # (flags, ruta)
    missing: list[str] = []

    if have("dpkg"):
        # dpkg --verify marca: ??5?????? = cambio de checksum (contenido),
        # columnas: S(tamaño) M(modo) 5(md5) D(dispositivo) L(enlace) U(uid)
        # G(gid) T(mtime). Nos interesan sobre todo 5 (contenido) y M (permisos).
        rc, out, _ = run(["dpkg", "--verify"], timeout=180)
        if rc in (0, 1):  # 1 = hay diferencias, no es error
            for ln in out.splitlines():
                parts = ln.split(None, 1)
                if len(parts) != 2:
                    continue
                flags, path = parts
                # Ignorar archivos de configuración (marcados con 'c')
                if " c " in f" {ln} " or flags.endswith("c"):
                    continue
                # 'missing': el paquete declara el fichero pero no está. Suele
                # ser documentación excluida (imágenes mínimas, path-exclude),
                # no una manipulación: se cuenta aparte.
                if flags == "missing":
                    missing.append(path.strip())
                    continue
                modified.append((flags, path))
    elif have("rpm"):
        rc, out, _ = run(["rpm", "-Va", "--nomtime"], timeout=180)
        if rc in (0, 1):
            for ln in out.splitlines():
                parts = ln.split()
                if len(parts) < 2:
                    continue
                flags = parts[0]
                path = parts[-1]
                if "c" in parts:  # archivo de configuración
                    continue
                modified.append((flags, path))
    else:
        r.skipped = "Ni dpkg ni rpm disponibles."
        return r

    # Cambios de contenido (md5) en ejecutables: lo más grave. En librerías
    # también importa, pero hay más falsos positivos (triggers de paquetes,
    # ficheros regenerados), así que van con severidad media.
    bin_dirs = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/")
    lib_dirs = ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")
    critical_changes = [
        (f, p) for f, p in modified
        if "5" in f and p.startswith(bin_dirs)
    ]
    def is_shared_lib(p: str) -> bool:
        name = os.path.basename(p)
        return name.endswith(".so") or ".so." in name

    lib_changes = [
        (f, p) for f, p in modified
        if "5" in f and p.startswith(lib_dirs) and is_shared_lib(p)
    ]
    if critical_changes:
        detail = "\n".join(f"{f}  {p}" for f, p in critical_changes[:40])
        r.findings.append(Finding(
            "HIGH", "integrity",
            f"{len(critical_changes)} binarios del sistema con contenido alterado",
            detail=detail,
            recommendation=("Un binario que difiere de su paquete puede indicar "
                            "manipulación. Reinstala el paquete afectado "
                            "(apt install --reinstall PAQUETE) y verifica su origen."),
        ))
    if lib_changes:
        r.findings.append(Finding(
            "MEDIUM", "integrity",
            f"{len(lib_changes)} librerías compartidas con contenido alterado",
            detail="\n".join(f"{f}  {p}" for f, p in lib_changes[:40]),
            recommendation=("Comprueba si el cambio es legítimo (alternativas, "
                            "triggers); si no, reinstala el paquete."),
        ))
    flagged = set(critical_changes) | set(lib_changes)
    other_changes = [c for c in modified if c not in flagged]
    if other_changes:
        r.findings.append(Finding(
            "LOW", "integrity",
            f"{len(other_changes)} archivos difieren de su paquete (no binarios críticos)",
            detail="\n".join(f"{f}  {p}" for f, p in other_changes[:30]),
            recommendation="Revisa si los cambios son esperados (configuración, etc.).",
        ))
    missing_bins = [p for p in missing if p.startswith(bin_dirs)]
    if missing_bins:
        r.findings.append(Finding(
            "LOW", "integrity",
            f"{len(missing_bins)} ejecutables de paquetes ausentes",
            detail="\n".join(missing_bins[:30]),
            recommendation="Un ejecutable borrado puede ser legítimo o un intento "
                           "de ocultación; reinstala el paquete si no lo esperabas.",
        ))
    if missing:
        r.findings.append(Finding(
            "INFO", "integrity",
            f"{len(missing)} archivos de paquetes ausentes (normalmente documentación excluida)",
        ))
    if not modified and not missing:
        r.findings.append(Finding(
            "INFO", "integrity",
            "Todos los archivos coinciden con sus paquetes (sin manipulación)"))
    return r


def check_rootkit() -> CheckResult:
    """Comprobaciones heurísticas de indicadores de rootkit (al estilo de
    chkrootkit/rkhunter, en versión ligera y solo de lectura)."""
    r = CheckResult("rootkit")

    # 1) /etc/ld.so.preload — vector clásico de inyección de librerías
    preload = read_text("/etc/ld.so.preload")
    if preload and preload.strip():
        r.findings.append(Finding(
            "CRITICAL", "rootkit",
            "/etc/ld.so.preload existe y no está vacío",
            detail=preload.strip(),
            recommendation=("Este archivo fuerza la carga de librerías en todos "
                            "los procesos; es un mecanismo habitual de rootkits "
                            "de userland. Verifica cada entrada."),
        ))

    # 2) Variable de entorno LD_PRELOAD global en /etc/environment
    env = read_text("/etc/environment") or ""
    if "LD_PRELOAD" in env:
        r.findings.append(Finding(
            "HIGH", "rootkit", "LD_PRELOAD definido en /etc/environment",
            detail=next((l for l in env.splitlines() if "LD_PRELOAD" in l), ""),
            recommendation="Confirma que esa precarga de librería sea legítima.",
        ))

    # 3) Rutas/archivos asociados a rootkits conocidos
    known_paths = [
        "/dev/.hidden", "/dev/.lib", "/dev/.golf", "/usr/share/.aPa",
        "/etc/rc.d/init.d/rc.modules", "/lib/.so", "/usr/bin/.etc",
        "/usr/sbin/.../", "/tmp/.../", "/dev/shm/.X11-unix/.t",
    ]
    hits = [p for p in known_paths if os.path.exists(p)]
    if hits:
        r.findings.append(Finding(
            "HIGH", "rootkit",
            "Rutas asociadas a rootkits conocidos presentes",
            detail="\n".join(hits),
            recommendation="Investiga estos archivos; analiza con rkhunter/chkrootkit.",
        ))

    # 4) Procesos ocultos: PIDs en /proc que 'ps' no muestra (necesita root).
    #    Se hace DOBLE muestreo para descartar procesos efímeros (que nacen y
    #    mueren entre la lectura de /proc y la de 'ps') y evitar falsos positivos.
    if is_root() and have("ps"):
        def _snapshot() -> tuple[set[int], set[int]]:
            rc, out, _ = run(["ps", "-eo", "pid", "--no-headers"])
            ps_pids = {int(x) for x in out.split() if x.isdigit()} if rc == 0 else set()
            proc_pids = {int(n) for n in os.listdir("/proc") if n.isdigit()}
            return ps_pids, proc_pids

        ps1, proc1 = _snapshot()
        # Candidatos: en /proc pero no en ps, en la primera toma.
        candidates = {p for p in proc1 - ps1 if p > 1}
        if candidates:
            time.sleep(0.3)
            ps2, proc2 = _snapshot()
            # Un proceso REALMENTE oculto sigue vivo en /proc en la 2ª toma y
            # continúa ausente de 'ps' en ambas. Los efímeros se descartan solos.
            hidden = sorted(
                p for p in candidates
                if p in proc2 and p not in ps2 and os.path.isdir(f"/proc/{p}")
            )
            if hidden:
                detail_lines = []
                for p in hidden[:15]:
                    exe = ""
                    try:
                        exe = os.readlink(f"/proc/{p}/exe")
                    except OSError:
                        pass
                    detail_lines.append(f"PID {p}  {exe}")
                r.findings.append(Finding(
                    "CRITICAL", "rootkit",
                    f"{len(hidden)} procesos en /proc ocultos a 'ps'",
                    detail="\n".join(detail_lines),
                    recommendation=("Posible rootkit ocultando procesos. "
                                    "Investiga con herramientas dedicadas."),
                ))

    # 5) Interfaces de red en modo promiscuo (posible sniffer)
    if have("ip"):
        rc, out, _ = run(["ip", "link"])
        if rc == 0:
            promisc = re.findall(r"\d+:\s+(\S+):.*PROMISC", out)
            if promisc:
                r.findings.append(Finding(
                    "MEDIUM", "rootkit",
                    "Interfaces de red en modo promiscuo",
                    detail=", ".join(promisc),
                    recommendation=("El modo promiscuo permite capturar tráfico; "
                                    "confírmalo si no usas un sniffer legítimo."),
                ))

    # 6) Módulos de kernel ocultos. 'lsmod' solo lee /proc/modules, así que
    #    compararlos entre sí no detecta nada. Lo útil es cruzar dos vistas
    #    distintas del kernel: los módulos cargables registrados en sysfs
    #    (/sys/module/X/initstate) frente a la lista de /proc/modules. Muchos
    #    rootkits LKM se borran de la lista pero no de sysfs (o viceversa).
    proc_mods = read_text("/proc/modules")
    if proc_mods is not None and os.path.isdir("/sys/module"):
        proc_names = {l.split()[0] for l in proc_mods.splitlines() if l.split()}
        sys_names = set()
        try:
            for name in os.listdir("/sys/module"):
                if os.path.exists(f"/sys/module/{name}/initstate"):
                    sys_names.add(name)
        except OSError:
            pass
        hidden_mods = sys_names - proc_names
        if hidden_mods:
            r.findings.append(Finding(
                "HIGH", "rootkit",
                "Módulos de kernel en /sys/module pero ausentes de /proc/modules",
                detail=", ".join(sorted(hidden_mods)),
                recommendation=("Discrepancia sospechosa; posible módulo oculto. "
                                "Analiza con herramientas dedicadas (p.ej. "
                                "un arranque desde medio externo)."),
            ))

    if not r.findings:
        r.findings.append(Finding(
            "INFO", "rootkit", "Sin indicadores de rootkit en las comprobaciones rápidas"))
    return r


def check_baseline() -> CheckResult:
    """Puntuación de hardening alineada con buenas prácticas tipo CIS.
    Cada control suma a una puntuación global expresada en porcentaje."""
    r = CheckResult("baseline")
    controls: list[tuple[str, bool, str]] = []  # (descripción, cumple, recomendación)

    # 1) ASLR al máximo
    aslr = (read_text("/proc/sys/kernel/randomize_va_space") or "").strip()
    controls.append(("ASLR al máximo (randomize_va_space=2)", aslr == "2",
                     "Activa: kernel.randomize_va_space = 2"))

    # 2) Core dumps deshabilitados para SUID
    suid_dump = (read_text("/proc/sys/fs/suid_dumpable") or "").strip()
    controls.append(("Volcados de núcleo SUID deshabilitados (suid_dumpable=0)",
                     suid_dump == "0", "Pon fs.suid_dumpable = 0"))

    # 3) Política de antigüedad de contraseñas en /etc/login.defs
    logindefs = read_text("/etc/login.defs") or ""
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", logindefs, re.M)
    pass_max_ok = bool(m and int(m.group(1)) <= 365)
    controls.append(("Caducidad de contraseña configurada (PASS_MAX_DAYS<=365)",
                     pass_max_ok, "Define PASS_MAX_DAYS en /etc/login.defs"))

    m2 = re.search(r"^\s*PASS_MIN_DAYS\s+(\d+)", logindefs, re.M)
    controls.append(("Antigüedad mínima de contraseña (PASS_MIN_DAYS>=1)",
                     bool(m2 and int(m2.group(1)) >= 1),
                     "Define PASS_MIN_DAYS >= 1"))

    # 4) umask restrictivo por defecto
    umask_ok = bool(re.search(r"^\s*UMASK\s+0?2[27]", logindefs, re.M))
    controls.append(("umask por defecto restrictivo (027/022)", umask_ok,
                     "Define UMASK 027 en /etc/login.defs"))

    # 5) cifrado de contraseñas con SHA-512 o yescrypt
    enc = re.search(r"^\s*ENCRYPT_METHOD\s+(\S+)", logindefs, re.M)
    enc_ok = bool(enc and enc.group(1).upper() in ("SHA512", "YESCRYPT"))
    controls.append(("Hash de contraseñas fuerte (SHA512/yescrypt)", enc_ok,
                     "Define ENCRYPT_METHOD YESCRYPT"))

    # 6) Existe un firewall (reutiliza la lógica simple)
    fw = (have("ufw") or have("firewall-cmd") or have("nft") or have("iptables"))
    controls.append(("Herramienta de firewall instalada", fw,
                     "Instala y configura un firewall"))

    # 7) Cuenta root con shell pero sin login directo SSH ya cubierto; aquí:
    #    comprobar que no hay cuentas con UID 0 extra
    uid0_extra = [u.pw_name for u in pwd.getpwall()
                  if u.pw_uid == 0 and u.pw_name != "root"]
    controls.append(("Solo root tiene UID 0", not uid0_extra,
                     "Elimina cuentas UID 0 no autorizadas"))

    # 8) /tmp con opción noexec (dificulta ejecución de payloads)
    mounts = read_text("/proc/mounts") or ""
    # Compara el punto de montaje exacto (antes '/var/tmp' o '/tmp/x' contaban).
    tmp_noexec = any(
        len(p) >= 4 and p[1] == "/tmp" and "noexec" in p[3].split(",")
        for p in (l.split() for l in mounts.splitlines()))
    controls.append(("/tmp montado con noexec", tmp_noexec,
                     "Monta /tmp con noexec,nosuid,nodev"))

    # 9) SYN cookies activas
    syn = (read_text("/proc/sys/net/ipv4/tcp_syncookies") or "").strip()
    controls.append(("Protección SYN cookies activa", syn == "1",
                     "Pon net.ipv4.tcp_syncookies = 1"))

    # 10) Auditd instalado (registro de auditoría)
    controls.append(("Subsistema de auditoría (auditd) presente",
                     have("auditctl") or os.path.exists("/sbin/auditd"),
                     "Instala y habilita auditd"))

    passed = sum(1 for _, ok, _ in controls if ok)
    total = len(controls)
    score = round(100 * passed / total)

    # Severidad del hallazgo global según la puntuación
    if score >= 80:
        sev = "INFO"
    elif score >= 60:
        sev = "LOW"
    elif score >= 40:
        sev = "MEDIUM"
    else:
        sev = "HIGH"

    failed = [(d, rec) for d, ok, rec in controls if not ok]
    detail = f"Controles superados: {passed}/{total}\n"
    if failed:
        detail += "Pendientes:\n" + "\n".join(f"  ✗ {d}" for d, _ in failed)
    r.findings.append(Finding(
        sev, "baseline",
        f"Puntuación de hardening: {score}% ({passed}/{total} controles)",
        detail=detail,
        recommendation=("; ".join(rec for _, rec in failed[:4])
                        if failed else "Buen nivel de hardening base."),
    ))
    # Añadir cada control fallido como hallazgo de bajo nivel para el informe
    for d, rec in failed:
        r.findings.append(Finding(
            "LOW", "baseline", f"Control CIS no superado: {d}",
            recommendation=rec,
        ))
    return r


def check_sudoers() -> CheckResult:
    """Revisa la configuración de sudo: permisos de los ficheros y reglas
    permisivas (NOPASSWD) que faciliten escalado de privilegios."""
    r = CheckResult("sudoers")
    files = ["/etc/sudoers"]
    d = "/etc/sudoers.d"
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f in ("README", "README.md"):
                continue
            files.append(os.path.join(d, f))

    read_any = False
    for path in files:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        # sudoers debe ser 0440 y propiedad de root; escribible por grupo/otros
        # es muy grave (cualquiera podría darse permisos de root).
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            r.findings.append(Finding(
                "CRITICAL", "sudoers",
                f"Fichero sudoers escribible por grupo/otros: {path}",
                detail=f"Permisos actuales: {oct(mode)}",
                recommendation=f"Restringe de inmediato: sudo chmod 440 {path}",
            ))
        content = read_text(path)
        if content is None:
            continue
        read_any = True
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("Defaults"):
                continue
            if "NOPASSWD" in line:
                r.findings.append(Finding(
                    "MEDIUM", "sudoers",
                    "Regla sudo sin contraseña (NOPASSWD)",
                    detail=f"{os.path.basename(path)}: {line}",
                    recommendation=("Evita NOPASSWD salvo que sea imprescindible; "
                                    "exige contraseña para usar sudo."),
                ))

    if not read_any and not is_root():
        r.skipped = "No se pudo leer la configuración de sudo (ejecuta con sudo)."
        return r
    if not r.findings:
        r.findings.append(Finding(
            "INFO", "sudoers", "Configuración de sudo sin hallazgos relevantes"))
    return r


def check_capabilities() -> CheckResult:
    """Igual que SUID, las file capabilities pueden conceder privilegios.
    Detecta binarios con capabilities sensibles (cap_setuid, cap_sys_admin...)."""
    r = CheckResult("caps")
    if not have("getcap"):
        r.skipped = "Comando 'getcap' no disponible (paquete libcap2-bin)."
        return r
    dirs = [d for d in ("/usr/bin", "/usr/sbin", "/bin", "/sbin",
                        "/usr/local/bin", "/usr/local/sbin") if os.path.isdir(d)]
    rc, out, _ = run(["getcap", "-r", *dirs], timeout=60)
    risky = ("cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
             "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_net_admin",
             "cap_chown", "cap_fowner", "cap_sys_rawio")
    all_caps, flagged = [], []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        all_caps.append(ln)
        low = ln.lower()
        if any(c in low for c in risky):
            flagged.append(ln)

    if flagged:
        r.findings.append(Finding(
            "HIGH", "caps",
            "Binarios con file capabilities potencialmente peligrosas",
            detail="\n".join(flagged),
            recommendation=("Pueden permitir escalado de privilegios igual que "
                            "SUID. Si no son necesarias: sudo setcap -r ARCHIVO"),
        ))
    if all_caps:
        r.findings.append(Finding(
            "INFO", "caps", f"{len(all_caps)} binarios con file capabilities",
            detail="\n".join(all_caps)))
    else:
        r.findings.append(Finding(
            "INFO", "caps", "Sin binarios con file capabilities"))
    return r


def check_private_keys() -> CheckResult:
    """Comprueba que las claves privadas (SSH de host y de usuario, TLS) no
    sean legibles/escribibles por grupo u otros."""
    r = CheckResult("keys")
    candidates: list[str] = []

    # Claves privadas de host SSH
    if os.path.isdir("/etc/ssh"):
        for n in os.listdir("/etc/ssh"):
            if n.endswith("_key"):
                candidates.append(os.path.join("/etc/ssh", n))
    # Claves TLS del sistema
    for d in ("/etc/ssl/private", "/etc/pki/tls/private"):
        if os.path.isdir(d):
            try:
                for n in os.listdir(d):
                    candidates.append(os.path.join(d, n))
            except OSError:
                pass
    # Claves SSH privadas de cada usuario
    for u in pwd.getpwall():
        ssh_dir = os.path.join(u.pw_dir, ".ssh")
        if os.path.isdir(ssh_dir):
            try:
                for n in os.listdir(ssh_dir):
                    if n.startswith("id_") and not n.endswith(".pub"):
                        candidates.append(os.path.join(ssh_dir, n))
            except OSError:
                pass

    # Grupos que, por convenio de la distribución, pueden leer claves TLS
    # (Debian: ssl-cert con 0640 en /etc/ssl/private es lo esperado).
    trusted_key_groups = {"ssl-cert"}

    bad = []        # legible/escribible por otros o escribible por grupo
    group_read = []  # solo legible por un grupo no habitual
    for path in candidates:
        try:
            st = os.stat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        if mode & (stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            bad.append((path, oct(mode)))
        elif mode & stat.S_IRGRP:
            try:
                gname = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                gname = str(st.st_gid)
            if gname not in trusted_key_groups:
                group_read.append((path, oct(mode), gname))

    if bad:
        r.findings.append(Finding(
            "HIGH", "keys",
            f"{len(bad)} claves privadas con permisos demasiado abiertos",
            detail="\n".join(f"{p}  ({m})" for p, m in bad),
            recommendation="Restringe al propietario: chmod 600 ARCHIVO",
        ))
    if group_read:
        r.findings.append(Finding(
            "MEDIUM", "keys",
            f"{len(group_read)} claves privadas legibles por un grupo",
            detail="\n".join(f"{p}  ({m}, grupo {g})" for p, m, g in group_read),
            recommendation="Si ese grupo no necesita la clave: chmod 600 ARCHIVO",
        ))
    if not bad and not group_read:
        r.findings.append(Finding(
            "INFO", "keys",
            "Permisos de claves privadas correctos (o sin acceso de lectura)"))
    return r


def check_path_writable() -> CheckResult:
    """Un directorio world-writable (o '.') dentro del PATH permite secuestrar
    comandos legítimos: vector clásico de escalado de privilegios."""
    r = CheckResult("path")
    path_env = os.environ.get("PATH", "")
    insecure = []
    for d in path_env.split(":"):
        if d in ("", "."):
            insecure.append((d or "(vacío)", "ruta relativa / directorio actual"))
            continue
        try:
            st = os.stat(d)
        except OSError:
            continue
        if st.st_mode & stat.S_IWOTH:
            insecure.append((d, "world-writable"))

    if insecure:
        r.findings.append(Finding(
            "HIGH", "path", "Directorios inseguros en el PATH",
            detail="\n".join(f"{d}  ({why})" for d, why in insecure),
            recommendation=("Elimina del PATH cualquier directorio escribible por "
                            "todos o entradas vacías/'.'."),
        ))
    else:
        r.findings.append(Finding(
            "INFO", "path", "PATH sin directorios inseguros"))
    return r


def check_services() -> CheckResult:
    """Lista servicios systemd en estado 'failed': un servicio caído puede
    dejar protecciones sin aplicar o indicar un problema."""
    r = CheckResult("services")
    if not have("systemctl"):
        r.skipped = "systemctl no disponible (sistema sin systemd)."
        return r
    rc, out, _ = run(["systemctl", "--failed", "--no-legend", "--plain"])
    failed = [ln.split()[0] for ln in out.splitlines() if ln.strip()]
    if failed:
        r.findings.append(Finding(
            "LOW", "services", f"{len(failed)} servicios en estado 'failed'",
            detail="\n".join(failed),
            recommendation=("Revisa cada uno con: systemctl status NOMBRE"),
        ))
    else:
        r.findings.append(Finding(
            "INFO", "services", "Sin servicios systemd en estado failed"))
    return r


def check_mounts() -> CheckResult:
    """Revisa que los puntos de montaje sensibles usen opciones de hardening
    (nosuid/nodev/noexec), siguiendo recomendaciones tipo CIS."""
    r = CheckResult("mounts")
    mp: dict[str, set[str]] = {}
    for ln in (read_text("/proc/mounts") or "").splitlines():
        parts = ln.split()
        if len(parts) >= 4:
            mp[parts[1]] = set(parts[3].split(","))

    wanted = {
        "/tmp": ["nosuid", "nodev", "noexec"],
        "/var/tmp": ["nosuid", "nodev", "noexec"],
        "/dev/shm": ["nosuid", "nodev", "noexec"],
        "/home": ["nosuid", "nodev"],
        "/boot": ["nosuid", "nodev"],
    }
    for path, opts in wanted.items():
        if path not in mp:
            continue
        missing = [o for o in opts if o not in mp[path]]
        if missing:
            r.findings.append(Finding(
                "LOW", "mounts",
                f"{path} sin opciones de hardening: {', '.join(missing)}",
                detail=f"Opciones actuales: {','.join(sorted(mp[path]))}",
                recommendation=f"Añade {','.join(missing)} a {path} en /etc/fstab.",
            ))
    if "/tmp" not in mp:
        r.findings.append(Finding(
            "INFO", "mounts", "/tmp no es una partición separada",
            recommendation=("Considera /tmp en su propia partición con "
                            "noexec,nosuid,nodev."),
        ))
    if not r.findings:
        r.findings.append(Finding("INFO", "mounts", "Opciones de montaje correctas"))
    return r


def check_accounts() -> CheckResult:
    """Higiene de cuentas: UIDs duplicados, cuentas de servicio con shell
    interactivo y contraseñas sin caducidad."""
    r = CheckResult("accounts")
    users = list(pwd.getpwall())

    # 1) UIDs duplicados
    seen: dict[int, list[str]] = {}
    for u in users:
        seen.setdefault(u.pw_uid, []).append(u.pw_name)
    dup = {uid: n for uid, n in seen.items() if len(n) > 1}
    if dup:
        r.findings.append(Finding(
            "MEDIUM", "accounts", "UIDs duplicados",
            detail="\n".join(f"UID {uid}: {', '.join(n)}" for uid, n in dup.items()),
            recommendation="Cada usuario debe tener un UID único.",
        ))

    # 2) Cuentas de sistema (0<UID<1000) con shell de login interactivo
    login_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash",
                    "/usr/bin/zsh", "/bin/ksh", "/usr/bin/fish"}
    sys_login = [u.pw_name for u in users
                 if 0 < u.pw_uid < 1000 and u.pw_shell in login_shells]
    if sys_login:
        r.findings.append(Finding(
            "LOW", "accounts",
            "Cuentas de sistema con shell de login interactivo",
            detail=", ".join(sys_login),
            recommendation="Asigna /usr/sbin/nologin a las cuentas de servicio.",
        ))

    # 3) Contraseñas activas sin caducidad (requiere /etc/shadow)
    shadow = read_text("/etc/shadow")
    if shadow:
        never_expire = []
        for ln in shadow.splitlines():
            parts = ln.split(":")
            if len(parts) < 5:
                continue
            name, pw, maxdays = parts[0], parts[1], parts[4]
            if pw and pw[0] not in "!*" and maxdays in ("", "99999"):
                never_expire.append(name)
        if never_expire:
            r.findings.append(Finding(
                "LOW", "accounts", "Cuentas con contraseña sin caducidad",
                detail=", ".join(never_expire),
                recommendation="Configura caducidad: sudo chage -M 365 USUARIO.",
            ))

    if not r.findings:
        r.findings.append(Finding("INFO", "accounts", "Higiene de cuentas correcta"))
    return r


def check_docker() -> CheckResult:
    """Comprueba la superficie de ataque de Docker: permisos del socket y
    miembros del grupo 'docker' (equivalente a root)."""
    r = CheckResult("docker")
    sock = "/var/run/docker.sock"
    present = os.path.exists(sock)
    if present:
        try:
            st = os.stat(sock)
            mode = stat.S_IMODE(st.st_mode)
            if st.st_mode & (stat.S_IROTH | stat.S_IWOTH):
                r.findings.append(Finding(
                    "HIGH", "docker",
                    "Socket de Docker accesible por 'otros'",
                    detail=f"{sock} permisos {oct(mode)}",
                    recommendation=("Acceso al socket equivale a root. Restringe "
                                    "permisos y limita el grupo 'docker'."),
                ))
        except OSError:
            pass

    try:
        members = grp.getgrnam("docker").gr_mem
        if members:
            r.findings.append(Finding(
                "MEDIUM", "docker",
                "Usuarios en el grupo 'docker' (equivale a root)",
                detail=", ".join(members),
                recommendation=("Pertenecer a 'docker' permite escalar a root; "
                                "limita la membresía a lo imprescindible."),
            ))
    except KeyError:
        pass

    if not present and not r.findings:
        r.skipped = "Docker no detectado (sin /var/run/docker.sock)."
        return r
    if not r.findings:
        r.findings.append(Finding(
            "INFO", "docker", "Configuración de Docker sin hallazgos relevantes"))
    return r


def check_modprobe() -> CheckResult:
    """Verifica que sistemas de archivos y protocolos de red poco usados estén
    deshabilitados vía modprobe (control habitual en CIS)."""
    r = CheckResult("modprobe")
    risky = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf",
             "usb-storage", "dccp", "sctp", "rds", "tipc"]
    config = ""
    for d in ("/etc/modprobe.d", "/usr/lib/modprobe.d", "/run/modprobe.d"):
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    if f.endswith(".conf"):
                        config += (read_text(os.path.join(d, f)) or "") + "\n"
            except OSError:
                pass

    not_disabled = []
    for mod in risky:
        disabled = (
            re.search(rf"^\s*install\s+{re.escape(mod)}\s+/bin/(true|false)",
                      config, re.M)
            or re.search(rf"^\s*blacklist\s+{re.escape(mod)}\b", config, re.M)
        )
        if not disabled:
            not_disabled.append(mod)

    if not_disabled:
        r.findings.append(Finding(
            "LOW", "modprobe",
            f"{len(not_disabled)} módulos poco usados no deshabilitados",
            detail=", ".join(not_disabled),
            recommendation=("Si no se usan, deshabilítalos en /etc/modprobe.d/: "
                            "'install MODULO /bin/false'."),
        ))
    else:
        r.findings.append(Finding(
            "INFO", "modprobe", "Módulos poco usados deshabilitados"))
    return r


def check_coredump() -> CheckResult:
    """Revisa la configuración de volcados de núcleo (core dumps), que pueden
    filtrar memoria sensible si no se restringen."""
    r = CheckResult("coredump")
    suid_dump = (read_text("/proc/sys/fs/suid_dumpable") or "").strip()
    if suid_dump and suid_dump != "0":
        r.findings.append(Finding(
            "MEDIUM", "coredump",
            f"Volcados de SUID habilitados (suid_dumpable={suid_dump})",
            recommendation="Pon fs.suid_dumpable = 0.",
        ))

    limits = read_text("/etc/security/limits.conf") or ""
    if not re.search(r"^\s*\*\s+hard\s+core\s+0", limits, re.M):
        r.findings.append(Finding(
            "LOW", "coredump",
            "Sin límite 'hard core 0' en limits.conf",
            recommendation="Añade '* hard core 0' para desactivar core dumps.",
        ))

    cp = (read_text("/proc/sys/kernel/core_pattern") or "").strip()
    if cp.startswith("|"):
        r.findings.append(Finding(
            "INFO", "coredump", "core_pattern canaliza a un gestor externo",
            detail=cp,
        ))

    if not r.findings:
        r.findings.append(Finding(
            "INFO", "coredump", "Configuración de core dumps correcta"))
    return r


# Registro de todos los módulos disponibles
ALL_CHECKS: dict[str, Callable[[], CheckResult]] = {
    "system": check_system_info,
    "updates": check_updates,
    "users": check_users,
    "accounts": check_accounts,
    "ssh": check_ssh,
    "firewall": check_firewall,
    "ports": check_listening_ports,
    "suid": check_suid,
    "caps": check_capabilities,
    "permissions": check_world_writable,
    "sensitive": check_sensitive_perms,
    "keys": check_private_keys,
    "path": check_path_writable,
    "sudoers": check_sudoers,
    "services": check_services,
    "docker": check_docker,
    "mounts": check_mounts,
    "modprobe": check_modprobe,
    "coredump": check_coredump,
    "kernel": check_sysctl,
    "cron": check_cron,
    "authlog": check_failed_logins,
    "integrity": check_integrity,
    "rootkit": check_rootkit,
    "baseline": check_baseline,
}


# --------------------------------------------------------------------------- #
# Informes
# --------------------------------------------------------------------------- #

def _run_check(name: str) -> CheckResult:
    """Ejecuta un módulo de forma aislada: un fallo nunca tumba la auditoría."""
    fn = ALL_CHECKS[name]
    try:
        return fn()
    except Exception as e:
        cr = CheckResult(name)
        cr.findings.append(Finding(
            "INFO", name, f"Error ejecutando el módulo '{name}': {e}"))
        return cr


def collect(selected: list[str], progress: bool = False,
            jobs: int = 1) -> list[CheckResult]:
    """Ejecuta los módulos seleccionados. Con jobs>1 se paralelizan mediante un
    pool de hilos (son tareas de E/S: subprocess + lecturas de /proc y ficheros),
    pero la lista devuelta respeta SIEMPRE el orden de 'selected' para que los
    informes sean deterministas."""
    total = len(selected)

    if jobs <= 1:
        results = []
        for i, name in enumerate(selected, 1):
            if progress:
                print(f"  [{i:2}/{total}] ejecutando módulo: {name} ...",
                      file=sys.stderr, flush=True)
            results.append(_run_check(name))
        return results

    results_map: dict[str, CheckResult] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futures = {ex.submit(_run_check, name): name for name in selected}
        for fut in as_completed(futures):
            name = futures[fut]
            results_map[name] = fut.result()
            done += 1
            if progress:
                print(f"  [{done:2}/{total}] completado: {name}",
                      file=sys.stderr, flush=True)
    # Reordenar según 'selected' (as_completed devuelve en orden de finalización).
    return [results_map[name] for name in selected]


def all_findings(results: list[CheckResult]) -> list[Finding]:
    out = []
    for r in results:
        out.extend(r.findings)
    out.sort(key=lambda f: SEV_ORDER[f.severity])
    return out


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def print_console(results: list[CheckResult], use_color: bool) -> None:
    def c(text: str, key: str) -> str:
        if not use_color:
            return text
        return f"{COLORS.get(key, '')}{text}{COLORS['RESET']}"

    findings = all_findings(results)
    counts = severity_counts(findings)

    print()
    print(c("=" * 70, "BOLD"))
    print(c("  AUDITORÍA DE SEGURIDAD — secaudit", "BOLD"))
    print(c("=" * 70, "BOLD"))
    print(f"  Fecha: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"  Ejecutado como root: {'sí' if is_root() else 'NO (cobertura parcial)'}")
    print()
    summary = "  ".join(
        c(f"{s}: {counts[s]}", s) for s in SEVERITIES if counts[s])
    print("  Resumen:  " + (summary or "sin hallazgos"))
    print(c("-" * 70, "DIM"))

    for sev in SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        for f in group:
            tag = c(f" {f.severity:8} ", f.severity)
            print(f"\n{tag} [{f.category}] {c(f.title, 'BOLD')}")
            if f.detail:
                for line in f.detail.splitlines():
                    print(f"             {c(line, 'DIM')}")
            if f.recommendation:
                print(f"             {c('→ ' + f.recommendation, 'INFO')}")

    skipped = [r for r in results if r.skipped]
    if skipped:
        print(c("\n" + "-" * 70, "DIM"))
        print(c("  Módulos omitidos:", "DIM"))
        for r in skipped:
            print(c(f"    - {r.name}: {r.skipped}", "DIM"))
    print(c("\n" + "=" * 70, "BOLD"))


# --------------------------------------------------------------------------- #
# Comparación entre auditorías (--diff)
# --------------------------------------------------------------------------- #

def results_to_report(results: list[CheckResult]) -> dict:
    """Convierte los resultados de una auditoría al mismo formato que el JSON."""
    findings = all_findings(results)
    return {
        "generated_at": datetime.datetime.now().isoformat(),
        "host": platform.node(),
        "as_root": is_root(),
        "summary": severity_counts(findings),
        "findings": [asdict(f) for f in findings],
        "skipped": {r.name: r.skipped for r in results if r.skipped},
    }


def load_report(path: str) -> dict:
    """Carga un informe JSON previo y valida que tenga el formato esperado."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if "findings" not in data or not isinstance(data["findings"], list):
        raise ValueError(f"{path} no parece un informe de secaudit válido.")
    return data


def finding_key(f: dict) -> tuple[str, str]:
    """Firma estable de un hallazgo: categoría + título con los números
    normalizados (para que '4 archivos' y '5 archivos' se consideren el mismo
    hallazgo, y el cambio se vea en el detalle, no como hallazgo nuevo)."""
    title = re.sub(r"\d+", "#", f.get("title", ""))
    return (f.get("category", ""), title)


def detail_lines(findings: list[dict]) -> set[str]:
    """Conjunto de líneas de detalle (p.ej. rutas de binarios SUID, puertos)
    agregadas de todos los hallazgos con la misma firma."""
    lines: set[str] = set()
    for f in findings:
        for ln in (f.get("detail") or "").splitlines():
            ln = ln.strip()
            # Ignorar líneas de resumen tipo "(+12 más)" que solo cuentan
            if ln and not re.match(r"^\.\.\.|^\(\+", ln):
                lines.add(ln)
    return lines


def diff_reports(base: dict, curr: dict) -> dict:
    """Compara dos informes y clasifica los cambios."""
    base_map: dict[tuple[str, str], list[dict]] = {}
    for f in base["findings"]:
        base_map.setdefault(finding_key(f), []).append(f)
    curr_map: dict[tuple[str, str], list[dict]] = {}
    for f in curr["findings"]:
        curr_map.setdefault(finding_key(f), []).append(f)

    new = [f for k, fs in curr_map.items() if k not in base_map for f in fs]
    resolved = [f for k, fs in base_map.items() if k not in curr_map for f in fs]

    changed = []
    for k in curr_map:
        if k not in base_map:
            continue
        added = detail_lines(curr_map[k]) - detail_lines(base_map[k])
        removed = detail_lines(base_map[k]) - detail_lines(curr_map[k])
        if added or removed:
            changed.append({
                "category": curr_map[k][0].get("category", ""),
                "title": curr_map[k][0].get("title", ""),
                "severity": curr_map[k][0].get("severity", "INFO"),
                "added": sorted(added),
                "removed": sorted(removed),
            })

    new.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99))
    return {
        "base_date": base.get("generated_at", "?"),
        "curr_date": curr.get("generated_at", "?"),
        "new": new,
        "resolved": resolved,
        "changed": changed,
    }


# Módulos cuyos elementos NUEVOS son siempre motivo de alerta, aunque el
# hallazgo que los contiene sea informativo. Un binario SUID, una capability o
# un puerto expuesto que antes no existían son indicadores clásicos de
# persistencia o de escalada, aunque el binario no esté en la lista GTFOBins.
WATCHED_CATEGORIES = {"suid", "caps", "ports", "keys", "path", "sudoers", "cron"}


def is_alert(category: str, severity: str, new_item: bool) -> bool:
    """Decide si un cambio respecto a la base merece alerta.
    - Siempre: severidad CRITICAL/HIGH.
    - En módulos vigilados: cualquier elemento nuevo dentro de un hallazgo, o
      un hallazgo nuevo que no sea puramente informativo."""
    if severity in ("CRITICAL", "HIGH"):
        return True
    if category in WATCHED_CATEGORIES:
        return new_item or severity != "INFO"
    return False


def count_alerts(diff: dict) -> int:
    """Número de novedades que merecen alerta (base del código de salida)."""
    n = 0
    for f in diff["new"]:
        if is_alert(f.get("category", ""), f.get("severity", "INFO"), False):
            n += 1
    for ch in diff["changed"]:
        if is_alert(ch.get("category", ""), ch.get("severity", "INFO"), True):
            n += len(ch["added"])
    return n


def print_diff_console(diff: dict, use_color: bool) -> int:
    """Imprime el diff. Devuelve el número de novedades que merecen alerta."""
    def c(text: str, key: str) -> str:
        return f"{COLORS.get(key, '')}{text}{COLORS['RESET']}" if use_color else text

    print()
    print(c("=" * 70, "BOLD"))
    print(c("  COMPARACIÓN DE AUDITORÍAS — secaudit --diff", "BOLD"))
    print(c("=" * 70, "BOLD"))
    print(f"  Base:   {diff['base_date']}")
    print(f"  Actual: {diff['curr_date']}")
    print(c("-" * 70, "DIM"))

    high_new = count_alerts(diff)

    # --- NOVEDADES (lo más importante para detectar compromisos) ---
    if diff["new"]:
        print(c("\n  ⚠ HALLAZGOS NUEVOS (no estaban en la base)", "BOLD"))
        for f in diff["new"]:
            sev = f.get("severity", "INFO")
            tag = c(f" {sev:8} ", sev)
            print(f"  {tag} [{f.get('category')}] {c('+ ' + f.get('title', ''), 'BOLD')}")
            for line in (f.get("detail") or "").splitlines()[:6]:
                print(f"               {c(line.strip(), 'DIM')}")
    else:
        print(c("\n  ✓ Sin hallazgos nuevos.", "INFO"))

    # --- CAMBIOS DENTRO DE HALLAZGOS EXISTENTES (nuevos items) ---
    item_changes = [ch for ch in diff["changed"] if ch["added"]]
    if item_changes:
        print(c("\n  ⚠ ELEMENTOS NUEVOS dentro de hallazgos existentes", "BOLD"))
        print(c("    (p.ej. binario SUID, puerto o archivo que apareció)", "DIM"))
        for ch in item_changes:
            print(f"\n  {c('[' + ch['category'] + ']', 'BOLD')} {ch['title']}")
            for ln in ch["added"][:15]:
                print(f"      {c('+ ' + ln, 'HIGH')}")
            extra = len(ch["added"]) - 15
            if extra > 0:
                print("      " + c(f"... (+{extra} más)", "DIM"))

    # --- RESUELTOS / DESAPARECIDOS ---
    if diff["resolved"]:
        print(c("\n  ✓ HALLAZGOS RESUELTOS (ya no aparecen)", "INFO"))
        for f in diff["resolved"]:
            print(f"      {c('- ' + f.get('category', '') + ': ' + f.get('title', ''), 'DIM')}")

    removed_items = [ch for ch in diff["changed"] if ch["removed"]]
    if removed_items:
        print(c("\n  · Elementos que desaparecieron de hallazgos existentes", "DIM"))
        for ch in removed_items:
            for ln in ch["removed"][:10]:
                print(f"      {c('- ' + ln, 'DIM')}")

    print(c("\n" + "-" * 70, "DIM"))
    if high_new:
        print(c(f"  ⚠ ATENCIÓN: {high_new} novedad(es) que requieren revisión "
                "(severidad alta o cambios en módulos vigilados).", "HIGH"))
    else:
        print(c("  Sin novedades que requieran alerta.", "INFO"))
    print(c("=" * 70, "BOLD"))
    return high_new


def write_json(results: list[CheckResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results_to_report(results), fh, indent=2, ensure_ascii=False)


def write_html(results: list[CheckResult], path: str) -> None:
    findings = all_findings(results)
    counts = severity_counts(findings)
    sev_color = {
        "CRITICAL": "#7f1d1d", "HIGH": "#dc2626", "MEDIUM": "#d97706",
        "LOW": "#0891b2", "INFO": "#16a34a",
    }

    def esc(s: str) -> str:
        return html.escape(s).replace("\n", "<br>")

    rows = []
    for f in findings:
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{sev_color[f.severity]}">{f.severity}</span></td>
          <td class="cat">{esc(f.category)}</td>
          <td>
            <div class="title">{esc(f.title)}</div>
            {f'<div class="detail">{esc(f.detail)}</div>' if f.detail else ''}
            {f'<div class="rec">→ {esc(f.recommendation)}</div>' if f.recommendation else ''}
          </td>
        </tr>""")

    chips = "".join(
        f'<span class="chip" style="background:{sev_color[s]}">{s}: {counts[s]}</span>'
        for s in SEVERITIES if counts[s])

    skipped_html = ""
    sk = [r for r in results if r.skipped]
    if sk:
        items = "".join(f"<li><b>{esc(r.name)}</b>: {esc(r.skipped or '')}</li>" for r in sk)
        skipped_html = f'<div class="skipped"><h3>Módulos omitidos</h3><ul>{items}</ul></div>'

    doc = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de auditoría — secaudit</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background:#0f172a; color:#e2e8f0; }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 4px; }}
  .meta {{ color:#94a3b8; font-size:.9rem; margin-bottom:20px; }}
  .chips {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:24px; }}
  .chip {{ color:#fff; padding:4px 12px; border-radius:999px; font-size:.8rem; font-weight:600; }}
  table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:12px; overflow:hidden; }}
  td {{ padding:14px 16px; vertical-align:top; border-top:1px solid #334155; }}
  td:first-child {{ width:96px; }}
  .badge {{ color:#fff; padding:3px 8px; border-radius:6px; font-size:.72rem; font-weight:700; }}
  .cat {{ color:#94a3b8; font-size:.85rem; }}
  .title {{ font-weight:600; }}
  .detail {{ color:#94a3b8; font-size:.85rem; margin-top:4px; font-family:ui-monospace,monospace; white-space:pre-wrap; }}
  .rec {{ color:#4ade80; font-size:.85rem; margin-top:6px; }}
  .skipped {{ margin-top:28px; color:#94a3b8; font-size:.85rem; }}
  footer {{ margin-top:32px; color:#64748b; font-size:.78rem; }}
</style></head><body><div class="wrap">
  <h1>Informe de auditoría de seguridad</h1>
  <div class="meta">Host: {esc(platform.node())} &middot;
    {datetime.datetime.now():%Y-%m-%d %H:%M:%S} &middot;
    {'ejecutado como root' if is_root() else 'cobertura parcial (sin root)'}</div>
  <div class="chips">{chips or '<span class="chip" style="background:#16a34a">Sin hallazgos</span>'}</div>
  <table><tbody>{''.join(rows)}</tbody></table>
  {skipped_html}
  <footer>Generado por secaudit — herramienta de auditoría defensiva. Solo lectura del estado del sistema.</footer>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def write_txt(results: list[CheckResult], path: str) -> None:
    """Escribe el informe en texto plano (sin colores ANSI), apto para
    guardar, enviar por correo o abrir en cualquier editor."""
    findings = all_findings(results)
    counts = severity_counts(findings)

    lines: list[str] = []
    add = lines.append

    add("=" * 70)
    add("  AUDITORÍA DE SEGURIDAD — secaudit")
    add("=" * 70)
    add(f"  Fecha: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    add(f"  Host:  {platform.node()}")
    add(f"  Ejecutado como root: {'sí' if is_root() else 'NO (cobertura parcial)'}")
    add("")
    summary = "  ".join(f"{s}: {counts[s]}" for s in SEVERITIES if counts[s])
    add("  Resumen:  " + (summary or "sin hallazgos"))
    add("-" * 70)

    for sev in SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        for f in group:
            add("")
            add(f"  [{f.severity:8}] [{f.category}] {f.title}")
            if f.detail:
                for line in f.detail.splitlines():
                    add(f"             {line}")
            if f.recommendation:
                add(f"             -> {f.recommendation}")

    skipped = [r for r in results if r.skipped]
    if skipped:
        add("")
        add("-" * 70)
        add("  Módulos omitidos:")
        for r in skipped:
            add(f"    - {r.name}: {r.skipped}")

    add("")
    add("=" * 70)
    add("  Generado por secaudit — auditoría defensiva (solo lectura).")
    add("=" * 70)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_md(results: list[CheckResult], path: str) -> None:
    """Escribe el informe en Markdown, ideal para pegar en un repo, ticket o
    wiki. Agrupa por severidad y usa bloques de código para los detalles."""
    findings = all_findings(results)
    counts = severity_counts(findings)

    out: list[str] = []
    out.append("# Informe de auditoría de seguridad — secaudit")
    out.append("")
    out.append(f"- **Host:** {platform.node()}")
    out.append(f"- **Fecha:** {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    out.append(f"- **Ejecutado como root:** "
               f"{'sí' if is_root() else 'no (cobertura parcial)'}")
    summary = " · ".join(f"{s}: {counts[s]}" for s in SEVERITIES if counts[s])
    out.append(f"- **Resumen:** {summary or 'sin hallazgos'}")
    out.append("")

    for sev in SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        out.append(f"## {sev} ({len(group)})")
        out.append("")
        for f in group:
            out.append(f"### `[{f.category}]` {f.title}")
            if f.detail:
                out.append("")
                out.append("```")
                out.append(f.detail)
                out.append("```")
            if f.recommendation:
                out.append("")
                out.append(f"> **Recomendación:** {f.recommendation}")
            out.append("")

    sk = [r for r in results if r.skipped]
    if sk:
        out.append("## Módulos omitidos")
        out.append("")
        for r in sk:
            out.append(f"- **{r.name}:** {r.skipped}")
        out.append("")

    out.append("---")
    out.append("*Generado por secaudit — auditoría defensiva (solo lectura).*")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Auditor de seguridad defensiva para Linux (solo lectura).")
    parser.add_argument("--html", metavar="ARCHIVO", help="Exporta informe HTML.")
    parser.add_argument("--json", metavar="ARCHIVO", help="Exporta informe JSON.")
    parser.add_argument("--txt", metavar="ARCHIVO",
                        help="Exporta informe en texto plano (.txt).")
    parser.add_argument("--md", metavar="ARCHIVO",
                        help="Exporta informe en Markdown (.md).")
    parser.add_argument("--only", metavar="m1,m2",
                        help="Ejecuta solo estos módulos (separados por comas).")
    parser.add_argument("--min-severity", metavar="NIVEL", choices=SEVERITIES,
                        help="Muestra solo hallazgos de esta severidad o "
                             "superior (CRITICAL, HIGH, MEDIUM, LOW, INFO).")
    parser.add_argument("--list", action="store_true",
                        help="Lista los módulos disponibles y sale.")
    parser.add_argument("--diff", metavar="BASE.json",
                        help="Ejecuta una auditoría nueva y la compara con un "
                             "informe JSON previo (línea base), mostrando qué "
                             "apareció, cambió o se resolvió.")
    parser.add_argument("--quiet", action="store_true",
                        help="No muestra el progreso de los módulos por stderr.")
    parser.add_argument("--jobs", "-j", metavar="N", type=int, default=0,
                        help="Número de módulos a ejecutar en paralelo. "
                             "0 = automático; 1 = secuencial.")
    parser.add_argument("--no-color", action="store_true",
                        help="Desactiva colores en consola.")
    parser.add_argument("--version", action="version",
                        version=f"secaudit {__version__}")
    args = parser.parse_args(argv)

    if args.list:
        print("Módulos disponibles:")
        for name in ALL_CHECKS:
            print(f"  - {name}")
        return 0

    if args.only:
        selected = [m.strip() for m in args.only.split(",") if m.strip()]
        unknown = [m for m in selected if m not in ALL_CHECKS]
        if unknown:
            print(f"Módulos desconocidos: {', '.join(unknown)}", file=sys.stderr)
            print("Usa --list para ver los disponibles.", file=sys.stderr)
            return 2
    else:
        selected = list(ALL_CHECKS.keys())

    if not is_root():
        print("[aviso] No se ejecuta como root: algunas comprobaciones tendrán "
              "cobertura parcial. Para un análisis completo, ejecútalo con sudo.",
              file=sys.stderr)

    # Nivel de paralelismo: 0 = automático (acotado, son tareas de E/S).
    if args.jobs and args.jobs > 0:
        jobs = args.jobs
    else:
        jobs = min(8, max(1, len(selected)))

    results = collect(selected, progress=not args.quiet, jobs=jobs)

    # Modo comparación: ejecuta auditoría y la contrasta con una base previa.
    # (El filtro --min-severity no se aplica aquí para no falsear el diff.)
    if args.diff:
        try:
            base = load_report(args.diff)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"[error] No se pudo cargar la base '{args.diff}': {e}",
                  file=sys.stderr)
            return 2
        curr = results_to_report(results)
        diff = diff_reports(base, curr)
        use_color = (not args.no_color) and sys.stdout.isatty()
        high_new = print_diff_console(diff, use_color)

        if args.json:
            write_json(results, args.json)
            print(f"[ok] Nueva instantánea guardada en {args.json}")
        if args.html:
            write_html(results, args.html)
            print(f"[ok] Informe HTML escrito en {args.html}")
        if args.txt:
            write_txt(results, args.txt)
            print(f"[ok] Informe TXT escrito en {args.txt}")
        if args.md:
            write_md(results, args.md)
            print(f"[ok] Informe Markdown escrito en {args.md}")

        # Código de salida 1 si hay novedades de severidad alta/crítica.
        return 1 if high_new else 0

    # El código de salida refleja el riesgo REAL, antes de aplicar filtros.
    counts_full = severity_counts(all_findings(results))

    # Filtro de severidad (solo afecta a lo que se muestra/exporta).
    if args.min_severity:
        thr = SEV_ORDER[args.min_severity]
        for r in results:
            r.findings = [f for f in r.findings if SEV_ORDER[f.severity] <= thr]

    use_color = (not args.no_color) and sys.stdout.isatty()
    print_console(results, use_color)

    if args.json:
        write_json(results, args.json)
        print(f"[ok] Informe JSON escrito en {args.json}")
    if args.html:
        write_html(results, args.html)
        print(f"[ok] Informe HTML escrito en {args.html}")
    if args.txt:
        write_txt(results, args.txt)
        print(f"[ok] Informe TXT escrito en {args.txt}")
    if args.md:
        write_md(results, args.md)
        print(f"[ok] Informe Markdown escrito en {args.md}")

    # Código de salida: 1 si hay hallazgos CRITICAL/HIGH, 0 en caso contrario.
    return 1 if (counts_full["CRITICAL"] or counts_full["HIGH"]) else 0


def cli() -> None:
    """Punto de entrada del comando 'secaudit' instalado con pip."""
    sys.exit(main())


if __name__ == "__main__":
    cli()