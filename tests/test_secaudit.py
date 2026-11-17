"""Tests de secaudit. Se centran en la lógica pura (parseo, diff, alertas y
exportación), que es lo que se puede verificar sin depender del sistema."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secaudit as sa  # noqa: E402


# --------------------------------------------------------------------------- #
# Modelo
# --------------------------------------------------------------------------- #

def test_finding_rechaza_severidad_invalida():
    with pytest.raises(ValueError):
        sa.Finding("URGENTE", "x", "titulo")


def test_todos_los_modulos_registrados_son_invocables():
    assert len(sa.ALL_CHECKS) >= 25
    assert all(callable(fn) for fn in sa.ALL_CHECKS.values())


# --------------------------------------------------------------------------- #
# Parseo de sshd_config
# --------------------------------------------------------------------------- #

def test_sshd_primera_aparicion_gana(tmp_path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("PermitRootLogin no\nPermitRootLogin yes\n")
    assert sa.parse_sshd_config(str(cfg))["permitrootlogin"] == "no"


def test_sshd_sigue_includes_antes_que_el_resto(tmp_path):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "50-cloud.conf").write_text("PasswordAuthentication yes\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"Include {d}/*.conf\nPasswordAuthentication no\n")
    # Como en Debian/Ubuntu: el drop-in incluido al principio manda.
    assert sa.parse_sshd_config(str(cfg))["passwordauthentication"] == "yes"


def test_sshd_ignora_bloques_match_y_comentarios(tmp_path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("# PermitRootLogin yes\nX11Forwarding no\n"
                   "Match User backup\n    X11Forwarding yes\n")
    vals = sa.parse_sshd_config(str(cfg))
    assert "permitrootlogin" not in vals
    assert vals["x11forwarding"] == "no"


# --------------------------------------------------------------------------- #
# Comparación con la línea base
# --------------------------------------------------------------------------- #

def _report(*findings):
    return {"generated_at": "t", "findings": [
        {"severity": s, "category": c, "title": t, "detail": d}
        for s, c, t, d in findings]}


def test_diff_detecta_suid_nuevo_aunque_el_hallazgo_sea_info():
    base = _report(("INFO", "suid", "3 binarios SUID/SGID en total",
                    "/usr/bin/su\n/usr/bin/passwd\n/usr/bin/mount"))
    curr = _report(("INFO", "suid", "4 binarios SUID/SGID en total",
                    "/usr/bin/su\n/usr/bin/passwd\n/usr/bin/mount\n/tmp/.x"))
    diff = sa.diff_reports(base, curr)
    assert diff["new"] == []          # mismo hallazgo (números normalizados)
    assert diff["changed"][0]["added"] == ["/tmp/.x"]
    assert sa.count_alerts(diff) == 1


def test_diff_sin_cambios_no_alerta():
    r = _report(("HIGH", "firewall", "No se detectó ningún firewall activo", ""))
    assert sa.count_alerts(sa.diff_reports(r, r)) == 0


def test_diff_hallazgo_alto_nuevo_alerta():
    base = _report()
    curr = _report(("CRITICAL", "users", "Cuentas con contraseña VACÍA", "pepe"))
    assert sa.count_alerts(sa.diff_reports(base, curr)) == 1


def test_diff_cambio_en_modulo_no_vigilado_no_alerta():
    base = _report(("LOW", "services", "1 servicios en estado 'failed'", "a.service"))
    curr = _report(("LOW", "services", "2 servicios en estado 'failed'",
                    "a.service\nb.service"))
    assert sa.count_alerts(sa.diff_reports(base, curr)) == 0


def test_diff_puerto_expuesto_nuevo_alerta():
    base = _report(("INFO", "ports", "2 servicios en escucha (solo interfaces locales)", ""))
    curr = _report(("MEDIUM", "ports", "1 servicios en escucha en TODAS las interfaces",
                    "tcp   0.0.0.0:4444"))
    assert sa.count_alerts(sa.diff_reports(base, curr)) == 1


# --------------------------------------------------------------------------- #
# Ejecución de extremo a extremo (módulos que no requieren root)
# --------------------------------------------------------------------------- #

SAFE_MODULES = "system,kernel,path,mounts,coredump"


def test_exporta_todos_los_formatos(tmp_path):
    out = {ext: tmp_path / f"r.{ext}" for ext in ("json", "html", "txt", "md")}
    rc = sa.main(["--only", SAFE_MODULES, "--quiet", "--no-color",
                  *[a for ext, p in out.items() for a in (f"--{ext}", str(p))]])
    assert rc in (0, 1)
    data = json.loads(out["json"].read_text())
    assert {"findings", "summary", "host"} <= data.keys()
    assert "<!DOCTYPE html>" in out["html"].read_text()
    assert out["md"].read_text().startswith("# Informe")


def test_diff_contra_si_mismo_devuelve_0(tmp_path):
    base = tmp_path / "base.json"
    sa.main(["--only", SAFE_MODULES, "--quiet", "--json", str(base)])
    assert sa.main(["--only", SAFE_MODULES, "--quiet", "--diff", str(base)]) == 0


def test_html_escapa_contenido(tmp_path):
    r = sa.CheckResult("x", findings=[
        sa.Finding("INFO", "x", "<script>alert(1)</script>")])
    p = tmp_path / "r.html"
    sa.write_html([r], str(p))
    assert "<script>alert(1)" not in p.read_text()


def test_modulo_desconocido_devuelve_2():
    assert sa.main(["--only", "noexiste"]) == 2


# --------------------------------------------------------------------------- #
# Puertos en escucha
# --------------------------------------------------------------------------- #

SS_OUTPUT = """\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0            0.0.0.0:5353      0.0.0.0:*     users:(("avahi-daemon",pid=812,fd=12))
udp   UNCONN 0      0            0.0.0.0:43193     0.0.0.0:*     users:(("Discord",pid=20783,fd=118))
udp   UNCONN 0      0      0.0.0.0%wlp2s0:68       0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=900,fd=3),("sshd",pid=1,fd=3))
tcp   LISTEN 0      128        127.0.0.1:631       0.0.0.0:*     users:(("cupsd",pid=700,fd=7))
"""


def test_parse_ss_quita_pids_y_separa_udp_efimero():
    listeners, eph = sa.parse_ss(SS_OUTPUT, 32768)
    assert eph == 1
    assert ("tcp", "0.0.0.0:22", "sshd") in listeners
    assert ("udp", "0.0.0.0:5353", "avahi-daemon") in listeners
    assert not any("pid=" in proc for _, _, proc in listeners)


def test_puertos_estables_entre_reinicios_no_alertan():
    """Mismo servicio con otro PID y otro socket efímero: no es una novedad."""
    def report(ss):
        listeners, _ = sa.parse_ss(ss, 32768)
        detail = "\n".join(f"{p:5} {loc:24} {pr}".rstrip() for p, loc, pr in listeners)
        return _report(("MEDIUM", "ports", "3 servicios en escucha en TODAS las interfaces", detail))

    otro_arranque = (SS_OUTPUT.replace("pid=900", "pid=1234").replace("pid=812", "pid=555")
                     .replace("43193", "51022"))
    assert sa.count_alerts(sa.diff_reports(report(SS_OUTPUT), report(otro_arranque))) == 0
