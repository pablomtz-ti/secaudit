#!/usr/bin/env bash
#
# install.sh — Instala secaudit como servicio programado de systemd.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Este instalador necesita privilegios de root. Usa: sudo ./install.sh" >&2
    exit 1
fi

SRC="$(cd "$(dirname "$0")" && pwd)"

echo "==> Instalando binarios en /usr/local/bin"
install -m 0755 "$SRC/secaudit.py"           /usr/local/bin/secaudit.py
install -m 0755 "$SRC/deploy/secaudit-run.sh" /usr/local/bin/secaudit-run.sh
install -m 0755 "$SRC/deploy/secaudit-baseline.sh" /usr/local/bin/secaudit-baseline

echo "==> Configuración en /etc/secaudit"
mkdir -p /etc/secaudit
if [ -f /etc/secaudit/secaudit.conf ]; then
    echo "    (se conserva la configuración existente)"
else
    install -m 0640 "$SRC/deploy/secaudit.conf" /etc/secaudit/secaudit.conf
fi

echo "==> Estado y datos en /var/lib/secaudit"
mkdir -p /var/lib/secaudit/reports
chmod 0750 /var/lib/secaudit

echo "==> Unidades de systemd"
install -m 0644 "$SRC/deploy/secaudit.service" /etc/systemd/system/secaudit.service
install -m 0644 "$SRC/deploy/secaudit.timer" /etc/systemd/system/secaudit.timer
systemctl daemon-reload

if [ ! -f /var/lib/secaudit/baseline.json ]; then
    echo "==> Creando línea base inicial (puede tardar 1-2 min por la verificación de integridad)..."
    /usr/local/bin/secaudit-baseline || echo "    AVISO: no se pudo crear la base; se creará en la primera ejecución."
fi

echo "==> Activando el timer"
systemctl enable --now secaudit.timer

echo
echo "Instalación completada."
echo "------------------------------------------------------------------"
systemctl list-timers secaudit.timer --no-pager 2>/dev/null || true
echo "------------------------------------------------------------------"
echo "Comprobaciones útiles:"
echo "  sudo systemctl start secaudit.service          # ejecutar ya, una vez"
echo "  journalctl -u secaudit -n 50 --no-pager        # ver el resultado"
echo "  sudo secaudit-baseline                         # refrescar la base tras cambios legítimos"
echo "  cat /var/lib/secaudit/LAST_ALERT.txt           # última alerta (si la hubo)"
echo "  ls /var/lib/secaudit/reports/                  # informes HTML/JSON guardados"
echo "Edita /etc/secaudit/secaudit.conf para configurar el correo y la frecuencia."
