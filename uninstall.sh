#!/usr/bin/env bash
#
# uninstall.sh — Elimina el servicio y los binarios de secaudit.
# Conserva la configuración y los datos por seguridad (bórralos a mano si quieres).
#
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Necesita root. Usa: sudo ./uninstall.sh" >&2
    exit 1
fi

echo "==> Deteniendo y deshabilitando el timer"
systemctl disable --now secaudit.timer 2>/dev/null || true
systemctl stop secaudit.service 2>/dev/null || true

echo "==> Eliminando unidades de systemd"
rm -f /etc/systemd/system/secaudit.service /etc/systemd/system/secaudit.timer
systemctl daemon-reload

echo "==> Eliminando binarios"
rm -f /usr/local/bin/secaudit.py /usr/local/bin/secaudit-run.sh /usr/local/bin/secaudit-baseline

echo
echo "Desinstalación completada."
echo "Se han CONSERVADO (bórralos manualmente si lo deseas):"
echo "  /etc/secaudit         (configuración)"
echo "  /var/lib/secaudit     (línea base, informes y alertas)"
