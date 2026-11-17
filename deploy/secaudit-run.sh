#!/usr/bin/env bash
#
# secaudit-run.sh — Ejecuta la auditoría programada, la compara contra la línea
# base y alerta SOLO cuando aparecen cambios de severidad alta/crítica.
#
# Pensado para lanzarse desde secaudit.service (timer de systemd), pero también
# se puede ejecutar a mano. Las rutas se pueden sobrescribir con variables de
# entorno (útil para pruebas).
#
set -uo pipefail

CONF="${SECAUDIT_CONF:-/etc/secaudit/secaudit.conf}"
LIB="${SECAUDIT_LIB:-/var/lib/secaudit}"
TOOL="${SECAUDIT_TOOL:-/usr/local/bin/secaudit.py}"
REPORTS="$LIB/reports"
BASELINE="$LIB/baseline.json"
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- Valores por defecto (los sobrescribe el fichero de configuración) -------
MAIL_TO=""              # destinatario de alertas por correo (vacío = sin correo)
MODULES=""             # módulos a ejecutar (vacío = todos)
AUTO_REBASELINE="no"   # actualizar la base tras cada ejecución (no recomendado)
KEEP_REPORTS="30"      # nº de instantáneas/HTML a conservar

# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

mkdir -p "$REPORTS"

ONLY_ARG=()
[ -n "$MODULES" ] && ONLY_ARG=(--only "$MODULES")

# --- Primera ejecución: si no hay base, se crea y se termina -----------------
if [ ! -f "$BASELINE" ]; then
    python3 "$TOOL" --no-color --quiet "${ONLY_ARG[@]}" --json "$BASELINE" >/dev/null
    if [ ! -s "$BASELINE" ]; then
        echo "secaudit: ERROR, no se pudo crear la línea base." >&2
        exit 2
    fi
    echo "secaudit: línea base creada en $BASELINE (primera ejecución, sin comparación)."
    exit 0
fi

SNAP="$REPORTS/snapshot-$STAMP.json"
HTML="$REPORTS/report-$STAMP.html"
# Fichero temporal dentro de $LIB para no depender de /tmp (compatible con
# ProtectSystem=strict, que solo deja /var/lib/secaudit como escribible).
OUT="$(mktemp "$LIB/.run-XXXXXX")"

python3 "$TOOL" --no-color --quiet "${ONLY_ARG[@]}" \
    --diff "$BASELINE" --json "$SNAP" --html "$HTML" >"$OUT" 2>&1
RC=$?

# El contenido va a journald (lo recoge systemd al ser stdout del servicio).
cat "$OUT"

if [ "$RC" -eq 1 ]; then
    echo "secaudit: ⚠ CAMBIOS RELEVANTES detectados respecto a la base ($STAMP)."
    # Marca persistente para que otras herramientas la recojan.
    cp "$OUT" "$LIB/LAST_ALERT.txt"

    # Notificación por correo (opcional y best-effort).
    if [ -n "$MAIL_TO" ]; then
        SUBJECT="[secaudit] Cambios de seguridad en $(hostname) ($STAMP)"
        if command -v mail >/dev/null 2>&1; then
            mail -s "$SUBJECT" "$MAIL_TO" < "$OUT" \
                && echo "secaudit: alerta enviada a $MAIL_TO" \
                || echo "secaudit: fallo al enviar correo (revisa el MTA)."
        elif command -v sendmail >/dev/null 2>&1; then
            { printf 'Subject: %s\n\n' "$SUBJECT"; cat "$OUT"; } | sendmail "$MAIL_TO" \
                && echo "secaudit: alerta enviada a $MAIL_TO (sendmail)."
        else
            echo "secaudit: MAIL_TO definido pero no hay 'mail' ni 'sendmail' instalado."
        fi
    fi
elif [ "$RC" -eq 0 ]; then
    rm -f "$LIB/LAST_ALERT.txt"   # sin novedades: limpia alerta previa
else
    echo "secaudit: error en la auditoría (código $RC)."
fi

# --- Re-baseline automático (opcional, desaconsejado en monitorización) ------
if [ "$AUTO_REBASELINE" = "yes" ] && [ -f "$SNAP" ]; then
    cp "$SNAP" "$BASELINE"
    echo "secaudit: línea base actualizada automáticamente."
fi

# --- Rotación de informes antiguos ------------------------------------------
if [ "${KEEP_REPORTS:-0}" -gt 0 ]; then
    # shellcheck disable=SC2012
    ls -1t "$REPORTS"/snapshot-*.json 2>/dev/null | tail -n +"$((KEEP_REPORTS + 1))" | xargs -r rm -f
    # shellcheck disable=SC2012
    ls -1t "$REPORTS"/report-*.html 2>/dev/null | tail -n +"$((KEEP_REPORTS + 1))" | xargs -r rm -f
fi

rm -f "$OUT"
exit "$RC"
