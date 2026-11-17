#!/usr/bin/env bash
#
# secaudit-baseline — (Re)genera la línea base "conocida-buena".
#
# Ejecútalo tras cambios legítimos del sistema (instalar software, abrir un
# puerto a propósito, etc.) para que las comparaciones posteriores no sigan
# alertando por algo que ya has revisado y aceptado.
#
set -uo pipefail

CONF="${SECAUDIT_CONF:-/etc/secaudit/secaudit.conf}"
LIB="${SECAUDIT_LIB:-/var/lib/secaudit}"
TOOL="${SECAUDIT_TOOL:-/usr/local/bin/secaudit.py}"
BASELINE="$LIB/baseline.json"

MODULES=""
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

ONLY_ARG=()
[ -n "$MODULES" ] && ONLY_ARG=(--only "$MODULES")

mkdir -p "$LIB"

# Se genera en un fichero temporal y solo se sustituye la base si la auditoría
# terminó bien. Código 0/1 = OK (1 solo indica hallazgos altos); >=2 = error.
TMP="$(mktemp "$LIB/.baseline-XXXXXX")"
python3 "$TOOL" --no-color --quiet "${ONLY_ARG[@]}" --json "$TMP" >/dev/null 2>"$TMP.err"
RC=$?
if [ "$RC" -gt 1 ] || [ ! -s "$TMP" ]; then
    echo "secaudit: ERROR al generar la línea base (código $RC). Se mantiene la anterior." >&2
    cat "$TMP.err" >&2
    rm -f "$TMP" "$TMP.err"
    exit 2
fi
rm -f "$TMP.err"

# Conserva la base anterior por si quieres revertir.
[ -f "$BASELINE" ] && cp "$BASELINE" "$BASELINE.prev"
mv "$TMP" "$BASELINE"
chmod 0640 "$BASELINE"
echo "secaudit: nueva línea base guardada en $BASELINE"
[ -f "$BASELINE.prev" ] && echo "secaudit: la anterior se conservó en $BASELINE.prev"
exit 0
