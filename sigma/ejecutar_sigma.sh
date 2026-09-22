#!/usr/bin/env bash
# ejecutar_sigma.sh -- Demostracion completa de Sigma:
#   1) convierte la regla Sigma a varios lenguajes (Splunk, Lucene, SQLite)
#   2) carga un log sintetico en SQLite
#   3) ejecuta la consulta SQLite generada por Sigma contra ese log
#
# Se ejecuta desde la raiz del proyecto:  bash sigma/ejecutar_sigma.sh
set -euo pipefail
cd "$(dirname "$0")/.."

SIGMA=".venv/bin/sigma"
REGLA="sigma/reglas/proceso_sospechoso.yml"
DB="sigma/logs/eventos.db"

echo "======================================================================"
echo " 1) La MISMA regla Sigma traducida a varios backends"
echo "======================================================================"
echo "--- Splunk (SPL) ---"
$SIGMA convert -t splunk --without-pipeline "$REGLA" 2>/dev/null
echo
echo "--- Elasticsearch (Lucene) ---"
$SIGMA convert -t lucene --without-pipeline "$REGLA" 2>/dev/null
echo
echo "--- SQLite ---"
$SIGMA convert -t sqlite "$REGLA" 2>/dev/null
echo

echo "======================================================================"
echo " 2) Cargamos el log sintetico en una base SQLite"
echo "======================================================================"
rm -f "$DB"
sqlite3 "$DB" < sigma/logs/eventos.sql
echo "Eventos cargados en $DB:"
sqlite3 -header -column "$DB" "SELECT UtcTime, Image, CommandLine FROM eventos;"
echo

echo "======================================================================"
echo " 3) Ejecutamos la consulta de Sigma contra el log real"
echo "======================================================================"
# La regla usa la tabla generica <TABLE_NAME>; la apuntamos a 'eventos'.
CONSULTA=$($SIGMA convert -t sqlite "$REGLA" 2>/dev/null | sed 's/<TABLE_NAME>/eventos/')
echo "Consulta ejecutada:"
echo "  $CONSULTA"
echo
echo "Coincidencias (eventos detectados como sospechosos):"
sqlite3 -header -column "$DB" "$CONSULTA"
