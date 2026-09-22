#!/usr/bin/env bash
# ejecutar_yara.sh -- Demostracion completa de YARA sobre FICHERO y sobre RAM.
# Se ejecuta desde la raiz del proyecto:  bash yara/ejecutar_yara.sh
set -uo pipefail
cd "$(dirname "$0")/.."

R_FICHERO="yara/reglas/demo_fichero.yar"
R_RAM="yara/reglas/demo_ram.yar"
MUESTRAS="yara/muestras"

# Asegurar que la muestra esta compilada
[ -x "$MUESTRAS/muestra_demo" ] || sh "$MUESTRAS/compilar.sh"

echo "######################################################################"
echo " PARTE A -- YARA sobre FICHEROS en disco"
echo "######################################################################"
for f in muestra_demo eicar.com informe_limpio.txt; do
    echo "--- Escaneando $f ---"
    yara "$R_FICHERO" "$MUESTRAS/$f"
    echo "(fin)"
done
echo
echo "Nota: la regla C2_En_Claro NO salta contra el binario, porque el dominio"
echo "del C2 esta cifrado con XOR en disco."
echo

echo "######################################################################"
echo " PARTE B -- YARA sobre la RAM de un proceso"
echo "######################################################################"
# Lanzamos la muestra en segundo plano
"./$MUESTRAS/muestra_demo" >/tmp/muestra_demo.out 2>&1 &
PID=$!
sleep 1
echo "Proceso lanzado con PID=$PID"
echo
echo "--- La regla de C2 contra el FICHERO en disco (falla) ---"
yara "$R_RAM" "$MUESTRAS/muestra_demo"
echo "(sin salida = no detectado en disco)"
echo
echo "--- La MISMA regla contra la RAM del proceso $PID (acierta) ---"
yara -s "$R_RAM" "$PID"
echo
kill "$PID" 2>/dev/null
echo "(proceso $PID terminado)"
