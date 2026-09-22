#!/bin/sh
# Compila la muestra de demostracion. Se quitan simbolos (-s) para que el
# binario se parezca mas a una muestra real.
set -e
cd "$(dirname "$0")"
gcc -O1 -s -o muestra_demo muestra_demo.c
echo "Compilado: $(pwd)/muestra_demo"
