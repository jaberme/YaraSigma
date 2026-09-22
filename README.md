# Práctica: detección con YARA y Sigma

Ejemplo práctico para clase. Una muestra de laboratorio inofensiva cifra sus
indicadores en disco y los descifra en memoria, lo que permite ver por qué:

- YARA **no** detecta el C2 en el fichero (está cifrado con XOR).
- YARA **sí** lo detecta al escanear la **RAM** del proceso vivo.
- Sigma detecta el mismo ataque en los **logs**, y su regla se traduce a Splunk,
  Elasticsearch y SQLite.

## Documento

`practica_yara_sigma.tex` (compilado en `practica_yara_sigma.pdf`) contiene la
guía completa con explicaciones y salidas reales.

```sh
latexmk -pdf practica_yara_sigma.tex
```

## Reproducir las demos

```sh
# YARA sobre fichero y memoria
bash yara/ejecutar_yara.sh

# Sigma: conversión a varios backends + consulta real sobre SQLite
bash sigma/ejecutar_sigma.sh
```

## Requisitos

- `yara` 4.x (binario en el PATH).
- Entorno virtual con Sigma en `.venv/` (`sigma-cli`, `pysigma-backend-sqlite`,
  `pysigma-backend-splunk`, `pysigma-backend-elasticsearch`). Los scripts usan
  `.venv/bin/sigma`.
- `gcc` para compilar la muestra, `sqlite3` para la demo de Sigma.

## Estructura

```
yara/
  muestras/   muestra_demo.c, compilar.sh, eicar.com, informe_limpio.txt
  reglas/     demo_fichero.yar, demo_ram.yar
  ejecutar_yara.sh
sigma/
  reglas/     proceso_sospechoso.yml, beacon_red.yml
  logs/       eventos.sql
  ejecutar_sigma.sh
```

Todo es de laboratorio e inofensivo. El dominio `c2.malicioso-demo.local` es
ficticio y no resuelve.
