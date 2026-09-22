/*
 * demo_fichero.yar -- Reglas YARA para escanear FICHEROS en disco.
 *
 * Anatomia de una regla YARA:
 *   rule Nombre : etiquetas {
 *       meta:       informacion descriptiva (no afecta a la deteccion)
 *       strings:    patrones a buscar (texto, hexadecimal, regex)
 *       condition:  expresion booleana que decide si la regla salta
 *   }
 */

import "elf"     // modulo para inspeccionar cabeceras ELF (Linux)
import "hash"    // modulo para calcular hashes (md5, sha256, ...)

// ---------------------------------------------------------------------------
// 1) Regla clasica: fichero de prueba EICAR.
//    EICAR es una cadena estandar e inofensiva que todos los antivirus
//    reconocen. Sirve para probar motores de deteccion sin usar malware real.
// ---------------------------------------------------------------------------
rule EICAR_Fichero_Prueba : prueba
{
    meta:
        autor       = "Clase de Seguridad UAL"
        descripcion = "Detecta el fichero de prueba estandar EICAR"
        referencia  = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}

// ---------------------------------------------------------------------------
// 2) Regla que SI detecta la muestra en disco: se apoya en artefactos que
//    quedan en claro (nombre del fichero fuente, hilo de ejecucion, cabecera
//    ELF), no en las cadenas cifradas.
// ---------------------------------------------------------------------------
rule Malware_Demo_Disco : demo linux
{
    meta:
        autor       = "Clase de Seguridad UAL"
        descripcion = "Detecta la muestra malware_demo en disco por sus artefactos"

    strings:
        // Mensajes que el binario imprime y quedan en claro dentro del ELF
        $s1 = "[muestra_demo]"
        $s2 = "Cadenas descifradas en memoria"

    condition:
        // Debe ser un ejecutable ELF de Linux Y contener alguno de los mensajes.
        // ET_EXEC = binario clasico; ET_DYN = binario PIE (por defecto en gcc actual).
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and any of ($s*)
}

// ---------------------------------------------------------------------------
// 3) Regla que NO deberia saltar en disco: busca las cadenas del C2 y del
//    payload EN CLARO. Como en la muestra estan cifradas con XOR, esta regla
//    falla en disco... pero acertara al escanear la RAM (ver demo_ram.yar).
//    Es el nucleo pedagogico del ejemplo.
// ---------------------------------------------------------------------------
rule C2_En_Claro : demo c2
{
    meta:
        autor       = "Clase de Seguridad UAL"
        descripcion = "Busca el dominio del C2 y el payload en texto plano"

    strings:
        $dominio = "c2.malicioso-demo.local" ascii wide nocase
        $payload = "EVIL_PAYLOAD_DEMO_v1"     ascii wide

    condition:
        any of them
}
