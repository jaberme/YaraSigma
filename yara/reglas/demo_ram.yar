/*
 * demo_ram.yar -- Reglas YARA para escanear la MEMORIA (RAM) de un proceso.
 *
 * Uso:  yara demo_ram.yar <PID>
 *
 * Idea clave: cuando el proceso malware_demo se ejecuta, descifra en memoria
 * el dominio del C2 y el marcador del payload. Aunque en disco esas cadenas
 * estan cifradas (XOR), en RAM aparecen EN CLARO. Por eso estas reglas, que
 * fallan contra el fichero, aciertan contra el proceso vivo.
 *
 * Esta es la razon por la que el analisis de memoria es imprescindible frente
 * al malware que se ofusca o se cifra en disco.
 */

rule Malware_Demo_En_Memoria : demo ram
{
    meta:
        autor       = "Clase de Seguridad UAL"
        descripcion = "Detecta el C2 y el payload descifrados en la RAM del proceso"

    strings:
        $dominio = "c2.malicioso-demo.local" ascii wide nocase
        $payload = "EVIL_PAYLOAD_DEMO_v1"     ascii wide
        $url     = "http://c2.malicioso-demo.local/beacon" ascii

    condition:
        // Con que aparezca cualquiera de los indicadores descifrados basta
        any of them
}

rule Beacon_C2_Generico : ram heuristica
{
    meta:
        autor       = "Clase de Seguridad UAL"
        descripcion = "Heuristica generica: URL de beacon http hacia un C2"

    strings:
        // Expresion regular: http(s) hacia un host 'c2.*' con ruta /beacon
        $beacon = /https?:\/\/c2\.[a-z0-9.\-]+\/beacon/ ascii nocase

    condition:
        $beacon
}
