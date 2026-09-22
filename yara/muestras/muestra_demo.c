/*
 * muestra_demo.c -- Muestra simulada e inofensiva para la clase.
 *
 * Simula una tecnica muy habitual: las cadenas comprometedoras (dominio
 * del C2, marcador del payload) NO estan en claro en el binario, sino
 * cifradas con XOR. Solo se descifran en memoria cuando el programa se
 * ejecuta. Por eso una regla YARA que busque las cadenas en claro:
 *   - NO detecta el fichero en disco
 *   - SI detecta el proceso en ejecucion (escaneo de RAM)
 *
 * El programa no hace nada peligroso: descifra las cadenas, las mantiene
 * en memoria y duerme en un bucle hasta que se le mata (Ctrl+C / kill).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#define CLAVE_XOR 0x5A

/* "http://c2.malicioso-demo.local/beacon" cifrado con XOR 0x5A */
static unsigned char c2_cifrado[] = {
    0x32,0x2e,0x2e,0x2a,0x60,0x75,0x75,0x39,0x68,0x74,0x37,0x3b,0x36,0x33,
    0x39,0x33,0x35,0x29,0x35,0x77,0x3e,0x3f,0x37,0x35,0x74,0x36,0x35,0x39,
    0x3b,0x36,0x75,0x38,0x3f,0x3b,0x39,0x35,0x34
};

/* "EVIL_PAYLOAD_DEMO_v1" cifrado con XOR 0x5A */
static unsigned char marcador_cifrado[] = {
    0x1f,0x0c,0x13,0x16,0x05,0x0a,0x1b,0x03,0x16,0x15,0x1b,0x1e,0x05,0x1e,
    0x1f,0x17,0x15,0x05,0x2c,0x6b
};

static char *descifrar(const unsigned char *src, size_t n)
{
    char *out = malloc(n + 1);
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(src[i] ^ CLAVE_XOR);
    out[n] = '\0';
    return out;
}

int main(void)
{
    /* Solo para la demo: permite que cualquier proceso del mismo usuario
     * (p.ej. `yara <pid>`) lea nuestra memoria aunque
     * /proc/sys/kernel/yama/ptrace_scope valga 1. Sin esto habria que
     * ejecutar yara con sudo. */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    char *c2       = descifrar(c2_cifrado, sizeof c2_cifrado);
    char *marcador = descifrar(marcador_cifrado, sizeof marcador_cifrado);

    printf("[muestra_demo] PID %d\n", getpid());
    printf("[muestra_demo] Cadenas descifradas en memoria. Esperando... (Ctrl+C para salir)\n");
    fflush(stdout);

    /* Bucle "beacon": no se conecta a ningun sitio, solo simula la espera. */
    for (;;) {
        /* Aqui una muestra real contactaria con c2 y ejecutaria marcador */
        sleep(5);
    }

    free(c2);
    free(marcador);
    return 0;
}
