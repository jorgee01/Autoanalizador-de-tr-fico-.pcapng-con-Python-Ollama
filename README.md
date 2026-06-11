# Analizador Automático de Tráfico de Red con IA

> Buenas! Esta es una herramienta académica desarrollada en Python para el análisis automático de capturas de tráfico de red en formato `.pcapng`, con generación de informes mediante Inteligencia Artificial local para el curso de redes y comunicación de datos. NO es lo más potente pero funciona.


---

## Descripción

Este proyecto implementa una herramienta capaz de analizar por si sola archivos de captura de tráfico de red en formato **.pcapng**, extrayendo estadísticas de la **Capa de Transporte del modelo OSI** (TCP y UDP).

El sistema identifica sesiones, conexiones establecidas, cierres de conexión y protocolos de aplicación inferidos por puerto. Como componente de IA, se integra **Ollama** con un modelo LLM ejecutado localmente, el cual interpreta las estadísticas extraídas y genera un informe narrativo en lenguaje natural.

---

## Requisitos

| Componente | Versión mínima |
|------------|---------------|
| Python | 3.11 o superior |
| Ollama | 1.3b |
| TShark (Wireshark) | Cualquier versión reciente |
| Visual Studio Code | Opcional |

---

## Instalación

### 1. Clonar o descargar el proyecto

Colocar la carpeta del proyecto en cualquier ubicación del sistema.

### 2. Crear y activar el entorno virtual

```bash
python -m venv .venv
```

**Windows:**
```bash
.venv\Scripts\activate
```

**macOS / Linux:**
```bash
source .venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Instalar Ollama

Descargar desde: https://ollama.com/download

Verificar instalación:
```bash
ollama --version
```

### 5. Descargar el modelo de IA

```bash
ollama pull deepseek-coder:6.7b
```

> También puede utilizarse cualquier otro modelo compatible con Ollama. Ver sección [Inteligencia Artificial](#inteligencia-artificial) para más detalles.

### 6. Instalar Wireshark / TShark

PyShark requiere TShark para funcionar.

Descargar desde: https://www.wireshark.org/download.html

> Durante la instalación, asegurarse de marcar la opción de instalar **TShark**.

---

## Estructura del proyecto

```
proyecto_trafico_red/
│
├── app/
│   ├── main.py               # Punto de entrada
│   ├── parser_pcap.py        # Carga de paquetes
│   ├── tcp_analysis.py       # Análisis de tráfico TCP
│   ├── udp_analysis.py       # Análisis de tráfico UDP
│   ├── classification.py     # Clasificación por protocolo
│   ├── ollama_report.py      # Generación de informe con IA
│   └── utils.py              # Funciones auxiliares compartidas
│
├── reports/                  # Informes generados automáticamente
├── samples/                  # Capturas de ejemplo
├── requirements.txt
└── README.md
```

---

## Uso

Asegurarse de que Ollama esté corriendo antes de ejecutar:

```bash
ollama serve
```

Luego ejecutar el analizador:

```bash
python app/main.py
```

El programa solicitará la ruta del archivo `.pcapng`:

```
Ruta del archivo .pcapng: samples/captura.pcapng
```

También se puede ingresar una ruta absoluta:

```
Ruta del archivo .pcapng: C:\Users\Usuario\Desktop\captura.pcapng
```

Al finalizar el análisis:

- Se imprime un resumencito en consola.
- Se genera automáticamente el archivo:

```
reports/reporte_generado.md
```

---

## Funcionalidades

- Identificación de sesiones TCP y UDP
- Detección del Three-Way Handshake completo
- Detección de conexiones incompletas
- Conteo de cierres mediante FIN y RST
- Contabilización de datagramas UDP
- Inferencia de protocolos de aplicación por puerto (HTTP, HTTPS/TLS, DNS, SSH, FTP, entre otros)
- Generación automática de informe narrativo en español mediante IA local

---

## Inteligencia Artificial

### ¿Por qué Ollama?

Se eligió **Ollama** porque nos permite experimentar con ia local y así aprender un poco más de sus funcionalidades, aunque es un poco tiesa, podemos lograr buenos prompts con ella.

### Modelos utilizados

| Modelo | Estado |
|--------|--------|
| `deepseek-coder:1.3b` | Funcionó al final (ver bitácora de errores) |
| `deepseek-coder:6.7b` |  Modelo actual(pesado, no sirvió) |

El modelo recibe las estadísticas extraídas por el sistema y genera una explicación clara del comportamiento del tráfico observado. **No analiza directamente el archivo `.pcapng`** — interpreta los datos ya procesados.

Para cambiar el modelo, modificar esta línea en `ollama_report.py`:

```python
MODEL = "deepseek-coder:1.3b"
```

---

## Bitácora de errores y decisiones técnicas

### v0.1 — Modelo `deepseek-coder:6.7b`

**Problema:** El tiempo de generación del informe era muy lento, más de 1 minuto.

**Causa:** El modelo de 1.3B tiene capacidad limitada para seguir instrucciones complejas. Con un prompt detallado de ~500 palabras, el modelo tardaba en procesar y tendía a **inventar datos** que ni siquiera existían en el archivo, aunque al menos arrancó bien.

**Solución aplicada:**
- Se redujo y simplificó el prompt para disminuir la carga de tokens.
- Se agregó `temperature: 0.3` para reducir la "creatividad" del modelo y mejorar la precisión.
- Se limitó la longitud de respuesta con `num_predict: 600`.
- Finalmente volvimos al modelo `deepseek-coder:1.3b` para obtener respuestas más precisas y en menor tiempo.

---

## Autor

Proyecto desarrollado con fines académicos — Análisis de Tráfico de Red

```
Jorg3~   Murillo, C35519
Juni0r   Jiménez  Venegas
```

> *Universidad de Costa Rica — Redes y Comunicaciones de Datos, I Ciclo 2026*