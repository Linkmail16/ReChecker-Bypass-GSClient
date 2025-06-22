# ReChecker Bypass GSClient
## ES | Español
Un bypass avanzado para sistemas de detección de archivos específicamente diseñado para GSClient.

## EN | English
An advanced file detection system bypass specifically designed for GSClient.

---

## Instalación | Installation

### ES | Español

#### Opción 1: Usar el DLL precompilado
1. Descarga `ReCheckerBypass.dll` desde las releases
2. Inyecta el DLL en el proceso de GSClient usando un inyector
3. El bypass se activará automáticamente después de 2 segundos

#### Opción 2: Compilar desde el código fuente
1. Clona este repositorio
2. Abre el proyecto en Visual Studio
3. Compila en Release para mejor rendimiento

### EN | English

#### Option 1: Use the precompiled DLL
1. Download `ReCheckerBypass.dll` from releases
2. Inject the DLL into the GSClient process using an injector
3. The bypass will activate automatically after 2 seconds

#### Option 2: Compile from source code
1. Clone this repository
2. Open the project in Visual Studio
3. Compile in Release for better performance

---

## Configuración | Configuration

### ES | Español
El bypass utiliza un archivo `hiddenFiles.cfg` para determinar qué archivos ocultar. Este archivo se crea automáticamente en la primera ejecución.

### EN | English
The bypass uses a `hiddenFiles.cfg` file to determine which files to hide. This file is created automatically on first run.

### Formato del archivo de configuración | Configuration file format
```
# ReChecker Bypass - Archivo de configuración
# Cada línea representa un archivo o patrón a ocultar
# Las líneas que empiezan con # son comentarios

# Ejemplos de patrones:
archivo.dll      # Oculta exactamente 'archivo.dll'
*hack.dll        # Oculta cualquier archivo que termine en 'hack.dll'
hack*            # Oculta cualquier archivo que empiece con 'hack'
*hack*           # Oculta cualquier archivo que contenga 'hack'

# Archivos por defecto a ocultar:
hiddenFiles.cfg
psgs.cfg
```

### Wildcards soportados | Supported wildcards
- `*` - Coincide con cualquier cantidad de caracteres | Matches any number of characters
- `?` - Coincide con un solo carácter | Matches a single character

---

## Sistema de Logging | Logging System

### ES | Español
El bypass incluye un sistema de logging avanzado que muestra:
- **[SCAN]** - Archivos detectados durante el escaneo
- **[BLOCKED]** - Archivos ocultados exitosamente
- **[CONFIG]** - Información de configuración

Los logs aparecen en la consola de GSClient con colores para fácil identificación.

### EN | English
The bypass includes an advanced logging system that shows:
- **[SCAN]** - Files detected during scanning
- **[BLOCKED]** - Files successfully hidden
- **[CONFIG]** - Configuration information

Logs appear in the GSClient console with colors for easy identification.

### Mecanismo de bypass | Bypass mechanism:
1. **ES:** Intercepta llamadas al sistema de archivos | **EN:** Intercepts file system calls
2. **ES:** Compara el nombre del archivo con los patrones configurados | **EN:** Compares filename with configured patterns
3. **ES:** Si coincide, devuelve "archivo no encontrado" | **EN:** If matches, returns "file not found"
4. **ES:** Si no coincide, permite el acceso normal | **EN:** If doesn't match, allows normal access

---

## Archivos objetivo | Target files

### ES | Español
El sistema prioriza la detección de:

### EN | English
The system prioritizes detection of:

- Archivos `.dll` (bibliotecas dinámicas) | `.dll` files (dynamic libraries)
- Archivos `.cfg` (configuración) | `.cfg` files (configuration)
- Archivos `.ini` (configuración) | `.ini` files (configuration)
- Archivos `.asi` (plugins) | `.asi` files (plugins)

---

## Compilación | Compilation

### Dependencias necesarias | Required dependencies:
```cpp
#include <windows.h>
#include <psapi.h>
#include "detours.h"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "psapi.lib")
```

### Configuración del proyecto | Project configuration:
- **ES:** Plataforma: Win32 o x64 | **EN:** Platform: Win32 or x64
- **ES:** Configuración: Release (recomendado para uso) | **EN:** Configuration: Release (recommended for use)
- **ES:** Subsistema: Windows DLL | **EN:** Subsystem: Windows DLL

---

## Advertencias | Warnings

### ES | Español
- **Solo para uso educativo y testing**

### EN | English
- **For educational and testing purposes only**

---

## Autor | Author
**Linkmail**

## Enlaces útiles | Useful links
- [Microsoft Detours](https://github.com/Microsoft/Detours)
- [GSClient](https://gsclient.me/)
