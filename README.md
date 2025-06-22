# ReChecker Bypass GSClient

Un bypass avanzado para sistemas de detección de archivos específicamente diseñado para GSClient.

## Instalación

### Opción 1: Usar el DLL precompilado
1. Descarga `ReCheckerBypass.dll` desde las releases
2. Inyecta el DLL en el proceso de GSClient usando un inyector
3. El bypass se activará automáticamente después de 2 segundos

### Opción 2: Compilar desde el código fuente
1. Clona este repositorio
2. Abre el proyecto en Visual Studio
4. Compila en Release para mejor rendimiento

## Configuración

El bypass utiliza un archivo `hiddenFiles.cfg` para determinar qué archivos ocultar. Este archivo se crea automáticamente en la primera ejecución.

### Formato del archivo de configuración

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

### Wildcards soportados
- `*` - Coincide con cualquier cantidad de caracteres
- `?` - Coincide con un solo carácter

## Sistema de Logging

El bypass incluye un sistema de logging avanzado que muestra:

- **[SCAN]** - Archivos detectados durante el escaneo
- **[BLOCKED]** - Archivos ocultados exitosamente
- **[CONFIG]** - Información de configuración

Los logs aparecen en la consola de GSClient con colores para fácil identificación.

### Mecanismo de bypass:
1. Intercepta llamadas al sistema de archivos
2. Compara el nombre del archivo con los patrones configurados
3. Si coincide, devuelve "archivo no encontrado"
4. Si no coincide, permite el acceso normal

## Archivos objetivo

El sistema prioriza la detección de:
- Archivos `.dll` (bibliotecas dinámicas)
- Archivos `.cfg` (configuración)
- Archivos `.ini` (configuración)
- Archivos `.asi` (plugins)

## Compilación

### Dependencias necesarias:
```cpp
#include <windows.h>
#include <psapi.h>
#include "detours.h"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "psapi.lib")
```

### Configuración del proyecto:
- Plataforma: Win32 o x64
- Configuración: Release (recomendado para uso)
- Subsistema: Windows DLL

## Advertencias

- **Solo para uso educativo y testing**

## Autor

**Linkmail**

## Enlaces útiles

- [Microsoft Detours](https://github.com/Microsoft/Detours)
- [GSClient](https://gsclient.me/)
