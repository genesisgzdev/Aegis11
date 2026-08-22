# Changelog

## Unreleased

- Actualiza la acción de checkout del build Windows a la generación que ejecuta sobre Node 24.
- El rollback del WAL comprueba tipo y bytes antes de revertir y deja intactos cambios externos detectados en la clave.
- La aplicación de una política de Registro también compara el tipo Win32; no considera equivalentes dos valores con los mismos bytes pero distinto tipo.

## [0.1.2] - 2026-08-22

### Fixed

- Limita la tarea de reinforcement a cinco minutos y evita instancias concurrentes durante servicing.
- Rechaza combinaciones de modos CLI y mantiene snapshot, simulate y apply fuera de la recuperación del WAL.
- Captura la versión real del sistema y reemplaza el baseline mediante un archivo temporal con escritura duradera.

### Fixed

- Lee el payload WAL por longitud antes de localizar su checksum.
- Reconstruye una sola vez el último estado durable de cada transacción antes de recuperar, evitando revertir un `PENDING` histórico después de un `COMMITTED`.
- Persiste el resultado de la recuperación y distingue rollback completado de rollback fallido.
- Persiste también el resultado de una reversión cuando falla el append del registro `COMMITTED`.
- Identifica las transacciones por su secuencia durable en vez de depender solo del reloj del sistema.
- Escribe los seis tipos de registro declarados con su tipo Win32 correspondiente.
- Mantiene el snapshot fuera de la ruta de recuperación y lo reemplaza de forma atómica con la versión real del sistema.

### Riesgo y actualización

- `--restore` sigue rechazado; esta release no presenta un mecanismo de restauración que todavía no tiene paridad de estado.
- La versión describe una base de compilación y contratos de recuperación, no una validación privilegiada completa en Windows.

## [Unreleased]

- Sustituye identificadores de ejemplo del proveedor, subcapa y ETW por GUID estables propios. La verificación posterior de WFP consulta el proveedor instalado y deja de usar ICMP contra una dirección pública como indicador de salud.
- Durante la actualización elimina también el proveedor usado por la versión previa, para no dejar filtros persistentes fuera de la ruta de limpieza.
- `--apply` deja de ejecutar mutaciones de servicios sin journal y devuelve exit code 3 hasta que exista rollback con paridad.
- `--reconcile` queda limitado a recuperar el WAL; no modifica servicios ni tareas sin un snapshot journaled con rollback completo.
- El registro automático de reinforcement queda desactivado hasta que sus mutaciones tengan paridad de recuperación.
- Si una escritura de registro falla después del `PENDING`, la ruta persiste el estado parcial, intenta revertirlo y guarda el resultado antes de devolver error.
- El rollback interactivo conserva el WAL cuando una reversión falla o no puede quedar registrada.
- El rollback interactivo comprueba también que el archivo WAL se haya podido retirar antes de informar éxito.
- El menú interactivo rechaza Balanced y Aggressive hasta que servicios, tareas y módulos adicionales compartan un plan journaled con rollback completo; solo Light puede ejecutar cambios de registro por el WAL actual.

## [0.1.1] - 2026-08-20

### Changed

- Reworked the README around the current Windows build path and validation boundary.
- Conectó `--snapshot` al baseline de servicios, tareas y registro; `--restore` continúa reservado hasta tener restauración completa.
- Kept the release positioned as a compile baseline rather than a runtime-certified mitigation product.

## [0.1.0] - 2026-08-20

- Initial public Windows policy-engine baseline.
- El snapshot ahora conserva el tipo y los bytes exactos del valor de registro, la vista de Windows, la configuración básica y dependencias del servicio y el XML de las tareas capturadas. El esquema queda versionado; esto prepara el contrato de restore sin presentarlo como implementado.
