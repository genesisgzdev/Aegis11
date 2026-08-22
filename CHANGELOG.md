# Changelog

## [Unreleased]

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

## [0.1.1] - 2026-08-20

### Changed

- Reworked the README around the current Windows build path and validation boundary.
- Conectó `--snapshot` al baseline de servicios, tareas y registro; `--restore` continúa reservado hasta tener restauración completa.
- Kept the release positioned as a compile baseline rather than a runtime-certified mitigation product.

## [0.1.0] - 2026-08-20

- Initial public Windows policy-engine baseline.
