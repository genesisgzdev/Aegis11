# Changelog

## [Unreleased]

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
- Documented the CLI modes and the fact that snapshot and restore are not implemented.
- Kept the release positioned as a compile baseline rather than a runtime-certified mitigation product.

## [0.1.0] - 2026-08-20

- Initial public Windows policy-engine baseline.
