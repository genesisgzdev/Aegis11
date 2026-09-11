# Elegir y recuperar ajustes

## Antes de decidir

La pantalla principal muestra tu versión de Windows y las acciones disponibles. Elige 1 para leer los cambios. Un valor que ya coincide no necesita una nueva modificación. Si aparece un valor nuevo, Aegis explica que lo añadirá.

Los ajustes de privacidad cubren datos de diagnóstico, Copilot y resultados web en la búsqueda. Windows puede ignorar una política que tu edición no admita. Aegis no presenta la escritura de un valor como prueba de que Windows haya cambiado todo su comportamiento.

## Confirmar una propuesta

Escribe `SI` solo después de revisar la lista. Aegis guarda el estado previo de cada ajuste antes de escribirlo. Si falla un ajuste, detiene los siguientes. El mensaje final invita a volver al menú y no declara que todo haya salido bien cuando hubo un error.

Si hay una recuperación pendiente, primero usa R. No se aplican nuevas políticas desde el menú durante ese estado.

## Deshacer

R trabaja con el registro de cambios de Aegis. No restaura programas eliminados por otras herramientas, servicios ni una copia completa de Windows. Si otra aplicación modificó uno de esos valores después, Aegis puede detener la recuperación para no sobrescribir ese cambio ajeno.

Conserva el archivo `aegis_wal.jsonl` cuando aparezca un error de recuperación. Borrarlo eliminaría la información que Aegis necesita para volver a intentarlo.

## Elegir el comando adecuado

| Quieres | Comando |
| --- | --- |
| Usar el menú | `Aegis11.exe --interactive` |
| Consultar el plan de servicios | `Aegis11.exe --preview` |
| Guardar ajustes compatibles | `Aegis11.exe --snapshot ajustes.json` |
| Recuperar transacciones pendientes al iniciar | `Aegis11.exe --reconcile` |
| Ver ayuda | `Aegis11.exe --help` |

`--reconcile` recupera transacciones pendientes. Para deshacer cambios ya confirmados usa R en el menú. `--simulate` y `--dry-run` siguen siendo alias de `--preview` por compatibilidad.

## Lo que aún necesita desarrollo

La restauración de una copia de ajustes y los cambios conjuntos de servicios, tareas y aplicaciones necesitan una recuperación completa antes de habilitarse. Por eso `--apply`, `--restore`, Balanced y Aggressive se rechazan. Un botón disponible debe corresponder a una operación que realmente pueda ejecutarse y recuperarse.

[Volver al inicio](../README.md) · [Cómo se guarda y recupera cada cambio](ARCHITECTURE.md)
