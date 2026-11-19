# Reporte de triaje de alertas Wazuh

- **Generado:** 2026-11-19 15:40:36 UTC
- **Fuente:** `examples/sample-alerts.json` (sha256 `c1a313895206e7ec…`)
- **Alertas analizadas:** 12 | **Incidentes agrupados:** 7
- **Capa de IA:** mock (respuestas simuladas, NO es un modelo real)

## Resumen

| # | Regla | Equipo | Eventos | Usuario | Padre | Veredicto | Prioridad |
|---|-------|--------|---------|---------|-------|-----------|-----------|
| 1 | 100001 | Windows-PC | 1 | `NT AUTHORITY\SYSTEM` | `net.exe` | Cadena incompleta | Media |
| 2 | 100001 | Windows-PC | 2 | `NT AUTHORITY\SYSTEM` | `wazuh-agent.exe` | Probable falso positivo | Baja |
| 3 | 100001 | Windows-PC | 2 | `NT AUTHORITY\SYSTEM` | `wazuh-agent.exe` | Probable falso positivo | Baja |
| 4 | 100001 | Windows-PC | 2 | `NT AUTHORITY\SYSTEM` | `wazuh-agent.exe` | Probable falso positivo | Baja |
| 5 | 100001 | Windows-PC | 2 | `NT AUTHORITY\SYSTEM` | `wazuh-agent.exe` | Probable falso positivo | Baja |
| 6 | 100001 | Windows-PC | 2 | `LAB-PC\Gonzalo` | `cmd.exe` | Requiere verificación | Media |
| 7 | 100002 | Windows-PC | 1 | `LAB-PC\Gonzalo` | `cmd.exe` | Requiere verificación | Media |

## Incidente 1 - regla 100001

**Veredicto:** Cadena incompleta (prioridad Media)  
**Motivo:** Es el proceso hijo net1.exe, pero falta el evento de su padre net.exe en las alertas analizadas (posible corte de la muestra).  
**Acción sugerida:** Ampliar el rango con --last o revisar el evento padre en el dashboard antes de decidir.

**Técnica MITRE:** T1087.001 - Account Discovery: Local Account

**Evidencia:**

| Hora evento (UTC) | Hora evento (ART) | Proceso | Línea de comandos | Padre |
|---|---|---|---|---|
| 2026-11-17 04:56:02 | 01:56:02 | `net1.exe` | `C:\WINDOWS\system32\net1 user administrator` | `net.exe` |

> ⚠️ El timestamp del manager difiere 65 min del horario real del evento (posible desvío de reloj del manager). Se usa la hora del evento (`utcTime`).

**Preguntas de investigación:**

- ¿Quién ejecutó el comando y desde qué proceso padre?
- ¿Hubo otros comandos de descubrimiento (whoami, systeminfo, tasklist) en la misma ventana de tiempo?
- ¿El usuario tiene motivo legítimo (soporte, auditoría)?

**Acciones del playbook:**

- Si es actividad del propio agente: excluir en la regla (ver sugerencia).
- Si es un usuario real: confirmar con el usuario/responsable.
- Si el padre es sospechoso: aislar el equipo y escalar.

**Análisis asistido por IA** (generado automáticamente y no verificado; el veredicto lo deciden las reglas):

- **Resumen:** No hay patron conocido; requiere revision manual.
- **A verificar:** Revisar el evento completo.

## Incidente 2 - regla 100001

**Veredicto:** Probable falso positivo (prioridad Baja)  
**Motivo:** Proceso hijo de wazuh-agent.exe ejecutado como SYSTEM: chequeo propio del agente (SCA/inventario).  
**Acción sugerida:** Excluir en la regla los eventos con parentImage = wazuh-agent.exe.

**Técnica MITRE:** T1087.001 - Account Discovery: Local Account

**Evidencia:**

| Hora evento (UTC) | Hora evento (ART) | Proceso | Línea de comandos | Padre |
|---|---|---|---|---|
| 2026-11-17 04:56:03 | 01:56:03 | `net.exe` | `net user guest` | `wazuh-agent.exe` |
| 2026-11-17 04:56:03 | 01:56:03 | `net1.exe` | `C:\WINDOWS\system32\net1 user guest` | `net.exe` |

> ⚠️ El timestamp del manager difiere 65 min del horario real del evento (posible desvío de reloj del manager). Se usa la hora del evento (`utcTime`).

**Preguntas de investigación:**

- ¿Quién ejecutó el comando y desde qué proceso padre?
- ¿Hubo otros comandos de descubrimiento (whoami, systeminfo, tasklist) en la misma ventana de tiempo?
- ¿El usuario tiene motivo legítimo (soporte, auditoría)?

**Acciones del playbook:**

- Si es actividad del propio agente: excluir en la regla (ver sugerencia).
- Si es un usuario real: confirmar con el usuario/responsable.
- Si el padre es sospechoso: aislar el equipo y escalar.

**Análisis asistido por IA** (generado automáticamente y no verificado; el veredicto lo deciden las reglas):

- **Resumen:** Actividad del propio agente de Wazuh, sin indicios de uso malicioso.
- **Hipótesis:** Chequeo de configuracion (SCA) del agente.
- **A verificar:** Confirmar que la regla de exclusion cubre este patron.

## Incidente 3 - regla 100001

**Veredicto:** Probable falso positivo (prioridad Baja)  
**Motivo:** Proceso hijo de wazuh-agent.exe ejecutado como SYSTEM: chequeo propio del agente (SCA/inventario).  
**Acción sugerida:** Excluir en la regla los eventos con parentImage = wazuh-agent.exe.

**Técnica MITRE:** T1087.001 - Account Discovery: Local Account

**Evidencia:**

| Hora evento (UTC) | Hora evento (ART) | Proceso | Línea de comandos | Padre |
|---|---|---|---|---|
| 2026-11-17 08:20:47 | 05:20:47 | `net.exe` | `net user guest` | `wazuh-agent.exe` |
| 2026-11-17 08:20:47 | 05:20:47 | `net1.exe` | `C:\WINDOWS\system32\net1 user guest` | `net.exe` |

> ⚠️ El timestamp del manager difiere 316 min del horario real del evento (posible desvío de reloj del manager). Se usa la hora del evento (`utcTime`).

**Preguntas de investigación:**

- ¿Quién ejecutó el comando y desde qué proceso padre?
- ¿Hubo otros comandos de descubrimiento (whoami, systeminfo, tasklist) en la misma ventana de tiempo?
- ¿El usuario tiene motivo legítimo (soporte, auditoría)?

**Acciones del playbook:**

- Si es actividad del propio agente: excluir en la regla (ver sugerencia).
- Si es un usuario real: confirmar con el usuario/responsable.
- Si el padre es sospechoso: aislar el equipo y escalar.

**Análisis asistido por IA** (generado automáticamente y no verificado; el veredicto lo deciden las reglas):

- **Resumen:** Actividad del propio agente de Wazuh, sin indicios de uso malicioso.
- **Hipótesis:** Chequeo de configuracion (SCA) del agente.
- **A verificar:** Confirmar que la regla de exclusion cubre este patron.

## Incidente 4 - regla 100001

**Veredicto:** Probable falso positivo (prioridad Baja)  
**Motivo:** Proceso hijo de wazuh-agent.exe ejecutado como SYSTEM: chequeo propio del agente (SCA/inventario).  
**Acción sugerida:** Excluir en la regla los eventos con parentImage = wazuh-agent.exe.

**Técnica MITRE:** T1087.001 - Account Discovery: Local Account

**Evidencia:**

| Hora evento (UTC) | Hora evento (ART) | Proceso | Línea de comandos | Padre |
|---|---|---|---|---|
| 2026-11-17 08:20:47 | 05:20:47 | `net.exe` | `net user administrator` | `wazuh-agent.exe` |
| 2026-11-17 08:20:47 | 05:20:47 | `net1.exe` | `C:\WINDOWS\system32\net1 user administrator` | `net.exe` |

> ⚠️ El timestamp del manager difiere 316 min del horario real del evento (posible desvío de reloj del manager). Se usa la hora del evento (`utcTime`).

**Preguntas de investigación:**

- ¿Quién ejecutó el comando y desde qué proceso padre?
- ¿Hubo otros comandos de descubrimiento (whoami, systeminfo, tasklist) en la misma ventana de tiempo?
- ¿El usuario tiene motivo legítimo (soporte, auditoría)?

**Acciones del playbook:**

- Si es actividad del propio agente: excluir en la regla (ver sugerencia).
- Si es un usuario real: confirmar con el usuario/responsable.
- Si el padre es sospechoso: aislar el equipo y escalar.

**Análisis asistido por IA** (generado automáticamente y no verificado; el veredicto lo deciden las reglas):

- **Resumen:** Actividad del propio agente de Wazuh, sin indicios de uso malicioso.
- **Hipótesis:** Chequeo de configuracion (SCA) del agente.
- **A verificar:** Confirmar que la regla de exclusion cubre este patron.

## Incidente 5 - regla 100001

**Veredicto:** Probable falso positivo (prioridad Baja)  
**Motivo:** Proceso hijo de wazuh-agent.exe ejecutado como SYSTEM: chequeo propio del agente (SCA/inventario).  
**Acción sugerida:** Excluir en la regla los eventos con parentImage = wazuh-agent.exe.

**Técnica MITRE:** T1087.001 - Account Discovery: Local Account

**Evidencia:**

| Hora evento (UTC) | Hora evento (ART) | Proceso | Línea de comandos | Padre |
|---|---|---|---|---|
| 2026-11-17 08:20:47 | 05:20:47 | `net.exe` | `net user guest` | `wazuh-agent.exe` |
| 2026-11-17 08:20:47 | 05:20:47 | `net1.exe` | `C:\WINDOWS\system32\net1 user guest` | `net.exe` |

> ⚠️ El timestamp del manager difiere 316 min del horario real del evento (posible desvío de reloj del manager). Se usa la hora del evento (`utcTime`).

**Preguntas de investigación:**

- ¿Quién ejecutó el comando y desde qué proceso padre?
- ¿Hubo otros comandos de descubrimiento (whoami, systeminfo, tasklist) en la misma ventana de tiempo?
- ¿El usuario tiene motivo legítimo (soporte, auditoría)?

**Acciones del playbook:**

- Si es actividad del propio agente: excluir en la regla (ver sugerencia).
- Si es un usuario real: confirmar con el usuario/responsable.
- Si el padre es sospechoso: aislar el equipo y escalar.

**Análisis asistido por IA** (generado automáticamente y no verificado; el veredicto lo deciden las reglas):

- **Resumen:** Actividad del propio agente de Wazuh, sin indicios de uso malicioso.
- **Hipótesis:** Chequeo de configuracion (SCA) del agente.
- **A verificar:** Confirmar que la regla de exclusion cubre este patron.

## Incidente 6 - regla 100001

**Veredicto:** Requiere verificación (prioridad Media)  
**Motivo:** Ejecución interactiva por LAB-PC\Gonzalo desde cmd.exe.  
**Acción sugerida:** Confirmar con el usuario si fue intencional; revisar actividad cercana.

**Técnica MITRE:** T1087.001 - Account Discovery: Local Account

**Evidencia:**

| Hora evento (UTC) | Hora evento (ART) | Proceso | Línea de comandos | Padre |
|---|---|---|---|---|
| 2026-11-17 14:48:18 | 11:48:18 | `net.exe` | `net  user` | `cmd.exe` |
| 2026-11-17 14:48:18 | 11:48:18 | `net1.exe` | `C:\WINDOWS\system32\net1  user` | `net.exe` |

**Preguntas de investigación:**

- ¿Quién ejecutó el comando y desde qué proceso padre?
- ¿Hubo otros comandos de descubrimiento (whoami, systeminfo, tasklist) en la misma ventana de tiempo?
- ¿El usuario tiene motivo legítimo (soporte, auditoría)?

**Acciones del playbook:**

- Si es actividad del propio agente: excluir en la regla (ver sugerencia).
- Si es un usuario real: confirmar con el usuario/responsable.
- Si el padre es sospechoso: aislar el equipo y escalar.

**Análisis asistido por IA** (generado automáticamente y no verificado; el veredicto lo deciden las reglas):

- **Resumen:** Comando de descubrimiento ejecutado de forma interactiva.
- **Hipótesis:** Uso administrativo legitimo.
- **Hipótesis:** Reconocimiento inicial.
- **A verificar:** Confirmar con el usuario.
- **A verificar:** Revisar actividad cercana.

## Incidente 7 - regla 100002

**Veredicto:** Requiere verificación (prioridad Media)  
**Motivo:** Ejecución interactiva por LAB-PC\Gonzalo desde cmd.exe.  
**Acción sugerida:** Confirmar con el usuario si fue intencional; revisar actividad cercana.

**Técnica MITRE:** T1082 - System Information Discovery

**Evidencia:**

| Hora evento (UTC) | Hora evento (ART) | Proceso | Línea de comandos | Padre |
|---|---|---|---|---|
| 2026-11-17 14:48:51 | 11:48:51 | `systeminfo.exe` | `systeminfo` | `cmd.exe` |

**Preguntas de investigación:**

- ¿Quién ejecutó systeminfo y desde qué proceso padre?
- ¿Se ejecutó junto a otros comandos de reconocimiento?

**Acciones del playbook:**

- Verificar con el usuario/responsable si fue una tarea de soporte.
- Si el padre es sospechoso: escalar.

**Análisis asistido por IA** (generado automáticamente y no verificado; el veredicto lo deciden las reglas):

- **Resumen:** Comando de descubrimiento ejecutado de forma interactiva.
- **Hipótesis:** Uso administrativo legitimo.
- **Hipótesis:** Reconocimiento inicial.
- **A verificar:** Confirmar con el usuario.
- **A verificar:** Revisar actividad cercana.

## Limitaciones

- Triaje por **reglas heurísticas fijas**; no usa IA ni inteligencia de amenazas externa.
- Solo analiza las reglas indicadas (100001 y 100002) y evalúa cada proceso individualmente, sin correlación entre reglas distintas.
- Un veredicto de *Probable falso positivo* debe ser confirmado por el analista.
- El análisis de IA no modifica el veredicto, puede equivocarse o inventar y debe verificarse.
- Al modelo solo se le envía evidencia mínima sanitizada (sin hostname, usuario ni IPs); las líneas de comandos pueden contener otros datos sensibles.
