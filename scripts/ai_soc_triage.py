"""
AI-Powered SOC Triage Assistant (SOC Copilot)
---------------------------------------------
Este script simula el procesamiento automatizado de alertas crudas de Sysmon/Wazuh
generadas durante la simulación de técnicas de Reconocimiento y Detección (MITRE ATT&CK T1087 / T1082).
Utiliza una estructura de evaluación basada en IA para generar reportes ejecutivos de respuesta a incidentes.

Autor: Gonzalo Barrientos
Proyecto: Home SOC Lab - Wazuh & Sysmon Integration
"""

import json
from datetime import datetime

# Simulación de telemetría cruda recibida de Sysmon (Event ID 1 - Process Creation)
sample_wazuh_event = {
    "timestamp": "2026-11-03T19:08:23.388-0300",
    "agent": {"id": "001", "name": "Windows-PC", "ip": "192.168.1.50"},
    "rule": {
        "id": "100001",
        "level": 8,
        "description": "SOC Lab Alert: Reconnaissance Activity Detected via PowerShell/CMD",
        "mitre": {"id": ["T1087", "T1082"], "tactic": ["Discovery"]}
    },
    "sysmon": {
        "event_id": 1,
        "image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "net user",
        "parent_image": "C:\\Windows\\System32\\powershell.exe",
        "user": "Windows-PC\\Gonzalo"
    }
}

def analyze_event_with_ai_logic(event):
    """
    Simula la motorización del modelo de lenguaje (LLM) que analiza la alerta de Wazuh
    y estructura el reporte técnico para el equipo de respuesta a incidentes (L1/L2).
    """
    agent_name = event["agent"]["name"]
    cmd = event["sysmon"]["command_line"]
    parent = event["sysmon"]["parent_image"]
    mitre_ids = ", ".join(event["rule"]["mitre"]["id"])
    rule_level = event["rule"]["level"]

    report = f"""
================================================================================
 🛡️ AI SOC COPILOT - AUTOMATED INCIDENT TRIAGE REPORT
================================================================================
Timestamp Analysis : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target Endpoint    : {agent_name} (ID: {event['agent']['id']})
Triggered Rule ID  : {event['rule']['id']} (Severity Level: {rule_level})
MITRE ATT&CK Mapping: {mitre_ids} ({', '.join(event['rule']['mitre']['tactic'])})

--------------------------------------------------------------------------------
 🔍 EXECUTIVE SUMMARY & ANALYSIS
--------------------------------------------------------------------------------
Se ha detectado la ejecución del comando sospechoso de descubrimiento:
 > Comandos ejecutados : '{cmd}'
 > Proceso ejecutante : {event['sysmon']['image']}
 > Proceso Padre      : {parent}
 > Usuario del sistema: {event['sysmon']['user']}

Evaluación de Riesgo:
La ejecución de '{cmd}' desde la consola de comandos sugiere un comportamiento de
Reconocimiento Local (Account Discovery - T1087). El atacante o script malicioso está
intentando mapear los usuarios locales del endpoint para identificar vectores de elevación de privilegios.

--------------------------------------------------------------------------------
 🚨 RECOMMENDED ACTION PLAN FOR SOC ANALYST (L1/L2)
--------------------------------------------------------------------------------
 1. [CONTENCIÓN] Verificar si el usuario '{event['sysmon']['user']}' realizó esta acción por tareas de mantenimiento legítimas.
 2. [INVESTIGACIÓN] Revisar el historial de ejecuciones del proceso padre ({parent}) en busca de scripts no autorizados.
 3. [TELEMETRÍA] Filtrar eventos de Sysmon Event ID 3 (Network Connection) desde el host '{agent_name}' para descartar tráfico de C2.
 4. [REMEDIACIÓN] Si no es actividad autorizada, aislar temporalmente el endpoint '{agent_name}' mediante el agente de Wazuh.
================================================================================
"""
    return report

if __name__ == "__main__":
    print("Iniciando el procesamiento de alertas con el AI SOC Copilot...\n")
    triage_output = analyze_event_with_ai_logic(sample_wazuh_event)
    print(triage_output)
