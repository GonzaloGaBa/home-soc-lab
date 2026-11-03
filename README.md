# 🛡️ Home SOC Lab: Wazuh SIEM Deployment & Endpoint Telemetry (Sysmon)

## 📌 Overview
Este proyecto documenta la construcción de un entorno de **Security Operations Center (SOC) casero** utilizando la plataforma SIEM/XDR **Wazuh**. El laboratorio simula la monitorización de endpoints, recolección de eventos de seguridad y análisis avanzado de telemetría de amenazas bajo un enfoque defensivo (Blue Team).

---

## 🏗️ Architecture & Topology
* **Wazuh Manager:** Ubuntu Server (VirtualBox VM) — Configurado con NAT y reenvío de puertos (*Port Forwarding* para puertos `8443`, `1514`, `1515`).
* **Endpoint Monitoreado:** Windows 11 Home — Nombre de Agente: `Windows-PC` (ID: `001`).

---

## 🚀 Phase 1: Server Deployment & Clean Agent Onboarding
- Se desplegó el servidor central y se verificó el Dashboard principal.
- Se instaló y vinculó el agente de Wazuh en el sistema Windows mediante PowerShell apuntando al manager local.

### 1. Initial Dashboard State
![Wazuh Initial Dashboard](images/01-wazuh-dashboard-overview.png)

### 2. Active Agent Verification (Windows-PC)
![Wazuh Active Agent](images/01-wazuh-agent-active-windows-pc.png)

---

## 🔍 Phase 2: Sysmon Integration & Telemetry Collection
- Se instaló y actualizó **Sysmon (System Monitor)** utilizando la configuración de SwiftOnSecurity optimizada para el marco MITRE ATT&CK.
- Se modificó el archivo de configuración del agente (`ossec.conf`) para incorporar la lectura del canal operacional de Sysmon (`Microsoft-Windows-Sysmon/Operational`).

### Sysmon Telemetry Flow & Threat Mapping
![Sysmon Integration](images/02-wazuh-sysmon-integration.png)

---

## 🛠️ Next Steps
- [ ] Simulación de ataques de prueba (técnicas de descubrimiento e inyección de procesos).
- [ ] Creación de reglas personalizadas en Wazuh y alertas basadas en MITRE ATT&CK.
