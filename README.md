# Seguridad de Red: DTP VLAN Hopping e Inyección de Capa 2

## 📋 Información del Proyecto
> [!NOTE]
> **Institución:** Instituto Tecnológico de las Américas (ITLA)  
> **Curso:** Seguridad de Redes  
> **Estudiante:** Manuel Cruz Messón  
> **Docente:** Jonathan Rondón  
> **Fecha:** Junio 2026  

---

## 1. Objetivo del Laboratorio
El objetivo fundamental de este laboratorio de seguridad avanzada es evaluar el impacto práctico y el comportamiento lógico del script de ataque `dtp_hopping.py` dentro de un entorno de red controlado. 

El análisis se enfoca en auditar la vulnerabilidad de las interfaces de acceso con negociación dinámica activa bajo el protocolo propietario de Cisco, **Dynamic Trunking Protocol (DTP)**. A través de la inyección manual de tramas modificadas, se demostrará cómo un atacante puede forzar la transición de un puerto de acceso a un enlace troncal (*Trunk*), eludiendo el aislamiento departamental para interactuar de forma directa con los segmentos restringidos de la red corporativa, validando a su vez los mecanismos de endurecimiento e interfaces de descarte.

---

## 2. Herramientas Utilizadas

| Herramienta | Plataforma | Propósito y Aplicación en el Laboratorio |
| :--- | :--- | :--- |
| **Python 3 / Scapy (v2.5.0)** | Kali Linux 2018 | Construcción e inyección automatizada de tramas de Capa 2 forjadas utilizando las estructuras de datos de la librería Scapy (`Dot3`, `LLC`, `SNAP`) para eludir las restricciones del switch. |
| **Cisco IOS CLI** | Switch Cisco (Real/VM) | Auditoría del estado operacional de las interfaces mediante comandos de diagnóstico avanzados y validación del estado administrativo de los puertos. |
| **dtp_hopping.py** | Entorno de Ejecución Local | Script personalizado diseñado para el envío estructurado de payloads DTP con estado *Dynamic Desirable* y parámetros forzados hacia la dirección multicast corporativa. |

---

## 3. Entorno y Topología de Red Dedicada
La infraestructura del laboratorio se despliega bajo un esquema de direccionamiento IP estricto de Capa 3, integrado en la subred `192.168.89.0/24`, aplicando máscaras de subred de longitud variable (**VLSM**) de 27 bits para delimitar de forma rigurosa los hosts autorizados dentro del dominio de difusión.

### 3.1. Inventario de Equipos y Direccionamiento IP de Control

| # | Dispositivo | Dirección IP | Sistema Operativo |
| :-: | :--- | :--- | :--- |
| **1** | Router | `192.168.89.1` | Cisco IOS |
| **2** | Switch | *(Dispositivo Central)* | Cisco IOS |
| **3** | Servidor DNS | `192.168.89.10/27` | Linux (Ubuntu) |
| **4** | Servidor Web | `192.168.89.20/27` | Linux (Ubuntu) |
| **5** | Atacante | `192.168.89.15/27` | Kali Linux 2018 |

### 3.2. Conexiones e Interfaz Física

| Dispositivo Origen | Puerto Origen | Dispositivo Destino | Puerto Destino | Tipo de Enlace / Configuración |
| :--- | :--- | :--- | :--- | :--- |
| **R1** | Gi0/0 | **Switch** | Gi0/0 | Enlace de Red (`192.168.89.1`) |
| **SW1** | Gi0/1 | **DNS** | e0 | Interfaz de Acceso (`192.168.89.10/27`) |
| **SW1** | Gi0/2 | **Servidor Web** | e0 | Interfaz de Acceso (`192.168.89.20/27`) |
| **SW1** | Gi0/3 | **KALI** | e0 | Interfaz Objetivo Atacada (`192.168.89.15/27`) |

---

## 4. Análisis Estático del Script de Inyección
El script `dtp_hopping.py` aprovecha la flexibilidad de Scapy para ensamblar tramas de control estructuradas a bajo nivel, simulando ser un switch Cisco que demanda de forma legítima un estado de interconexión troncal.

### 4.1. Función de Construcción de Tramas TLV (`build_dtp_desirable`)
Dado que DTP utiliza una estructura basada en **Type-Length-Value (TLV)**, el script define internamente un empaquetador binario utilizando la directiva `struct.pack("!HH", t, length)`. Esto asegura que el identificador del tipo y el tamaño total del campo se transmitan de forma exacta en formato de red (*Big Endian*).

* **Inyección Forzada:** La inyección de los bytes `0xA5` fuerza la configuración del switch remoto si este se halla en su estado por defecto de negociación automático. 
* **Encapsulamiento L2:** Se completa dirigiendo el tráfico a la dirección MAC de difusión multicast propietaria de Cisco para protocolos L2 (`01:00:0c:cc:cc:cc`), encapsulada sobre las capas estándar de control de enlace lógico (**LLC**) y el protocolo de acceso a subredes (**SNAP**), con el identificador OUI `0x00000C` y código de protocolo `0x2004`.

---

## 5. Tráfico de Red y Fases de Ejecución del Incidente
La explotación metódica del puerto del switch mediante el script se divide de manera rigurosa en cuatro fases operativas consecutivas:

* **Fase 1: Reconocimiento e Inicialización de la Interfaz** El script determina de forma automática la dirección MAC física de la estación de auditoría local (Kali Linux) vinculada a la interfaz designada (`eth0`), preparándola para el enmascaramiento lógico de las tramas salientes.  
  > ⚠️ **Nota de Laboratorio:** Aunque el output por defecto del script mencione `Fa0/1`, la interfaz real que estaremos transformando y comprometiendo en esta topología es la **`Gi0/3`**.

* **Fase 2: Inyección de Mensajes de Estado Desirable** A través de un bucle controlado por tiempo (`interval=0.5`), se inyectan las ráfagas de paquetes estructurados simulando un dispositivo switch de distribución legítimo que requiere levantar un enlace troncal.

* **Fase 3: Transición Dinámica del Estado del Puerto** El switch objetivo (con su interfaz en modo por defecto `dynamic auto` o `dynamic desirable`) procesa el paquete DTP manipulado, modifica su máquina de estados L2 interna y transmuta el puerto de un estado operativo de acceso a un estado troncal (**Trunk**).

* **Fase 4: Salto de VLAN Activo (VLAN Hopping)** Una vez consolidado el enlace troncal, la estación atacante queda expuesta a la totalidad de las VLAN que fluyen por dicho puerto. El atacante puede, mediante la inyección directa de tramas con encabezados encapsulados 802.1Q (`Dot1Q(vlan=20)`), enrutar tráfico no autorizado hacia hosts externos como el Servidor Web corporativo o el Servidor DNS sin pasar por las restricciones de Capa 3 del Gateway.

---

## 6. Mecanismo de Mitigación Avanzado (Hardening de Interfaces)
Para contrarrestar de manera absoluta la viabilidad de este ataque en la capa de acceso y asegurar que las interfaces de los usuarios finales no puedan ser forzadas a modificar su naturaleza lógica, resulta perentorio inhabilitar la ejecución de DTP y aislar los dominios de broadcast nativos mediante políticas restrictivas de endurecimiento.

```cisco
! Deshabilitar la negociación DTP y forzar el modo de acceso estático
Switch(config)# interface interface GigabitEthernet0/3
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# switchport nonegotiate

! Configuración defensiva complementaria en interfaces troncales legítimas
Switch(config)# interface GigabitEthernet0/0
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk native vlan 666
Switch(config-if)# switchport trunk allowed vlan 10,20
