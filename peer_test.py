from __future__ import annotations
import argparse, json, socket, sys, time, threading
from network.discovery import PeerDiscovery, _get_local_ip

BCAST_PORT = 5454          # UDP broadcast port (avoids conflict with mDNS 5353)
BCAST_MAGIC = b"MESHVAULT_DISCOVER"


# ── mDNS-based discovery (works on hotspot / home routers) ──────────────────

def advertise(name, port, duration):
    local_ip = _get_local_ip()
    print("[mDNS-ADVERTISE] Service", name, "on", local_ip, "port", port)
    pd = PeerDiscovery()
    pd.advertise_service(name=name, port=port, metadata={"version": "0.1", "device": socket.gethostname()})
    print("[mDNS-ADVERTISE] Registered. Advertising for", duration, "seconds...")
    try:
        for remaining in range(duration, 0, -5):
            time.sleep(5)
            print("[mDNS-ADVERTISE] Still alive...", remaining - 5, "s left")
    except KeyboardInterrupt:
        pass
    finally:
        pd.stop()
        print("[mDNS-ADVERTISE] Stopped.")


def scan_mdns(timeout):
    local_ip = _get_local_ip()
    print("[mDNS-SCAN] Local IP:", local_ip)
    print("[mDNS-SCAN] Scanning for", timeout, "seconds...")
    pd = PeerDiscovery()
    peers = pd.find_peers(timeout_seconds=timeout)
    pd.stop()
    _print_peers(peers, "mDNS-SCAN")
    return peers


# ── UDP Broadcast discovery (works on campus/AP-isolated WiFi) ──────────────

def bcast_advertise(name, port, duration):
    local_ip = _get_local_ip()
    print("[BCAST-ADVERTISE] Listening for discovery pings on UDP port", BCAST_PORT)
    print("[BCAST-ADVERTISE] Service:", name, "at", local_ip, "port", port)
    reply = json.dumps({"name": name, "host": local_ip, "port": port, "device": socket.gethostname()}).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", BCAST_PORT))
    sock.settimeout(1.0)
    deadline = time.time() + duration
    print("[BCAST-ADVERTISE] Ready. Waiting for scanners... (Ctrl+C to stop)")
    try:
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(256)
                if data == BCAST_MAGIC:
                    sock.sendto(reply, addr)
                    print("[BCAST-ADVERTISE] Replied to scanner at", addr[0])
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print("[BCAST-ADVERTISE] Stopped.")


def scan_bcast(timeout):
    local_ip = _get_local_ip()
    print("[BCAST-SCAN] Local IP:", local_ip)
    print("[BCAST-SCAN] Sending broadcast discovery ping...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(1.0)
    sock.bind(("", 0))
    sock.sendto(BCAST_MAGIC, ("255.255.255.255", BCAST_PORT))
    print("[BCAST-SCAN] Collecting replies for", timeout, "seconds...")
    peers = []
    seen = set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(1024)
            key = addr[0]
            if key == local_ip or key in seen:
                continue
            seen.add(key)
            info = json.loads(data.decode())
            peers.append(info)
            print("[BCAST-SCAN] Got reply from", addr[0])
        except (socket.timeout, json.JSONDecodeError):
            pass
    sock.close()
    _print_peers(peers, "BCAST-SCAN")
    return peers


# ── Helpers ─────────────────────────────────────────────────────────────────

def _print_peers(peers, tag):
    if peers:
        print("[" + tag + "] Found", len(peers), "peer(s):")
        for p in peers:
            print("  ->", p.get("name", p.get("host")))
            print("     Host:", p["host"], "port", p["port"])
            if "device" in p:
                print("     Device:", p["device"])
    else:
        print("[" + tag + "] No peers found.")


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MeshVault peer discovery tester (mDNS + UDP Broadcast)")
    parser.add_argument("--advertise", action="store_true", help="Advertise this device")
    parser.add_argument("--scan",      action="store_true", help="Scan for peers")
    parser.add_argument("--broadcast", action="store_true", help="Use UDP broadcast instead of mDNS (for campus WiFi)")
    parser.add_argument("--name",     default=socket.gethostname(), help="Service name")
    parser.add_argument("--port",     type=int, default=9000, help="Port to advertise (default 9000)")
    parser.add_argument("--duration", type=int, default=120,  help="Advertise duration in seconds (default 120)")
    parser.add_argument("--timeout",  type=int, default=8,    help="Scan timeout in seconds (default 8)")
    args = parser.parse_args()

    if not args.advertise and not args.scan:
        parser.print_help()
        sys.exit(1)

    mode = "UDP BROADCAST" if args.broadcast else "mDNS"
    print("=" * 55)
    print("  MeshVault Discovery Test  [" + mode + "]")
    print("=" * 55)

    adv_fn  = bcast_advertise if args.broadcast else advertise
    scan_fn = scan_bcast      if args.broadcast else scan_mdns

    if args.advertise and args.scan:
        t = threading.Thread(target=adv_fn, args=(args.name, args.port, args.duration), daemon=True)
        t.start()
        time.sleep(1)
        scan_fn(args.timeout)
        t.join(timeout=2)
    elif args.advertise:
        adv_fn(args.name, args.port, args.duration)
    else:
        scan_fn(args.timeout)


if __name__ == "__main__":
    main()