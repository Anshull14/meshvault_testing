from network.discovery import PeerDiscovery

print("Scanning for MeshVault peers (5 seconds)...")
pd = PeerDiscovery()
peers = pd.find_peers(timeout_seconds=20)

if peers:
    for p in peers:
        print(f"  Found: {p['name']} -> {p['host']}:{p['port']} | props: {p['properties']}")
else:
    print("  No MeshVault peers found.")

pd.stop()