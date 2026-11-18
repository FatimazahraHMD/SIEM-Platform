import subprocess

def get_arp_table():
    arp_table = {}

    result = subprocess.run(
        ["ip", "neigh", "show", "dev", "enp0s8"],
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():

        parts = line.split()

        if len(parts) >= 3 and parts[1] == "lladdr":

            ip = parts[0]
            mac = parts[2]

            arp_table[ip] = mac

    return arp_table
