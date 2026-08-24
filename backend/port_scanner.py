import socket
import time


def scan_ports(target):

    result = {}

    try:

        ip = socket.gethostbyname(target)

        result["target"] = target
        result["ip"] = ip

    except:

        return {
            "success": False,
            "message": "Unable to resolve target"
        }

    ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "Remote Desktop"
    }

    open_ports = []

    start = time.time()
    ports_result = []

    for port, service in ports.items():

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        status = s.connect_ex((ip, port))

        if status == 0:
            port_status = "Open"
            open_ports.append(port)
        else:
            port_status = "Closed"

        ports_result.append({
            "port": port,
            "service": service,
            "status": port_status
        })

        s.close()

    end = time.time()

    result["scan_time"] = round(end - start, 2)
    result["ports_checked"] = len(ports)
    result["open_ports"] = len(open_ports)
    result["ports"] = ports_result

        # ---------------- RISK ANALYSIS ----------------

    risk_table = {
        21: "High (FTP is unencrypted)",
        22: "Medium (Secure if configured properly)",
        25: "Medium (Mail Server)",
        53: "Low (DNS Service)",
        80: "Low (HTTP)",
        110: "Medium (POP3)",
        143: "Medium (IMAP)",
        443: "Low (HTTPS)",
        3306: "High (Database should not be publicly exposed)",
        3389: "High (Remote Desktop)"
    }

    risk_result = []

    for port in open_ports:

        service = ports[port]

        risk_result.append({
            "port": port,
            "service": service,
            "risk": risk_table[port]
        })

    result["risk_analysis"] = risk_result
    result["success"] = True
    return result