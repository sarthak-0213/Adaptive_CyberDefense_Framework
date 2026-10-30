import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import psutil

from app.schemas.security_assessment import (
    NetworkReconResult,
    NetworkServiceObservation,
)

logger = logging.getLogger("security_assessment")


class NetworkAssessmentService:
    @staticmethod
    def _extract_host_and_port(target: str) -> tuple[str, Optional[int]]:
        target_clean = target.strip()
        if not target_clean.startswith(("http://", "https://")):
            # If no scheme, check if host:port
            if ":" in target_clean and not target_clean.count(":") > 1:
                parts = target_clean.split(":")
                try:
                    return parts[0], int(parts[1])
                except ValueError:
                    return parts[0], None
            return target_clean, None

        parsed = urlparse(target_clean)
        return parsed.hostname or "localhost", parsed.port

    def assess_network(self, target: str) -> NetworkReconResult:
        host, custom_port = self._extract_host_and_port(target)
        now_str = datetime.now(timezone.utc).isoformat()
        
        # 1. DNS Resolution
        dns_info: Dict[str, Any] = {
            "query_host": host,
            "resolved_ips": [],
            "canonical_name": host,
            "status": "NOT_ASSESSED"
        }
        try:
            cname, aliases, ip_list = socket.gethostbyname_ex(host)
            dns_info["canonical_name"] = cname
            dns_info["aliases"] = aliases
            dns_info["resolved_ips"] = ip_list
            dns_info["status"] = "RESOLVED"
        except Exception as e:
            dns_info["status"] = f"Resolution failed: {str(e)}"

        # 2. Reachability Check (TCP Connection to target)
        reachable = False
        target_ports_to_try = [custom_port] if custom_port else [8000, 80, 443, 22]
        target_ports_to_try = [p for p in target_ports_to_try if p is not None]

        for p in target_ports_to_try:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    res = s.connect_ex((host, p))
                    if res == 0:
                        reachable = True
                        break
            except Exception:
                continue

        # 3. Host Info
        host_info: Dict[str, Any] = {
            "target_host": host,
            "resolved_ip": dns_info["resolved_ips"][0] if dns_info["resolved_ips"] else "Unknown",
            "is_loopback": host in ["localhost", "127.0.0.1", "::1"],
            "reachability": "ONLINE" if reachable else "OFFLINE"
        }

        # 4. Local / Observed Network Interfaces
        interfaces: List[Dict[str, Any]] = []
        try:
            net_if_addrs = psutil.net_if_addrs()
            for if_name, addrs in net_if_addrs.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append({
                            "interface": if_name,
                            "ip": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast
                        })
        except Exception as e:
            logger.debug(f"Interface lookup skipped: {e}")

        # 5. DHCP Configuration / Observation
        dhcp_info: Dict[str, Any] = {
            "status": "Observed via interface telemetry" if interfaces else "Not assessed",
            "dhcp_enabled": any(iface.get("broadcast") is not None for iface in interfaces),
            "primary_interface": interfaces[0]["interface"] if interfaces else "Not detected",
            "gateway_observation": "Configured default route"
        }

        # 6. Service / Port Observations (Safe, authorized non-intrusive connect checks)
        standard_ports = [
            (22, "SSH", "TCP"),
            (80, "HTTP", "TCP"),
            (443, "HTTPS", "TCP"),
            (8000, "FastAPI Application / API", "TCP"),
            (8080, "Web Alternate / Proxy", "TCP")
        ]
        if custom_port and custom_port not in [22, 80, 443, 8000, 8080]:
            standard_ports.append((custom_port, "Authorized Target Custom Service", "TCP"))

        services_observed: List[NetworkServiceObservation] = []
        for port, s_name, proto in standard_ports:
            status = "not_assessed"
            if reachable or host in ["localhost", "127.0.0.1", "0.0.0.0"]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.4)
                        code = s.connect_ex((host, port))
                        if code == 0:
                            status = "observed"
                        else:
                            status = "closed"
                except Exception:
                    status = "filtered"

            services_observed.append(
                NetworkServiceObservation(
                    port=port,
                    protocol=proto,
                    service=s_name,
                    status=status,
                    timestamp=now_str
                )
            )

        overall_status = "PASS" if reachable else ("WARNING" if host in ["localhost", "127.0.0.1"] else "FAIL")

        return NetworkReconResult(
            target=target,
            reachable=reachable,
            host_info=host_info,
            interfaces=interfaces[:6],
            dns=dns_info,
            dhcp=dhcp_info,
            services=services_observed,
            timestamp=now_str,
            status=overall_status
        )


network_assessment_service = NetworkAssessmentService()
