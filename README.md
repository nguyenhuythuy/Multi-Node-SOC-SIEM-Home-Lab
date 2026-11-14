# Multi-Node SOC & SIEM Home Lab (Wazuh + pfSense/Suricata + Auditd)

## 1. Tổng quan dự án
Xây dựng môi trường trung tâm giám sát an toàn thông tin (SOC) thu nhỏ trên VMware Workstation nhằm mô phỏng các kịch bản tấn công thực tế, thu thập nhật ký đa tầng (Network & Host-based), phân tích điều tra số và ứng phó sự cố (Incident Response).

## 2. Kiến trúc mạng & Phân bổ IP (`20.20.10.0/24`)

| Vai trò máy ảo | Hệ điều hành | Địa chỉ IP | Dịch vụ / Công cụ giám sát |
| :--- | :--- | :--- | :--- |
| **Gateway & NIDS** | pfSense Firewall | `20.20.10.1` | Firewall Rules, Suricata NIDS |
| **SIEM Server** | Ubuntu Server | `20.20.10.5` | Wazuh Manager, Indexer, Dashboard |
| **Target 1 (Web)** | Windows 10 IIS | `20.20.10.7` | IIS Web Server, Sysmon, Wazuh Agent |
| **Target 2 (Linux)** | Ubuntu Server 22.04 | `20.20.10.8` | OpenSSH, Auditd (`execve`, FIM), Wazuh Agent |
| **Attacker** | Kali Linux | `20.20.10.x` | Nmap, Hydra, Metasploit, SQLmap |

## 3. Cấu trúc Repository
- `configs/`: Cấu hình mạng tĩnh Netplan và bộ luật giám sát tiến trình `auditd` (`execve`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`).
- `incident-reports/`: Báo cáo phân tích sự cố chuẩn quy trình SOC & ánh xạ MITRE ATT&CK.
- `screenshots/`: Bằng chứng thực thi tấn công và cảnh báo trên Wazuh SIEM.

## 4. Danh sách Báo cáo Sự cố (Incident Reports)
- **[IR-001: Tấn công dò mật khẩu SSH (Brute-Force) & Truy cập tệp `/etc/shadow`](incident-reports/IR-001-SSH-BruteForce.md)** — Phân tích chuỗi tấn công Nmap, Hydra, điều tra log đa tầng (`auth.log` + `auditd`) trên Wazuh SIEM và đề xuất khắc phục theo khung MITRE ATT&CK.
- **[IR-001: Tấn công dò mật khẩu SSH (Brute-Force) & Truy cập tệp `/etc/shadow`](incident-reports/IR-001-SSH-BruteForce.md)** — Phân tích chuỗi tấn công Nmap, Hydra, điều tra log đa tầng (`auth.log` + `auditd`) trên Wazuh SIEM và đề xuất khắc phục theo khung MITRE ATT&CK.
