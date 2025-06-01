# Hardware / Software setup
## Orange Pi 5 8GB RAM
- Ubuntu OS for OrangePi (debian works strange with pihole and some other containers, have tested).
- Static IP address in LAN (192.168.0.2).
- Docker containers:
	- Wireguard -> VPN easy to manage
	- Pihole -> Act as DNS server
	- Syncthing -> Backup of courses, blog, etc
# Steps to deploy homelab
1. Disable CGNAT
2. Enable Port Forwarding from 0.0.0.0 WAN to Orange PI LAN IP (UDP port 51820)
3. Assign Orange PI LAN IP as main DNS
4. Assign Static IP to Orange Pi
5. Enable docker containers (**Note: User `docker compose`, not docker-compose. Install docker from official repo via curl, not apt**)
Router assigns 192.168.0.128 to 192.168.0.255 via DHCP
192.168.0.2 to 192.168.0.127 are IP addresses for my personal lab devices.