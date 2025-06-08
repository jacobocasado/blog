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



# Proxmox 

## Steps to add new disk
```
You would need to format the drive via the UI (Click on the Node > Disks > Select your disk > Initialize disk with GPT). Depending on what kind of storage you want to create with your disk, the next steps differ.  
  
If you want to create a directory storage, you would simply navigate to Directory in the sidebar and then click 'Create'. There you just supply the sdb disk and enter a name and a type of filesystem.  
Be aware that Directory storage does not support many features offered by PVE such as Snapshots (you can check the capabilities of the different storage types in our documentation: [1]).  
  
You could also create an LVM-thin storage, which provides more features than a simple directory storage (which is probably what you currently have on your existing disk with name local). For this, instead of going to Directory in the sidebar, you can navigate to LVM-thin, then click 'Create Thinpool' . Then you just enter a name for your new pool and wait until the creation has finished. Your disk should then be ready to use. I would recommend for you to use this for now as LVM-thin offers more features and capabilities than simple Directory storage, while still being relatively simple to use for beginners.  
  
[1] [https://pve.proxmox.com/pve-docs/pve-admin-guide.html#_storage_types](https://pve.proxmox.com/pve-docs/pve-admin-guide.html#_storage_types)
```

## Steps to import VM
### QCOW format
Push via SCP qcow file in qcow folder:
```
scp /home/jaco/Documents/osed-offline/VM/VM-OSED-X86-01.qcow2 root@192.168.0.4:/var/lib/vz/template/qcow/osed.qcow2
```
Import the disk to the previously created VM (create a VM without disk):
```
qm importdisk <VM ID> <qcow2 image> <storage name>
qm importdisk 101 -f qcow2 osed.qcow2 vms_storage
```

After importing, in the web console click on "edit" in the unused disk in the "Hardware" section of the machine. Click OK and the disk should setup for the machine.
Lastly, change boot order so it boots from the disk first.
