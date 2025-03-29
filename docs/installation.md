# SecurityOnion Installation Guide

This guide provides step-by-step instructions for installing and configuring Security Onion 2.4 in a KVM/QEMU virtualized environment for the SecOn project.

## System Requirements

For effective SecurityOnion deployment in a KMU environment, ensure your host system meets the following requirements:

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU       | 4 cores | 8+ cores    |
| RAM       | 16 GB   | 32+ GB      |
| Storage   | 200 GB  | 500+ GB     |
| Network   | 2 interfaces | 2+ interfaces |

## Pre-Installation Tasks

### 1. Download SecurityOnion ISO

```bash
# Download SecurityOnion 2.4 ISO
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.0.iso

# Verify the ISO checksum
sha256sum securityonion-2.4.0.iso
```

### 2. Prepare KVM/QEMU Virtual Machine

Create a new virtual machine with the following specifications:

```bash
# Create a virtual machine with virt-install
virt-install \
  --name securityonion \
  --memory 32768 \
  --vcpus 8 \
  --disk size=500 \
  --network bridge=br0 \
  --network bridge=br1 \
  --cdrom /path/to/securityonion-2.4.0.iso \
  --graphics vnc
```

Alternatively, use virt-manager for GUI-based VM creation:

1. Open virt-manager
2. Click "Create a new virtual machine"
3. Select "Local install media"
4. Browse to the SecurityOnion ISO
5. Configure RAM and CPU allocation
6. Create a new disk (500 GB recommended)
7. Add two network interfaces:
   - Management interface: for administration
   - Monitoring interface: for traffic capture

## Installation Process

### 1. Boot from ISO

Start the VM and boot from the SecurityOnion ISO. You'll be presented with the boot menu.

### 2. Initial Setup

1. Select the "SecurityOnion 2.4.0" boot option
2. Once booted, log in with default credentials:
   - Username: `souser`
   - Password: `onion`
3. Start the setup wizard:
   ```bash
   sudo sosetup
   ```

### 3. Choose Deployment Type

Select the appropriate deployment type:

- **Evaluation Mode**: For testing in lab environments (easier setup)
- **Production Mode**: For live network deployment (more detailed configuration)

For the SecOn project, choose **Production Mode**.

### 4. Network Configuration

Configure network interfaces:

1. Management Interface:
   - Static IP in your management network
   - Used for web interface access and management tasks

2. Monitoring Interface:
   - Configured in promiscuous mode
   - No IP address assigned (used only for traffic capture)

Example configuration:
```
Management interface: ens3
- IP Address: 10.5.1.60
- Netmask: 255.255.255.0
- Gateway: 10.5.1.1
- DNS: 10.5.1.1

Monitoring interface: ens4
- Set to promiscuous mode
- No IP address assigned
```

### 5. Host and Credentials Setup

Set up host identification and administrative credentials:

1. Hostname: `secon`
2. Domain: `local`
3. Set a strong admin password for the web interface
4. Create a SOC admin account

### 6. Component Selection

Choose which SecurityOnion components to install:

- **Manager**: Central management node (required)
- **Search Node**: Elasticsearch for log storage and searching
- **Forward Node**: For log forwarding
- **Heavy Node**: Combination of Search and Forward capabilities

For the SecOn project's KMU environment, install **Manager + Search Node**.

### 7. Elasticsearch Configuration

Configure Elasticsearch settings:

1. Choose data retention period (default: 30 days)
2. Allocate memory based on available RAM:
   - For 32 GB system: allocate ~16 GB to Elasticsearch
3. Select appropriate index patterns for your environment

### 8. Sensor Configuration

Configure intrusion detection settings:

1. Choose IDS Engine:
   - Suricata (recommended)
   - Zeek for protocol analysis
2. Select rule sources:
   - ET Open (free)
   - ET Pro (commercial, if available)
   - Custom rules (for specific environment needs)

### 9. Complete Installation

1. Review configuration summary
2. Confirm and start installation process
3. Installation will take 15-30 minutes depending on hardware

## Post-Installation Tasks

### 1. Complete Initial Setup

1. Access the web interface at `https://<management-ip>`
2. Log in with the credentials created during installation
3. Complete the setup wizard if prompted

### 2. Configure Log Sources

Configure log sources in SecurityOnion:

```bash
# SSH to SecurityOnion
ssh analyst@10.5.1.60

# Configure Filebeat to receive logs from external sources
sudo nano /opt/so/conf/filebeat/filebeat.yml

# Add log sources to filebeat configuration
```

### 3. Configure SSL Certificate (Optional)

Replace the self-signed certificate with a trusted certificate:

```bash
# Generate certificate request
sudo so-allow
sudo so-certificate-request

# Install certificate
sudo so-certificate-install
```

### 4. Initial Rule Tuning

Perform initial rule tuning to reduce false positives:

```bash
# SSH to SecurityOnion
ssh analyst@10.5.1.60

# Check initial alerts
sudo so-rule-update

# Modify rules in /opt/so/rules/
sudo nano /opt/so/rules/custom.rules
```

### 5. Configure Backup

Set up regular configuration backups:

```bash
# Backup configuration to a remote location
sudo so-config-backup

# Set up a cron job for regular backups
sudo crontab -e
```

Add the following line for daily backups at 2 AM:
```
0 2 * * * sudo so-config-backup
```

### 6. Verify Installation

Verify that all components are functioning correctly:

```bash
# Check overall status
sudo so-status

# Check specific components
sudo so-elasticsearch-status
sudo so-suricata-status
sudo so-zeek-status
sudo so-filebeat-status
```

## Troubleshooting

### Common Issues

1. **Web interface not accessible**:
   ```bash
   # Check nginx status
   sudo so-nginx-status
   
   # Restart nginx
   sudo so-nginx-restart
   ```

2. **No alerts appearing**:
   ```bash
   # Check if Suricata is processing traffic
   sudo so-suricata-tail
   
   # Verify monitoring interface is capturing traffic
   sudo tcpdump -i ens4 -n
   ```

3. **High CPU/Memory usage**:
   ```bash
   # Check resource usage
   sudo so-monitor
   
   # Adjust Elasticsearch memory settings
   sudo so-elasticsearch-config
   ```

### Support Resources

- Official documentation: https://docs.securityonion.net
- Community Discord: https://securityonion.net/discord
- GitHub issues: https://github.com/Security-Onion-Solutions/securityonion/issues

## Next Steps

After successful installation, proceed to:

1. [Configuration Guide](configuration.md) - For detailed configuration steps
2. [Analysis Scripts](analysis_scripts.md) - To set up custom Python analysis tools
3. [Alert Configuration](alerts.md) - To customize alerting mechanisms

---

This installation guide is part of the SecOn project documentation. For any questions or issues specific to the project implementation, contact the project lead.
