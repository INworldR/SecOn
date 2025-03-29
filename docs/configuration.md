# SecurityOnion Configuration Guide

This guide provides detailed instructions for configuring Security Onion 2.4 after installation, focusing on optimizing the system for the SecOn project's KMU environment.

## Initial System Configuration

### System Access and Authentication

#### Configure SSH Access

```bash
# Allow SSH access from specific IPs
sudo so-allow
# Select 'a' for analyst
# Enter IP addresses or CIDR ranges for access
```

#### Set Up Multi-Factor Authentication (Optional)

For enhanced security, configure multi-factor authentication for web interface access:

```bash
# Install Google Authenticator
sudo yum install google-authenticator

# Configure PAM for Google Authenticator
sudo nano /etc/pam.d/sshd

# Add to the file:
auth required pam_google_authenticator.so

# Update SSH configuration
sudo nano /etc/ssh/sshd_config

# Change to:
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive

# Restart SSH service
sudo service sshd restart
```

### Network Configuration Optimization

#### Management Interface Tuning

```bash
# Edit network configuration
sudo nano /etc/netplan/01-netcfg.yaml

# Optimize for management traffic
# Example configuration:
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      dhcp4: no
      addresses: [10.5.1.60/24]
      gateway4: 10.5.1.1
      nameservers:
        addresses: [10.5.1.1, 8.8.8.8]
      optional: false
```

#### Monitoring Interface Optimization

```bash
# Configure monitoring interface for maximum performance
sudo nano /etc/network/interfaces.d/50-cloud-init.cfg

# Add for monitoring interface:
auto ens4
iface ens4 inet manual
  up ip link set $IFACE up promisc on arp off
  down ip link set $IFACE down promisc off
  mtu 9000  # If your network supports jumbo frames
```

Apply the changes:
```bash
sudo netplan apply
```

## Data Sources Configuration

### Syslog Collection

Configure the built-in syslog server to collect logs from network devices:

```bash
# Edit the syslog configuration
sudo nano /opt/so/conf/logstash/pipelines/syslog.conf

# Update input section for your network devices
input {
  udp {
    port => 514
    type => "syslog"
  }
  tcp {
    port => 514
    type => "syslog"
  }
}
```

### Configuring Filebeat for Log Sources

For the SecOn project's log hosts collecting data from mail and web servers:

```bash
# Create custom filebeat inputs for mail servers
sudo nano /opt/so/conf/filebeat/custom/mail_servers.yml

# Add configuration:
- type: log
  enabled: true
  paths:
    - /var/log/mail/*.log
  fields:
    logtype: mail
    environment: production
  fields_under_root: true
  multiline:
    pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
    negate: true
    match: after

# Create custom filebeat inputs for web servers
sudo nano /opt/so/conf/filebeat/custom/web_servers.yml

# Add configuration:
- type: log
  enabled: true
  paths:
    - /var/log/nginx/access.log
    - /var/log/apache2/access.log
  fields:
    logtype: webserver
    environment: production
  fields_under_root: true
```

Restart Filebeat to apply changes:
```bash
sudo so-filebeat-restart
```

### Adding MikroTik and Ubiquity Devices

```bash
# Create custom pipelines for network devices
sudo nano /opt/so/conf/logstash/pipelines/mikrotik.conf

# Add configuration for MikroTik devices
input {
  syslog {
    port => 5140
    tags => ["mikrotik"]
  }
}

filter {
  if "mikrotik" in [tags] {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{GREEDYDATA:message}" }
    }
  }
}

output {
  if "mikrotik" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "logstash-mikrotik-%{+YYYY.MM.dd}"
    }
  }
}
```

For Ubiquity devices:
```bash
sudo nano /opt/so/conf/logstash/pipelines/ubiquity.conf

# Similar configuration for Ubiquity devices
```

## Detection Configuration

### IDS Rules Management

#### Managing Suricata Rules

```bash
# List available rule sources
sudo so-rule-update list-sources

# Enable additional rule sources
sudo so-rule-update enable et-open
sudo so-rule-update enable etpro  # If you have an ET Pro subscription

# Update rules
sudo so-rule-update update
```

#### Creating Custom Rules

```bash
# Create custom rules directory if it doesn't exist
sudo mkdir -p /opt/so/rules/custom

# Create a custom rule file
sudo nano /opt/so/rules/custom/local.rules

# Add custom rules, example:
alert tcp any any -> $HOME_NET 22 (msg:"Potential SSH Bruteforce"; flow:to_server; threshold: type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:10000001; rev:1;)
```

Enable custom rules:
```bash
# Update the rule configuration
sudo nano /opt/so/saltstack/local/pillar/minions/sensor.sls

# Add your custom rule file to the rules section:
suricata:
  config:
    rules:
      - /opt/so/rules/custom/local.rules

# Apply changes
sudo salt-call state.apply
```

### Zeek Configuration

Configure Zeek for network protocol analysis:

```bash
# Edit Zeek configuration
sudo nano /opt/so/conf/zeek/local.zeek

# Add custom scripts for mail server and web server protocol analysis
@load protocols/smtp/detect-suspicious-attachments
@load protocols/http/detect-webapps

# Configure Zeek for your environment
redef Site::local_nets = { 10.5.0.0/16 };
```

Apply changes:
```bash
sudo so-zeek-restart
```

## Data Retention Configuration

### Elasticsearch Data Management

Configure retention policies based on the SecOn project requirements:

```bash
# Edit Elasticsearch curator configuration
sudo nano /opt/so/conf/elasticsearch/curator.yml

# Configure age-based delete action:
- action: delete_indices
  description: "Delete indices older than 30 days"
  options:
    continue_if_exception: True
    ignore_empty_list: True
  filters:
    - filtertype: age
      source: creation_date
      direction: older
      timestring: '%Y.%m.%d'
      unit: days
      unit_count: 30
    - filtertype: pattern
      kind: prefix
      value: logstash-
```

For different retention periods based on data type:
```bash
# Create custom curator actions
sudo nano /opt/so/conf/elasticsearch/curator/actions/differentiate_retention.yml

# Configure multiple delete actions with different criteria:
- action: delete_indices
  description: "Delete firewall logs older than 90 days"
  filters:
    - filtertype: age
      source: creation_date
      direction: older
      timestring: '%Y.%m.%d'
      unit: days
      unit_count: 90
    - filtertype: pattern
      kind: prefix
      value: logstash-firewall-

- action: delete_indices
  description: "Delete web logs older than 30 days"
  filters:
    - filtertype: age
      source: creation_date
      direction: older
      timestring: '%Y.%m.%d'
      unit: days
      unit_count: 30
    - filtertype: pattern
      kind: prefix
      value: logstash-web-
```

### Optimize Storage Usage

For environments with limited storage:

```bash
# Configure index lifecycle management
sudo nano /opt/so/conf/elasticsearch/ilm-policy.json

# Example policy:
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "5GB",
            "max_age": "1d"
          }
        }
      },
      "warm": {
        "min_age": "2d",
        "actions": {
          "forcemerge": {
            "max_num_segments": 1
          },
          "shrink": {
            "number_of_shards": 1
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

Apply the configuration:
```bash
# Apply ILM policy
curl -XPUT -H 'Content-Type: application/json' http://localhost:9200/_ilm/policy/so-policy -d @/opt/so/conf/elasticsearch/ilm-policy.json
```

## Performance Tuning

### Hardware Resource Allocation

#### Elasticsearch Memory Configuration

```bash
# Configure Java heap size for Elasticsearch
sudo nano /opt/so/conf/elasticsearch/jvm.options

# Update the heap size (adjust to your environment)
-Xms16g
-Xmx16g
```

#### Suricata Performance Tuning

```bash
# Edit Suricata configuration
sudo nano /opt/so/conf/suricata/suricata.yaml

# Tune threading:
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 1 ]
    - worker-cpu-set:
        cpu: [ 2, 3, 4, 5, 6, 7 ]
        mode: "exclusive"
        prio:
          default: "high"

# Tune memory allocation:
outputs:
  - fast:
      memory: 1gb
  - eve-log:
      memory: 1gb

# Tune stream settings:
stream:
  memcap: 4gb
  prealloc: yes
```

## Web Interface Customization

### Customize Dashboards for SecOn Project

```bash
# Access the SOC interface at https://10.5.1.60
# Log in with your credentials

# Create Custom Dashboards:
1. Go to Dashboards
2. Create a new dashboard
3. Add visualization panels specific to your KMU environment:
   - Firewall traffic summary
   - Mail server events
   - Web server access patterns
   - Authentication failures
   - Network anomalies
```

### Role-Based Access Control

Configure role-based access for different user types:

```bash
# Access SecurityOnion console
sudo so-console

# Create a new user
sudo so-user-add

# Assign roles based on responsibilities:
- Analyst: Read access to dashboards and alerts
- Senior Analyst: Read/write access, can create rules
- Administrator: Full system access
```

## Integration with SecOn Python Scripts

### API Access Configuration

Configure SecurityOnion to allow API access for custom scripts:

```bash
# Enable Elasticsearch API access
sudo so-allow
# Select 'e' for Elasticsearch
# Enter IP addresses of hosts running analysis scripts

# Configure API credentials
sudo so-elasticsearch-user-add
# Create a read-only user for scripts
```

## Backup and Recovery

### Configure Regular Backups

```bash
# Create backup script
sudo nano /opt/so/scripts/backup.sh

# Add backup commands:
#!/bin/bash
BACKUP_DIR="/opt/so/backup/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup configuration
tar -czf $BACKUP_DIR/config_backup.tar.gz /opt/so/conf/

# Backup custom rules
tar -czf $BACKUP_DIR/rules_backup.tar.gz /opt/so/rules/custom/

# Backup user accounts
sudo so-user-list > $BACKUP_DIR/users.txt

# Make script executable
chmod +x /opt/so/scripts/backup.sh
```

Add to crontab for regular execution:
```bash
sudo crontab -e

# Add line:
0 1 * * * /opt/so/scripts/backup.sh
```

### Recovery Procedure

In case of system failure:

```bash
# Restore configuration
tar -xzf config_backup.tar.gz -C /
sudo salt-call state.apply

# Restore rules
tar -xzf rules_backup.tar.gz -C /
sudo so-rule-update

# Restore users (manual process)
cat users.txt
# Recreate users with so-user-add
```

## Monitoring and Maintenance

### System Health Monitoring

```bash
# Create a health check script
sudo nano /opt/so/scripts/healthcheck.sh

# Add monitoring commands:
#!/bin/bash
LOG_FILE="/var/log/securityonion/healthcheck.log"

echo "==== Health Check $(date) ====" >> $LOG_FILE

# Check disk space
echo "Disk Usage:" >> $LOG_FILE
df -h >> $LOG_FILE

# Check Elasticsearch
echo "Elasticsearch Health:" >> $LOG_FILE
curl -s localhost:9200/_cluster/health?pretty >> $LOG_FILE

# Check services
echo "Service Status:" >> $LOG_FILE
sudo so-status >> $LOG_FILE

# Make executable
chmod +x /opt/so/scripts/healthcheck.sh
```

Add to crontab for hourly execution:
```bash
sudo crontab -e

# Add line:
0 * * * * /opt/so/scripts/healthcheck.sh
```

### Regular Updates

```bash
# Update SecurityOnion
sudo so-update

# Update rules
sudo so-rule-update

# Verify updates
sudo so-status
```

## Next Steps

After completing the SecurityOnion configuration, proceed to:

1. [Analysis Scripts](analysis_scripts.md) - Setting up custom Python analysis tools
2. [Alert Configuration](alerts.md) - Customizing alerting mechanisms
3. [Development Guidelines](development.md) - Guidelines for developing custom components

---

This configuration guide is part of the SecOn project documentation. For any questions or issues specific to the project implementation, contact the project lead.
