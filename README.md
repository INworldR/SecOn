# 🛡️ SecOn: SecurityOnion Implementation Project

> Enterprise-grade network security monitoring for a KMU-like private environment using SecurityOnion 2.4 with custom Python extensions and data science capabilities.

---

## 📋 Project Overview

This project implements SecurityOnion 2.4 in a virtualized environment to provide comprehensive network security monitoring for a private network with server infrastructure, clients, and network equipment. The implementation includes custom Python scripts for enhanced data analysis and visualization.

### Key Objectives

- Deploy SecurityOnion 2.4 in a KVM/QEMU virtual environment
- Monitor network traffic across multiple servers, clients, and network devices
- Analyze logs from mail servers and web servers
- Develop custom Python scripts for enhanced data analysis and visualization
- Implement effective alert mechanisms for security events
- Build a foundation for future AI-based threat detection

---

## 🔧 Technical Environment

### Network Components
- **Servers**: Multiple Gentoo and Debian servers
- **Clients**: Approximately 20 workstations
- **Network Equipment**: MikroTik and Ubiquity devices
- **Log Sources**: 2 log hosts collecting data from 2 mail servers and 40 web servers

### Development Environment
- **Virtualization**: KVM/QEMU
- **Version Control**: Git/GitHub
- **Programming**: Python with focus on data science libraries
  - NumPy
  - Pandas
  - Matplotlib
  - Seaborn
- **Documentation**: Obsidian, Confluence
- **Project Management**: Trello

---

## 🚀 Getting Started

### Prerequisites

- KVM/QEMU virtualization environment
- Python >= 3.12
- Git installed and configured
- Security Onion 2.4 ISO

### Installation

```bash
# Clone this repository
git clone git@github.com:INworldR/SecOn.git
cd SecOn

# Set up Python virtual environment
make setup

# Configure environment variables
cp conf/example.env conf/.env
# Edit .env file with your specific settings
```

### SecurityOnion VM Setup

1. Create a new KVM virtual machine with:
   - At least 16GB RAM (recommended: 32GB for production use)
   - 4+ CPU cores
   - 200GB+ disk space
   - Two network interfaces:
     - Management interface (for accessing the web interface)
     - Monitoring interface (for capturing traffic)

2. Attach the SecurityOnion ISO and follow the installation wizard:
   - Select "Evaluation Mode" for testing or "Production Mode" for full deployment
   - Configure network interfaces appropriately
   - Set strong credentials

3. Post-installation configuration:
   - Configure log sources
   - Set up Elasticsearch retention policies
   - Customize dashboards
   - Configure alerting rules

Detailed installation instructions are available in the [docs/installation.md](docs/installation.md) file.

---

## 📊 Custom Analysis Scripts

The `src/` directory contains Python scripts for enhanced data analysis:

- `src/dashboards/`: Custom Kibana dashboard configurations
- `src/analysis/`: Data analysis scripts using pandas and numpy
- `src/visualization/`: Plotting and visualization using matplotlib and seaborn
- `src/alerts/`: Custom alert mechanisms

### Example Usage

```bash
# Run basic traffic analysis
python src/analysis/traffic_analyzer.py --timeframe 24h

# Generate custom security dashboard
python src/dashboards/generator.py --template threat_overview

# Analyze specific threat patterns
python src/analysis/threat_patterns.py --logfile /path/to/logfile
```

---

## 📁 Directory Structure

```
.
├── data/         # Raw and processed data (not tracked by Git)
├── notebooks/    # Jupyter notebooks for exploration and prototyping
├── references/   # External resources, documentation, papers
├── results/      # Output files: plots, reports (not tracked by Git)
├── src/          # Source code: modules, pipelines, classes, functions
│   ├── analysis/     # Data analysis scripts
│   ├── alerts/       # Alert system extensions
│   ├── dashboards/   # Custom dashboard configurations
│   ├── integration/  # Integration with external systems
│   └── visualization/ # Data visualization scripts
├── docs/         # Documentation
├── conf/         # Configuration files: .env, YAML, JSON
├── Makefile      # Project automation
├── CHANGELOG.md  # Version history
└── README.md
```

---

## 🛠️ Development Workflow

1. **Planning**: Document requirements in Confluence
2. **Task Management**: Break down tasks in Trello
3. **Development**:
   - Create feature branch from `dev`
   - Implement changes
   - Write tests
   - Document in Obsidian as you go
4. **Code Review**: Submit PR from feature branch to `dev`
5. **Deployment**: Deploy and test on development VM
6. **Documentation**: Update documentation in Confluence
7. **Release**: Merge to `main` when ready for production

---

## 🔍 Monitoring Capabilities

- **Network Traffic Analysis**: Deep packet inspection and analysis
- **Log Analysis**: Centralized log collection and correlation
- **Threat Hunting**: Tools and custom scripts for proactive threat hunting
- **Alerting**: Rule-based and anomaly-based alert generation
- **Visualization**: Custom dashboards for security monitoring

---

## 🔮 Future Enhancements

- **AI-Based Detection**: Implement machine learning models for anomaly detection
- **Automated Response**: Develop scripts for automated incident response
- **Threat Intelligence Integration**: Connect with external threat feeds
- **Extended Visualization**: Advanced data visualization techniques
- **Reporting**: Automated report generation for compliance and security status

---

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Custom Analysis Scripts](docs/analysis_scripts.md)
- [Alert Configuration](docs/alerts.md)
- [Development Guidelines](docs/development.md)

---

## 📄 License

GNU General Public License v3.0

---

## ✍️ Author

Marc Haenle - me@haenle.com
