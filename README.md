# 🛡️ SecOn: Data Science for Network Security Analysis

> Advanced data science and machine learning techniques for analyzing network security data from SecurityOnion 2.4, demonstrating how data science can revolutionize cybersecurity analysis.

---

## 📋 Project Overview

This project demonstrates the application of advanced data science methodologies to cybersecurity monitoring using data from SecurityOnion 2.4. It showcases how machine learning, statistical analysis, and data visualization can transform raw security logs into actionable intelligence, with a focus on comparing and benchmarking different analytical approaches.

### Key Objectives

- Apply advanced clustering techniques to identify attack patterns in firewall logs
- Implement and benchmark machine learning pipelines for attack classification
- Perform time-series analysis to predict security incidents
- Develop sophisticated visualization techniques for security data
- Integrate Large Language Models for automated report generation
- Systematically compare and evaluate different analytical methods

---

## 🔧 Technical Environment

### Data Sources
- **SecurityOnion 2.4**: Enterprise-grade network security monitoring platform
- **Log Types**: Firewall logs, IDS alerts, network flow data
- **Infrastructure**: Monitoring approximately 20 workstations, multiple servers, and network equipment
- **Volume**: Log events from 2 mail servers and 40 web servers

### Development Environment
- **Language**: Python 3.12
- **Data Storage**: DuckDB (columnar analytics database)
- **Core Libraries**:
  - **Data Processing**: Pandas, NumPy
  - **Machine Learning**: Scikit-learn, XGBoost, TensorFlow/Keras
  - **Visualization**: Matplotlib, Seaborn, Plotly, NetworkX
  - **NLP/LLM Integration**: Transformers, LangChain
- **Development Tools**: Jupyter Lab, Git/GitHub
- **Documentation**: Markdown, Jupyter Notebooks

---

## 🚀 Analytical Approaches

### 1. Data Engineering and Storage Optimization
- Columnar database implementation with DuckDB for analytical performance
- Relational schema design optimized for security analytics
- ETL pipeline for JSON log ingestion and normalization
- Advanced SQL for security-focused aggregations and metrics

### 2. Advanced Clustering for Attack Pattern Detection
- Hierarchical clustering to identify attack families
- DBSCAN/HDBSCAN for anomaly detection
- Self-Organizing Maps for threat landscape visualization
- Comparative analysis of clustering algorithms

### 3. Machine Learning Classification Pipelines
- Supervised models (Random Forest, XGBoost, SVM, Neural Networks)
- Weakly-supervised learning with Snorkel for limited labeled data
- Hyperparameter optimization and cross-validation
- Feature importance analysis for interpretability

### 4. Time-Series Analysis and Forecasting
- ARIMA vs. Prophet vs. LSTM for anomaly prediction
- Change-point detection for security event analysis
- Ensemble methods for robust prediction
- Predictive maintenance for security systems

### 5. Advanced Visualization Techniques
- Interactive dashboards with Plotly and Dash
- Network graph visualizations of threat patterns
- Dimensionality reduction (t-SNE, UMAP) for complex datasets
- Visual model explainability

### 6. LLM Integration for Automated Analysis
- Automated report generation using Large Language Models
- Comparison of LLM capabilities for security analysis
- Prompt engineering for security-focused outputs
- Natural language querying of security data

---

## 📊 Jupyter Notebooks

The project consists of a series of Jupyter notebooks, each demonstrating specific data science techniques applied to security analytics:

1. `00_Database_Setup_and_Schema.ipynb`: Setting up DuckDB and implementing the optimized schema
2. `01_Data_Exploration_and_Preprocessing.ipynb`: Initial exploration and preparation of security log data
3. `02_Clustering_for_Attack_Pattern_Discovery.ipynb`: Comparison of clustering techniques
4. `03_Classification_Models_for_Threat_Detection.ipynb`: ML pipeline development and evaluation
5. `04_Time_Series_Analysis_for_Anomaly_Detection.ipynb`: Forecasting and anomaly detection
6. `05_Advanced_Visualization_Techniques.ipynb`: Visual analytics for security data
7. `06_LLM_Integration_for_Automated_Reporting.ipynb`: Leveraging LLMs for analysis interpretation

Each notebook systematically compares different methodologies, providing clear insights into their relative strengths and appropriate use cases. The notebooks leverage DuckDB's analytical capabilities through SQL queries embedded directly in Python, demonstrating how to combine relational database performance with pandas flexibility.

---

## 📁 Project Structure

```
.
├── data/              # Raw and processed security log data (not tracked)
│   ├── raw/           # Original JSON log files from SecurityOnion
│   └── processed/     # Processed data files
├── db/                # DuckDB database files and schemas
│   ├── schema/        # SQL schema definitions
│   ├── security_logs.duckdb  # Main database file
│   └── etl/           # ETL scripts for data loading
├── notebooks/         # Jupyter notebooks for analysis
│   ├── 01_Data_Exploration_and_Preprocessing.ipynb
│   ├── 02_Clustering_for_Attack_Pattern_Discovery.ipynb
│   ├── 03_Classification_Models_for_Threat_Detection.ipynb
│   ├── 04_Time_Series_Analysis_for_Anomaly_Detection.ipynb
│   ├── 05_Advanced_Visualization_Techniques.ipynb
│   └── 06_LLM_Integration_for_Automated_Reporting.ipynb
├── src/               # Source code modules
│   ├── data/          # Data extraction and preprocessing
│   ├── models/        # Machine learning model implementations
│   ├── visualization/ # Visualization functions
│   └── utils/         # Utility functions
├── results/           # Output: models, visualizations, reports (not tracked)
├── docs/              # Documentation
│   └── schema/        # Database schema documentation and ER diagrams
├── conf/              # Configuration files
├── Makefile           # Project automation
├── CHANGELOG.md       # Version history
└── README.md
```

---

## 🛠️ Getting Started

### Prerequisites

- Python 3.12
- Git
- Access to SecurityOnion instance or sample security logs
- Conda environment management

### Installation

```bash
# Clone this repository
git clone git@github.com:INworldR/SecOn.git
cd SecOn

# Set up Python virtual environment
make setup

# Install DuckDB for optimized analytical processing
conda install -c conda-forge duckdb

# Configure environment variables
cp conf/example.env conf/.env
# Edit .env file with your specific settings
```

### Running Notebooks

```bash
# Start Jupyter Lab
make notebooks

# Alternatively, use the provided script
./start-jupyterlab.sh
```

---

## 📚 Key Innovations

- **Optimized Data Architecture**: Columnar database design (DuckDB) for high-performance security analytics
- **Comparative Analysis Framework**: Systematic evaluation of different algorithms and techniques
- **Hybrid Detection Approaches**: Combining supervised and unsupervised methods
- **Explainable AI for Security**: Making complex models interpretable for security analysts
- **Automated Intelligence Generation**: Using LLMs to transform raw analysis into actionable reports
- **Performance Benchmarking**: Quantitative assessment of model efficacy for security use cases
- **Relational Schema Optimization**: Custom-designed schema that balances normalization with analytical performance

---

## 📄 License

GNU General Public License v3.0

---

## ✍️ Author

Marc Haenle - me@haenle.com
