# Clustering for Attack Pattern Discovery

This document provides a detailed explanation of the clustering analysis notebook `02_Clustering_for_Attack_Pattern_Discovery.ipynb`, which is used for discovering attack patterns in security logs from Security Onion.

## Overview

The clustering analysis notebook aims to identify groups of similar security events that might indicate malicious activity patterns. By using unsupervised machine learning techniques like K-means and DBSCAN, we can discover groups of events that share common characteristics, which could represent specific attack scenarios or anomalous behaviors.

## Technical Approach

### Data Source

The notebook uses security log data stored in a DuckDB database, specifically from the `security_logs` table created in the `00_Database_Setup_and_Schema.ipynb` notebook. The table schema includes:

- `event_id`: Unique identifier for each log event
- `timestamp`: When the event occurred
- `source_ip`: Origin IP address
- `source_port`: Origin port
- `dest_ip`: Destination IP address
- `dest_port`: Destination port
- `action`: Type of action (e.g., "block", "pass", etc.)
- `protocol`: Network protocol (e.g., "tcp", "udp", etc.)
- `bytes`: Data volume transferred
- `country`: Country of origin
- `log_date`: Date of the log entry
- `source_file`: Original source file name
- `raw_data`: Raw log data (optional)

### Analysis Process

The notebook follows these steps for clustering analysis:

1. **Data Loading and Preparation**
   - Connecting to the DuckDB database
   - Loading a subset of security logs with a valid protocol field
   - Handling missing values and examining data statistics

2. **Feature Engineering**
   - Creating time-based features (hour of day, day of week, weekend flags, business hour flags)
   - Extracting network information (private IP flags, port classifications)
   - Creating one-hot encodings for categorical variables (protocols, countries)
   - Transforming byte counts and adding data volume indicators

3. **Dimensionality Reduction**
   - Applying PCA to reduce the feature space for visualization
   - Dynamic component selection based on available features
   - Visualization of PCA-reduced data with fallbacks for limited feature scenarios

4. **K-means Clustering**
   - Using the Elbow method to find the optimal number of clusters
   - Applying K-means to group similar security events
   - Visualizing the clusters in reduced dimensional space

5. **DBSCAN Clustering**
   - Using DBSCAN as an alternative clustering method that can find outliers
   - Comparing DBSCAN results with K-means clusters
   - Identifying noise points that could represent anomalous behaviors

6. **Cluster Analysis**
   - Analyzing the characteristics of each cluster
   - Identifying patterns in timing, protocols, and geographic origins
   - Visualizing feature importance for each cluster

7. **Identifying Potential Attack Patterns**
   - Evaluating clusters for suspicious characteristics
   - Flagging clusters with high rates of blocked actions, unusual timing, or geographic origins
   - Extracting potentially suspicious events for further investigation

8. **Advanced Visualization**
   - Using t-SNE for more detailed visualization
   - Comparing cluster distributions across different techniques
   - Handling visualization challenges with limited features

## Implementation Details

### Feature Engineering

The feature engineering process is crucial as it transforms raw log data into meaningful numerical features that can be used for clustering. The notebook creates various types of features:

1. **Temporal Features**:
   - `hour_of_day`: Hour when the event occurred (0-23)
   - `day_of_week`: Day of the week (0-6, where 0 is Monday)
   - `is_weekend`: Binary indicator for weekend days
   - `is_business_hours`: Binary indicator for business hours (9am-5pm)

2. **Network Features**:
   - `source_ip_is_private`: Whether the source IP is from a private network
   - `is_web_port`, `is_mail_port`, `is_database_port`: Port classifications
   - One-hot encoded protocol types (e.g., `protocol_tcp`, `protocol_udp`)

3. **Geographic Features**:
   - One-hot encoded country information for top countries
   - Flags for suspicious countries of origin

4. **Traffic Features**:
   - `bytes_log`: Log-transformed byte count for better distribution
   - `large_transfer`: Flag for unusually large data transfers

### Clustering Approaches

The notebook implements two different clustering techniques:

1. **K-means Clustering**:
   - Partitioning method that aims to minimize the intra-cluster variance
   - Optimal number of clusters determined using the Elbow method
   - Works well for finding compact, spherical clusters

2. **DBSCAN (Density-Based Spatial Clustering of Applications with Noise)**:
   - Identifies clusters as areas of high density separated by areas of low density
   - Automatically detects outliers (noise points)
   - Does not require specifying the number of clusters in advance
   - Particularly useful for identifying unusual events that don't fit well into any cluster

### Handling Limited Features

The notebook includes special handling for scenarios where limited numerical features are available:

1. **Synthetic Feature Creation**:
   - Creating additional features when the original set is too small
   - Using modulo operations on port numbers for additional variance

2. **Adaptive Dimensionality Reduction**:
   - Automatically adjusting PCA components based on available features
   - Fallback to 1D visualization with jitter when only one component is available

3. **Visualization Adaptations**:
   - Adding random jitter to 1D projections for better visualization
   - Skipping t-SNE when insufficient features are available
   - Creating synthetic visualization dimensions when needed

### Identifying Suspicious Activities

The notebook defines criteria for identifying potentially suspicious clusters:

1. **Action-Based Criteria**:
   - High proportion of blocked connections
   - Unusual action patterns for specific protocols

2. **Temporal Criteria**:
   - Events concentrated during unusual hours (midnight to 5 AM)
   - Uneven distribution across days/times

3. **Network Criteria**:
   - Multiple source IPs targeting the same destination
   - Unusual port usage patterns

4. **Geographic Criteria**:
   - High traffic from countries associated with threat actors
   - Unusual geographic distribution

## Usage Guide

### Prerequisites

- Python 3.12 or higher
- Access to the SecurityOnion log database (DuckDB format)
- Required libraries: pandas, numpy, matplotlib, seaborn, scikit-learn, duckdb

### Running the Analysis

1. **Prepare the Database**:
   - First run the `00_Database_Setup_and_Schema.ipynb` notebook to prepare the database
   - Ensure the security logs are properly loaded into the DuckDB database

2. **Configure Parameters**:
   - Adjust the SQL query to select the appropriate logs for your analysis
   - Modify the feature engineering function to extract relevant features
   - Tune clustering parameters (e.g., number of clusters, DBSCAN parameters)

3. **Execute the Notebook**:
   - Run the cells in sequence to perform the complete analysis
   - Review the visualizations and cluster statistics
   - Adjust parameters as needed based on initial results

4. **Interpret Results**:
   - Examine cluster characteristics to identify attack patterns
   - Review the suspicious clusters detected by the algorithm
   - Extract specific events for further investigation

### Customization Options

The notebook is designed to be customizable for different security analysis needs:

1. **Feature Engineering**:
   - Add domain-specific features based on your environment
   - Modify the importance of different feature types
   - Add custom flags for known threat indicators

2. **Clustering Parameters**:
   - Adjust the number of clusters in K-means
   - Modify DBSCAN parameters (eps, min_samples) to control cluster density
   - Change dimensionality reduction settings for different visualizations

3. **Suspicious Criteria**:
   - Define custom criteria for what constitutes suspicious behavior
   - Adjust thresholds based on your environment's baseline
   - Add organization-specific indicators of compromise

## Practical Applications

The clustering analysis can be used for several security operations tasks:

1. **Threat Hunting**:
   - Identifying previously unknown attack patterns
   - Discovering zero-day exploits targeting your infrastructure
   - Finding lateral movement within your network

2. **Alert Prioritization**:
   - Grouping similar alerts to reduce analyst workload
   - Identifying high-priority clusters that require immediate attention
   - Filtering out normal operational clusters

3. **Security Posture Assessment**:
   - Understanding the types of attacks targeting your organization
   - Identifying gaps in security controls based on cluster patterns
   - Measuring the effectiveness of security mitigations over time

4. **Anomaly Detection**:
   - Finding outliers that don't fit established patterns
   - Detecting unusual behavior that might indicate compromise
   - Establishing behavioral baselines for network traffic

## Limitations and Considerations

While the clustering analysis provides valuable insights, there are some limitations to consider:

1. **Data Quality Dependencies**:
   - The quality of clusters depends on the completeness of log data
   - Missing fields or inconsistent logging can affect results
   - Pre-filtered logs may miss important patterns

2. **Interpretation Challenges**:
   - Clusters require security expertise to interpret correctly
   - Not all clusters represent attack patterns (false positives)
   - Some sophisticated attacks may span multiple clusters

3. **Computational Considerations**:
   - Large log volumes may require sampling for performance
   - Some clustering algorithms don't scale well to very large datasets
   - Real-time analysis may require optimized implementations

4. **Feature Selection Importance**:
   - The choice of features significantly impacts cluster quality
   - Domain knowledge is required for effective feature engineering
   - Different attack types may require different feature sets

## Future Enhancements

The notebook could be enhanced in several ways:

1. **Advanced Techniques**:
   - Implementing hierarchical clustering for nested attack patterns
   - Adding ensemble clustering for more robust results
   - Incorporating semi-supervised approaches with known attack labels

2. **Performance Optimizations**:
   - Implementing incremental clustering for continuous analysis
   - Adding parallel processing for large datasets
   - Optimizing feature extraction for better scaling

3. **Integration Capabilities**:
   - Adding export functions for integration with SIEM systems
   - Creating automated alert rules based on cluster characteristics
   - Building feedback loops for continuous improvement

4. **Visualization Enhancements**:
   - Interactive visualizations for exploring clusters
   - Timeline views for attack progression
   - Network graphs for related events

## Conclusion

The clustering analysis notebook provides a powerful approach for discovering attack patterns in security logs. By leveraging unsupervised machine learning techniques, security analysts can identify groups of related events that might indicate sophisticated attacks or new threat vectors. The results can guide threat hunting, improve alert prioritization, and enhance overall security posture.