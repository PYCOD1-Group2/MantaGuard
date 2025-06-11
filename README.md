# 🛡️ MantaGuard
**AI-Powered Network Security Analysis & Anomaly Detection Platform**  
*Comprehensive network monitoring with intelligent threat classification and automated remediation*

![MantaGuard Logo](MantaGuard_Logo.webp)

---

## 📋 Table of Contents
- [About MantaGuard](#-about-mantaguard)
- [Core Features](#-core-features)
- [System Architecture](#-system-architecture)
- [Quick Start Guide](#-quick-start-guide)
- [Detailed User Guide](#-detailed-user-guide)
  - [Network Scanning](#network-scanning)
  - [AI Analysis & Anomaly Detection](#ai-analysis--anomaly-detection)
  - [Connection Browser & Manual Labeling](#connection-browser--manual-labeling)
  - [Model Training & Management](#model-training--management)
  - [Reports & Analytics](#reports--analytics)
  - [Fixes & Patches](#fixes--patches)
- [Advanced Features](#-advanced-features)
- [Installation & Setup](#-installation--setup)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## 🔍 About MantaGuard

MantaGuard is a comprehensive network security platform that combines **real-time packet capture**, **AI-powered anomaly detection**, and **intelligent threat classification** to provide unparalleled network visibility and protection.

### What Makes MantaGuard Special?

- **Hybrid AI Classification**: Combines traditional anomaly detection with advanced multi-class classification
- **Interactive Training Repository**: Build and refine AI models through manual labeling and feedback
- **Professional Web Interface**: Modern, dark-themed dashboard with real-time monitoring
- **Automated Remediation**: Intelligent patches and fixes for detected vulnerabilities
- **Comprehensive Reporting**: Detailed forensic analysis and exportable reports

---

## 🚀 Core Features

### 🔍 **Network Monitoring**
- **Live Packet Capture**: Real-time network traffic monitoring with interface selection
- **PCAP Analysis**: Upload and analyze existing packet capture files
- **Zeek Integration**: Leverage Zeek (formerly Bro) for deep packet inspection
- **Multi-Protocol Support**: TCP, UDP, ICMP, and more

### 🤖 **AI-Powered Detection**
- **Anomaly Detection**: OneClassSVM for identifying unusual network behavior
- **Attack Classification**: Multi-class models for categorizing specific attack types
- **Confidence Scoring**: Intelligent confidence thresholds for accurate detection
- **Unknown Category Handling**: Graceful handling of unclassified anomalies

### 📊 **Training & Learning**
- **Manual Labeling System**: User-friendly interface for training data creation
- **Training Repository**: SQLite-based storage for labeled connections
- **Model Retraining**: Continuous improvement through reinforcement learning
- **Performance Metrics**: Detailed model evaluation and validation

### 🛡️ **Security & Remediation**
- **Automated Patching**: Intelligent fixes for detected vulnerabilities
- **Port Management**: Automated closing of suspicious open ports
- **IP Blocking**: Dynamic blacklisting of malicious addresses
- **Forensic Analysis**: Detailed investigation tools and evidence collection

---

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │────│  Flask Backend  │────│ AI Engine      │
│   (Bootstrap)   │    │  (Python)       │    │ (Scikit-learn) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Connection      │    │ Training        │    │ Zeek Parser     │
│ Browser         │────│ Repository      │────│ (Network Data)  │
│ (Labeling UI)   │    │ (SQLite)        │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Reports &       │    │ Model Storage   │    │ Packet Capture  │
│ Analytics       │────│ (Joblib)        │────│ (Live/PCAP)     │
│ (Visualizations)│    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## ⚡ Quick Start Guide

### 1. **Launch MantaGuard**
```bash
python app.py
```
Navigate to `http://localhost:5000` in your browser.

### 2. **Start Network Scanning**
1. Go to **Scanning** tab
2. Select your network interface
3. Click **Start Live Capture**
4. Monitor real-time traffic

### 3. **Review Detected Anomalies**
1. Navigate to **Reports** tab
2. View detected threats and anomalies
3. Click on any anomaly for detailed analysis

### 4. **Label Training Data** (Optional)
1. Go to **Connection Browser** tab
2. Filter connections by anomaly status
3. Select connections and apply labels
4. Train improved models

---

## 📖 Detailed User Guide

## Network Scanning

### Live Packet Capture
The scanning interface allows you to monitor network traffic in real-time:

1. **Interface Selection**: Choose your network interface from the dropdown
2. **Capture Settings**: Configure capture duration and filters
3. **Start Monitoring**: Begin live packet capture
4. **Real-time Analysis**: View connections as they're processed by AI

**Best Practices:**
- Use the primary network interface for comprehensive monitoring
- Start with shorter capture durations for testing
- Monitor the capture status indicator for real-time feedback

### PCAP File Analysis
Upload and analyze existing packet capture files:

1. **File Upload**: Drag and drop or browse for .pcap/.pcapng files
2. **Processing**: Watch as files are parsed through Zeek
3. **Analysis**: AI models automatically analyze all connections
4. **Results**: Review findings in the Reports section

**Supported Formats:**
- `.pcap` - Standard packet capture format
- `.pcapng` - Next generation packet capture format
- `.cap` - Alternative packet capture format

---

## AI Analysis & Anomaly Detection

### How the AI Engine Works

MantaGuard uses a **hybrid classification approach**:

1. **Feature Extraction**: Network connections converted to feature vectors
2. **Anomaly Detection**: OneClassSVM identifies unusual patterns
3. **Attack Classification**: Multi-class models categorize specific threats
4. **Confidence Assessment**: Scoring system determines reliability

### Understanding AI Results

**Anomaly Scores:**
- `< -0.5`: Highly anomalous (likely threat)
- `-0.5 to 0`: Moderately suspicious
- `> 0`: Normal behavior

**Classification Categories:**
- **Reconnaissance**: Port scans, host discovery, service enumeration
- **Exploitation**: Brute force attacks, buffer overflows, privilege escalation
- **Persistence**: Backdoors, lateral movement, data exfiltration
- **Denial of Service**: DDoS attacks, resource exhaustion
- **Malware**: C2 communication, malware downloads, infected hosts
- **Unknown**: Suspicious but unclassified activity

### Model Management

**Available Models:**
- **Base Model**: Pre-trained on common attack patterns
- **Custom Models**: Trained on your specific network data
- **Hybrid Models**: Combination of anomaly detection + classification

**Model Selection:**
- Click the AI model indicator in the header
- Switch between available model versions
- View model performance metrics

---

## Connection Browser & Manual Labeling

The Connection Browser is MantaGuard's powerful training interface for building better AI models.

### Browsing Connections

**Filter Options:**
- **Anomaly Status**: View only anomalies or normal traffic
- **Label Category**: Filter by attack type
- **Review Status**: Track labeling progress
- **Date Range**: Analyze specific time periods
- **Training Source**: See data origin

**Connection Details:**
Each connection shows:
- Source and destination IPs/ports
- Protocol and service information
- Anomaly score and classification
- Current label and review status

### Manual Labeling Workflow

1. **Filter Connections**: Use filters to find unlabeled anomalies
2. **Select Connections**: Check boxes for bulk operations
3. **Choose Labels**: 
   - **Category**: Main attack type (reconnaissance, exploitation, etc.)
   - **Subcategory**: Specific technique (port-scan, brute-force-attack, etc.)
   - **Confidence**: Your certainty in the label (low/medium/high)
4. **Add Context**: Include notes about your labeling decision
5. **Apply Labels**: Bulk update selected connections

**Labeling Best Practices:**
- Start with high-confidence, obvious cases
- Use "unknown" for suspicious but unclear activity
- Add detailed notes for complex cases
- Review and verify labels periodically

### Training Data Management

**Import Data:**
- **Automatic Import**: Scan results are automatically imported after network analysis
- **Manual Import**: Use "Import from Analysis" button if needed
- **Data Sources**: Live captures, PCAP uploads, and legacy analysis results

**Export Data:**
- Export labeled datasets for external analysis
- Share training data between systems
- Backup valuable labeled data

---

## Model Training & Management

⚠️ **DISCLAIMER: DEVELOPMENT FEATURES**
The model training, retraining, and advanced AI features described below are still under active development and may not be fully stable. Use at your own risk. These features are provided as-is for testing and development purposes.

### Training Multi-Class Models

1. **Prepare Data**: Ensure sufficient labeled examples per category
2. **Configure Training**:
   - **Classifier Type**: Random Forest or Gradient Boosting
   - **Minimum Confidence**: Filter training data quality
   - **Hyperparameter Tuning**: Enable for optimal performance
3. **Start Training**: Monitor progress and validation metrics
4. **Evaluate Results**: Review accuracy, precision, and recall

**Training Requirements:**
- Minimum 20 labeled connections total
- At least 10 examples per attack category
- Balanced representation across categories

### Performance Monitoring

**Key Metrics:**
- **Accuracy**: Overall classification correctness
- **Confident Accuracy**: Accuracy for high-confidence predictions
- **Cross-Validation**: Model generalization performance
- **Confusion Matrix**: Detailed classification breakdown

**Model Validation:**
- Automatic train/test splitting
- Cross-validation scoring
- Feature importance analysis
- Performance comparison across versions

---

## Reports & Analytics

### Security Dashboard

**Overview Metrics:**
- Total connections analyzed
- Anomalies detected
- Top attack categories
- Network activity trends

**Detailed Reports:**
- Per-scan analysis summaries
- Anomaly distribution charts
- Timeline visualizations
- Geographic threat mapping

### Forensic Analysis

**Connection Details:**
- Full packet-level analysis
- Protocol-specific insights
- Temporal correlation analysis
- Attack chain reconstruction

**Evidence Collection:**
- Exportable forensic reports
- PCAP file extraction
- Evidence preservation
- Audit trail maintenance

---

## Fixes & Patches

### Automated Remediation

MantaGuard can automatically respond to detected threats:

**Port Management:**
- Close suspicious open ports
- Block unauthorized services
- Firewall rule updates

**IP Blocking:**
- Dynamic blacklisting
- Threat intelligence integration
- Temporary vs. permanent blocks

**Vulnerability Patching:**
- Automated security updates
- Configuration fixes
- Service hardening

### Manual Interventions

**Guided Remediation:**
- Step-by-step fix instructions
- Risk assessment for each action
- Rollback procedures
- Impact analysis

**Custom Patches:**
- User-defined remediation scripts
- Integration with existing tools
- Scheduled maintenance windows

---

## 🔧 Advanced Features

### API Integration

MantaGuard provides REST APIs for integration:

```python
# Example: Get connection data
GET /api/connections?limit=100&is_anomaly=true

# Example: Label connections
POST /api/connections/label
{
    "uids": ["conn_123", "conn_456"],
    "category": "reconnaissance",
    "subcategory": "port-scan",
    "confidence": "high"
}

# Example: Train model
POST /api/models/multi-class-train
{
    "classifier_type": "random_forest",
    "min_confidence": "medium"
}
```

### Custom Feature Engineering

**Feature Categories:**
- **Behavioral**: Connection patterns and timing
- **Statistical**: Packet size distributions, rate analysis
- **Protocol-Specific**: HTTP headers, DNS queries, TLS handshakes
- **Temporal**: Time-based patterns and sequences

### Integration Points

**External Tools:**
- **SIEM Integration**: Send alerts to security platforms
- **Threat Intelligence**: Enrich data with external feeds
- **Network Tools**: Integration with existing security stack

---

## 💻 Installation & Setup

### Prerequisites

**System Requirements:**
- Python 3.8 or higher
- 4GB+ RAM recommended
- Network interface access
- Administrative privileges (for packet capture)

**Required Dependencies:**
```bash
pip install -r requirements.txt
```

### Installation Steps

1. **Clone Repository:**
```bash
git clone https://github.com/your-username/MantaGuard.git
cd MantaGuard
```

2. **Install Dependencies:**
```bash
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -r requirements.txt
```

3. **Initialize System:**
```bash
python -c "from mantaguard.utils.config import initialize_system; initialize_system()"
```

4. **Start Application:**
```bash
python app.py
```

### Configuration

**Environment Variables:**
- `MANTAGUARD_DEBUG`: Enable debug mode
- `MANTAGUARD_PORT`: Custom port (default: 5000)
- `MANTAGUARD_MODEL_DIR`: Custom model directory

**Configuration Files:**
- `config/settings.yaml`: Main configuration
- `data/unknown_categories.json`: Custom category definitions

---

## 🔧 Troubleshooting

### Common Issues

**"No Network Interfaces Found"**
- Ensure administrative privileges
- Check network interface availability
- Verify driver compatibility

**"Model Loading Failed"**
- Check model file integrity
- Verify Python dependencies
- Review error logs in console

**"PCAP Upload Failed"**
- Confirm file format compatibility
- Check file size limits
- Ensure sufficient disk space

**"Training Data Insufficient"**
- Label more connections manually
- Import additional training data
- Balance category representation

### Performance Optimization

**Large Network Environments:**
- Increase capture buffer sizes
- Use sampling for high-traffic networks
- Deploy distributed scanning

**Memory Management:**
- Monitor feature vector sizes
- Implement data pagination
- Regular model cleanup

### Getting Help

**Debug Information:**
1. Check browser console for JavaScript errors
2. Review Flask application logs
3. Examine model training outputs
4. Verify database integrity

**Community Support:**
- GitHub Issues for bug reports
- Discussions for feature requests
- Wiki for extended documentation

---

## 🤝 Contributing

We welcome contributions to MantaGuard! Here's how to get involved:

### Development Setup

1. **Fork and Clone:**
```bash
git clone https://github.com/your-fork/MantaGuard.git
cd MantaGuard
```

2. **Development Environment:**
```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
uv pip install -r requirements-dev.txt
```

3. **Run Tests:**
```bash
pytest tests/
```

### Contribution Guidelines

**Code Standards:**
- Follow PEP 8 style guidelines
- Include comprehensive docstrings
- Add unit tests for new features
- Update documentation as needed

**Feature Development:**
- Create feature branches from `main`
- Submit pull requests with detailed descriptions
- Include test cases and documentation
- Ensure backward compatibility

**Bug Reports:**
- Use GitHub Issues template
- Include reproduction steps
- Provide system information
- Attach relevant logs

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Zeek Project**: Network analysis framework
- **Scikit-learn**: Machine learning library
- **Flask**: Web application framework
- **Bootstrap**: UI component library
- **Security Research Community**: Threat intelligence and methodology

---

**MantaGuard** - *Protecting your network with intelligent analysis*

For questions, support, or feature requests, please visit our [GitHub repository](https://github.com/your-username/MantaGuard).