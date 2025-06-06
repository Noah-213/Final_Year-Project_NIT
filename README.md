Abstract:

Hybrid AI and WAF-based Pipeline for Real-Time API Attack Detection and Monitoring
API injection attacks pose critical security threats that traditional Web Application Firewalls (WAFs) struggle to mitigate due to evolving attack patterns and protocol complexities. This research introduces a hybrid detection pipelinethat synergizes rule-based WAF/CRS signatures with machine learning drivenanalysis of structural and behavioral API features.

The methodology, encompassing systematic feature engineering, rigorousmodel benchmarking, and containerized deployment, achieves near-perfectperformance in both binary attack detection (ROC AUC > 9.8) and multiclass attack classification (macro F1 = 1). Operational validation confirms realtime threat monitoring via integration with Grafana dashboards and Wazuh SIEM, demonstrating production readiness in a reproducible Docker-based environment.

The system demonstrates 99%+ detection accuracy while integrating seamlessly with industry-standard SIEM and monitoring tools, supporting actionable, real-time security operations. While results highlight exceptional accuracy in controlled settings, future work must address real-world operational resilience, including scalability under high-volume traffic, adversarial robustness testing, and automated model drift mitigation.

This work provides an open, extensible blueprint for next-generation API security, bridging machine learning innovation with operational pragmatism.
KEYWORDS: API security, Web Application Firewall, Machine Learning, Containerization, SIEM, Feature Engineering, Hybrid Detection, Operational Monitoring

Authors: BENNOUAR Tarek & HANI Nour El Houda
