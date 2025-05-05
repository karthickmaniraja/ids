# ids
To develop a secure, intelligent intrusion detection system (IDS) that uses machine learning to detect unauthorized access, malicious activities, or abnormal behaviors within healthcare infrastructure in real-time.



Intrusion Detection System for Healthcare Environments: Safeguarding Sensitive Medical Data
This project presents a real-time Intrusion Detection System (IDS) tailored for healthcare networks, particularly targeting the protection of Electronic Health Records (EHRs) and other critical medical data. The system is built using a Flask-based backend, a React frontend, and a two-stage machine learning pipeline, with Scapy for packet capture.

The IDS functions by monitoring network traffic, detecting anomalies using a binary Random Forest classifier, and then classifying specific types of attacks using an XGBoost multi-class classifier. It supports real-time alerts, AES-GCM encryption, JWT-based authentication, and role-based access control (RBAC) to secure data and access.

Key technologies include:

Machine Learning: Scikit-learn, XGBoost, SMOTE, and Imbalanced-learn

Security: AES-GCM encryption, RSA, bcrypt hashing, JWT tokens

Frontend: React + Vite + Tailwind CSS for a responsive UI

Packet Capture: Scapy for real-time traffic from EHR servers and IoT devices

Database: MongoDB (via PyMongo) for storing logs and user data

The system is capable of detecting 33 attack types, including healthcare-specific threats like ransomware, backdoors, and data exfiltration tools. It simulates and identifies threats like SYN floods (e.g., neptune), ransomware (e.g., warezclient), and spying malware (e.g., spy), ensuring compliance with regulations like HIPAA.

