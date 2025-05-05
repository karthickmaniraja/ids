readme.txt

app.py-main application
train_model.py-used to train model
preprocess_data.py-preprocess training data to train model


how to start the application:
1.go to IDS Project Folder.
2.open terminal.
3.type .\venv\Scripts\Activate to activate virtual environment.
4.open a new terminal in the frontend folder.
5.type npm run dev and go to the link in the output.


note:
1.chrome browser is recommended, try to avoid brave browser.
2.dataset folder contains the training and testing datasets(NSL-KDD Dataset - contains network attacks dataset which is commonly used).
3.when running in a new machine make sure to connect the mongodb dataset to the backend to ensure functionality.


machine learning model used-
1.Binary classifier : Random Forest (to classify between 1:normal and 0:attack)
2.Multi Class Classifier : XGBoost(to classify the type of attack[it is sent to this model when the binary classifier classifies the packet as a threat or attack i.e, 0])

Detectable Attacks
The IDS predicts 33 traffic classes (1 normal, 32 attacks), mapped via label_to_name:
apache2 (0): Apache server vulnerabilities.
back (1): Backdoor attacks exploiting server misconfigurations.
buffer_overflow (2): Exploits overwriting memory buffers.
ftp_write (3): Unauthorized FTP writes.
guess_passwd (4): Brute-force password guessing.
httptunnel (5): HTTP tunneling to bypass firewalls.
imap (6): IMAP protocol exploits.
ipsweep (7): IP address scanning.
land (8): Local Area Network Denial attacks.
loadmodule (9): Dynamic module loading exploits.
mailbomb (10): Email flooding attacks.
mscan (11): Multi-protocol scanning.
multihop (12): Multi-stage attacks via intermediaries.
neptune (13): SYN flood DoS attacks.
nmap (14): Network mapping scans.
normal (15): Benign traffic.
perl (16): Perl script exploits.
phf (17): PHF CGI script vulnerabilities.
pod (18): Ping of Death attacks.
portsweep (19): Port scanning.
processtable (20): Process table overflows.
rootkit (21): Root-level privilege escalation.
saint (22): SAINT scanning tool exploits.
satan (23): SATAN scanning tool exploits.
smurf (24): ICMP amplification attacks.
snmpgetattack (25): SNMP reconnaissance.
snmpguess (26): SNMP community string guessing.
spy (27): Spyware-like intrusions.
teardrop (28): Fragmented packet DoS attacks.
warezclient (29): Warez distribution clients.
warezmaster (30): Warez distribution servers.
worm (31): Self-replicating malware.
rare (32): Aggregated rare attack types (<10 samples).


Accuracy : 
Binary classifier : 0.99
Multi-Class Classifier : 
     1. 0.9 (if the number attacks is reduced from 32 to 20 common attacks)
     2. 0.78 (when all 32 attacks are includes,happens due to complex attacks and limited data to train specific attacks(<20)


Testing : 
Used Multiple functions to test the model using real packets.
  Example Functions:
     1.generate_real_time_data - send random data to the model with high attack features
     2.generate_real_time_data_neptune - simulate Neptune attack(SYN Flood) with High SYN error rate (serror_rate = 1.0),Zero data transfer (src_bytes = 0, dst_bytes = 0),Large connection count (count = 166, srv_count = 9),Attacker floods the target, causing a huge increase in connection requests.
     3.generate_real_time_data_back - simulate back attack(DOS) with arge source and destination byte sizes (src_bytes = 54540, dst_bytes = 8314),No errors in the connection (serror_rate = 0.0, rerror_rate = 0.0),All connections go to the same service (same_srv_rate = 1.0, diff_srv_rate = 0.0),Target system sees repeated requests in a short time.

Uncomment the function Thread for testing


Tools Used :
Summary of Tools and Frameworks
Category	        Tools/Frameworks
Web Framework	        Flask, Flask-SocketIO, Flask-CORS
Packet Capture	        Scapy
Machine Learning	NumPy, Pandas, Joblib, Scikit-learn (implied)
Cryptography	        PyCryptodome (Crypto), bcrypt, PyJWT (jwt), hashlib, base64
Database	        PyMongo (MongoDB)
System Monitoring	psutil
Logging	                logging
Time Handling	        datetime, pytz
Concurrency	        threading, time
Utilities	        os, json, random, collections.defaultdict, functools.wraps
File/Path Management	os.path