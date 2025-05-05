import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import os

# Define paths
test_data_path = './dataset/KDDTest+.txt'
binary_model_path = 'binary_model.pkl'
multi_model_path = 'multi_model.pkl'
feature_names_path = 'feature_names.pkl'
cat_encoders_path = './datasets/cat_encoders.pkl'
label_encoder_path = './datasets/label_encoder.pkl'
scaler_path = './datasets/scaler.pkl'
optimal_threshold_path = 'optimal_threshold.pkl'
label_encoder_non_normal_path = 'label_encoder_non_normal.pkl'

# Verify files exist
for path in [test_data_path, binary_model_path, multi_model_path, feature_names_path, cat_encoders_path, label_encoder_path, scaler_path, optimal_threshold_path, label_encoder_non_normal_path]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

# Define column names (41 features + label + difficulty)
column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty'
]

# Load the test data
test_data = pd.read_csv(test_data_path, header=None, names=column_names)

# Debug: Print the first few rows of the raw data
print("First 5 rows of raw test data:")
print(test_data.head(5).to_string())

# Debug: Print the label and difficulty columns
print("Sample values of label:", test_data['label'].head(10).tolist())
print("Sample values of difficulty:", test_data['difficulty'].head(10).tolist())

# Drop the difficulty column as it's not needed for prediction
test_data = test_data.drop(columns=['difficulty'])

print(f"Test dataset shape after dropping difficulty: {test_data.shape}")

# Load the categorical encoders and label encoder
cat_encoders = joblib.load(cat_encoders_path)
label_encoder = joblib.load(label_encoder_path)

# Debug: Print the known labels from the label encoder
print("Known labels from label_encoder:", label_encoder.classes_)

# Define categorical columns
cat_cols = ['protocol_type', 'service', 'flag']

# Encode categorical columns, handling unseen categories
for col in cat_cols:
    if col in cat_encoders:
        # Get the known categories from the encoder
        known_categories = set(cat_encoders[col].classes_)
        # Replace unseen categories with the most common category (first class)
        test_data[col] = test_data[col].apply(lambda x: x if x in known_categories else cat_encoders[col].classes_[0])
        test_data[col] = cat_encoders[col].transform(test_data[col].astype(str))
    else:
        raise KeyError(f"Encoder for {col} not found in cat_encoders.pkl")

# Encode the labels, handling unseen labels
known_labels = set(label_encoder.classes_)
print("Unique labels in test data:", set(test_data['label']))

# Map unseen labels to the 'rare' class (last label in label_encoder.classes_)
rare_label = len(label_encoder.classes_) - 1  # 'rare' is the last class
test_data['label'] = test_data['label'].apply(lambda x: x if x in known_labels else label_encoder.classes_[rare_label])
print("Labels after mapping unseen to 'rare':", test_data['label'].head(10).tolist())

# Encode the labels
test_data['label'] = label_encoder.transform(test_data['label'].astype(str))

# Convert all columns to numeric, handling any potential issues
for col in test_data.columns:
    if col != 'label':
        test_data[col] = pd.to_numeric(test_data[col], errors='coerce')
    else:
        test_data[col] = pd.to_numeric(test_data[col], errors='coerce', downcast='integer')

# Handle NaN values (same as training)
if test_data.isnull().any().any():
    print("NaN values detected in test data. Filling with column means or 0 if mean is NaN...")
    for col in test_data.columns:
        if pd.api.types.is_numeric_dtype(test_data[col]):
            mean_value = test_data[col].mean()
            test_data[col] = test_data[col].fillna(mean_value if pd.notna(mean_value) else 0)
    if test_data['label'].isnull().any():
        test_data['label'] = test_data['label'].fillna(test_data['label'].mode()[0])

print("NaN count per column after filling:")
print(test_data.isnull().sum())

# Prepare features and labels
X_test = test_data.drop(columns=['label'])
y_test = test_data['label']

# Load the feature names and ensure the test data has the same features
feature_names = joblib.load(feature_names_path)
if list(X_test.columns) != feature_names:
    print("Feature mismatch between training and test data. Aligning test data...")
    # Add missing columns with zeros
    for col in feature_names:
        if col not in X_test.columns:
            X_test[col] = 0
    # Reorder columns to match training data
    X_test = X_test[feature_names]

# Load the scaler and normalize the test data
scaler = joblib.load(scaler_path)
numeric_cols = X_test.select_dtypes(include=np.number).columns
X_test[numeric_cols] = scaler.transform(X_test[numeric_cols])

# Load the trained models, optimal threshold, and non-normal label encoder
binary_model = joblib.load(binary_model_path)
multi_model = joblib.load(multi_model_path)
optimal_threshold = joblib.load(optimal_threshold_path)
label_encoder_non_normal = joblib.load(label_encoder_non_normal_path)
print(f"Using threshold: {optimal_threshold}")

# Combined prediction function with the threshold
def combined_predict(X, threshold):
    # Stage 1: Predict normal vs. non-normal with the threshold
    binary_pred_prob = binary_model.predict_proba(X)[:, 1]  # Probability of non-normal
    binary_pred = (binary_pred_prob >= threshold).astype(int)
    final_pred = np.zeros(len(X), dtype=int)
    
    # If predicted as normal, assign label 15
    normal_mask = (binary_pred == 0)
    final_pred[normal_mask] = 15
    
    # If predicted as non-normal, use the multi-class classifier
    non_normal_mask = (binary_pred == 1)
    if np.any(non_normal_mask):
        # Predict with XGBoost (returns re-encoded labels)
        non_normal_pred = multi_model.predict(X[non_normal_mask])
        # Map the predictions back to the original labels
        non_normal_pred_original = label_encoder_non_normal.inverse_transform(non_normal_pred)
        final_pred[non_normal_mask] = non_normal_pred_original
    
    return final_pred

# Make predictions
y_pred = combined_predict(X_test, threshold=optimal_threshold)

# Get the unique classes in y_test and y_pred
unique_classes = np.unique(np.concatenate([y_test, y_pred]))
# Map these classes to their corresponding names
target_names = [label_encoder.classes_[i] for i in unique_classes]

# Evaluate the model
print("Classification Report on Test Data (threshold=0.5):")
print(classification_report(y_test, y_pred, target_names=target_names))
print("Confusion Matrix on Test Data:")
print(confusion_matrix(y_test, y_pred))

print("Model evaluation on test data completed.")