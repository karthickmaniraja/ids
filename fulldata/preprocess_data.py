import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import joblib
import os

# Define the path to the preprocessed data
data_path = './datasets/processed_data.csv'

# Verify the file exists and print its path
if not os.path.exists(data_path):
    raise FileNotFoundError(f"Preprocessed data file not found at: {data_path}")
print(f"Loading data from: {os.path.abspath(data_path)}")

# Load the data without forcing dtypes initially to inspect content
data = pd.read_csv(data_path)

# Print dataset shape for debugging
print(f"Dataset shape: {data.shape}")

# Define categorical columns
cat_cols = ['protocol_type', 'service', 'flag']

# Load the categorical encoders from preprocessing
cat_encoders = joblib.load('./datasets/cat_encoders.pkl')

# Verify and ensure categorical columns are numerical
for col in cat_cols:
    if not pd.api.types.is_numeric_dtype(data[col]):
        print(f"Warning: {col} contains non-numeric values. Re-encoding...")
        data[col] = cat_encoders[col].transform(data[col].astype(str))
    else:
        print(f"{col} is numerical: Sample values - {data[col].head().tolist()}")

# Convert all columns to appropriate numeric types after validation
for col in data.columns:
    if col != 'label':  # Label should remain integer
        data[col] = pd.to_numeric(data[col], errors='coerce')
    else:
        data[col] = pd.to_numeric(data[col], errors='coerce', downcast='integer')

# Handle NaN values before preparing features and labels
if data.isnull().any().any():
    print("NaN values detected. Filling with column means or 0 if mean is NaN...")
    # Fill NaN with the mean of each column, or 0 if the mean is NaN
    for col in data.columns:
        if pd.api.types.is_numeric_dtype(data[col]):
            mean_value = data[col].mean()
            data[col] = data[col].fillna(mean_value if pd.notna(mean_value) else 0)
    # Fill NaN in label with the mode (most common label)
    if data['label'].isnull().any():
        data['label'] = data['label'].fillna(data['label'].mode()[0])

# Verify data after filling NaN
print("Data types after NaN filling:")
print(data.dtypes)
print("Sample of data after NaN filling:")
print(data.head().to_string())
print("NaN count per column after filling:")
print(data.isnull().sum())

# Prepare features and labels
X = data.drop(columns=['label'])
y = data['label']

# Save feature names
feature_names = X.columns.tolist()

# Validate data types before SMOTE
print("Data types of features:")
print(X.dtypes)
print("Sample of X:")
print(X.head().to_string())

# Address class imbalance with SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# Print resampled dataset shape
print(f"Resampled dataset shape: {X_resampled.shape}")

# Split data with stratification
X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, stratify=y_resampled, random_state=42)

# Train the Random Forest Classifier with reduced estimators for testing
model = RandomForestClassifier(n_estimators=10, random_state=42, class_weight='balanced')  # Reduced from 100 to 10
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
label_encoder = joblib.load('./datasets/label_encoder.pkl')
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save the trained model and feature names
joblib.dump(model, 'trained_model.pkl')
joblib.dump(feature_names, 'feature_names.pkl')

print("Model training completed and saved as 'trained_model.pkl'.")