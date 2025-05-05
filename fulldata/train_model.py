import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
from sklearn.preprocessing import StandardScaler  # Add this import
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.combine import SMOTEENN
from imblearn.pipeline import Pipeline
import joblib
import os
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder

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
    for col in data.columns:
        if pd.api.types.is_numeric_dtype(data[col]):
            mean_value = data[col].mean()
            data[col] = data[col].fillna(mean_value if pd.notna(mean_value) else 0)
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

# Debug: Print class distribution
label_counts = y.value_counts()
print("Class distribution before merging rare classes:")
print(label_counts)

# Merge rare classes (fewer than 10 samples) into a 'rare' class
min_samples = 10
rare_classes = label_counts[label_counts < min_samples].index
print(f"Classes with fewer than {min_samples} samples (to be merged into 'rare'):", rare_classes)

# Create a new 'rare' class (assign it the next available integer label)
if len(rare_classes) > 0:
    rare_label = max(y) + 1  # Next available label
    print(f"Assigning rare classes to new label: {rare_label}")
    y = y.copy()
    X = X.copy()
    # Replace rare class labels with the new 'rare' label
    y[y.isin(rare_classes)] = rare_label
    # Update the label encoder to include the 'rare' class
    label_encoder = joblib.load('./datasets/label_encoder.pkl')
    new_classes = list(label_encoder.classes_) + ['rare']
    label_encoder.classes_ = np.array(new_classes)
    joblib.dump(label_encoder, './datasets/label_encoder.pkl')  # Save updated label encoder

# Debug: Print class distribution after merging
print("Class distribution after merging rare classes:")
print(y.value_counts())

# Save feature names
feature_names = X.columns.tolist()

# Initialize and fit the StandardScaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)  # Fit and transform the data
X = pd.DataFrame(X_scaled, columns=feature_names)  # Convert back to DataFrame

# Save the scaler
joblib.dump(scaler, 'scaler.pkl')
print("Scaler saved as 'scaler.pkl'")

# Validate data types before resampling
print("Data types of features after scaling:")
print(X.dtypes)
print("Sample of X after scaling:")
print(X.head().to_string())

# Stage 1: Binary Classifier (normal vs. non-normal)
# Create binary labels: 0 for normal (label 15), 1 for non-normal
y_binary = (y != 15).astype(int)  # 0: normal, 1: non-normal

# Undersample the normal class to balance with non-normal
normal_count = (y_binary == 0).sum()
non_normal_count = (y_binary == 1).sum()
undersampler_binary = RandomUnderSampler(sampling_strategy={0: non_normal_count}, random_state=42)

X_binary, y_binary = undersampler_binary.fit_resample(X, y_binary)

# Train a binary Random Forest classifier
binary_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
binary_model.fit(X_binary, y_binary)

# Use precision-recall curve to find the optimal threshold
X_train_bin, X_test_bin, y_train_bin, y_test_bin = train_test_split(X_binary, y_binary, test_size=0.2, stratify=y_binary, random_state=42)
y_pred_prob_bin = binary_model.predict_proba(X_test_bin)[:, 1]  # Probability of non-normal
precision, recall, thresholds = precision_recall_curve(y_test_bin, y_pred_prob_bin)
# Find the threshold that maximizes F1-score
f1_scores = 2 * (precision * recall) / (precision + recall)
optimal_idx = np.argmax(f1_scores)
optimal_threshold = thresholds[optimal_idx]
print(f"Optimal threshold for binary classifier: {optimal_threshold}")

# Override the optimal threshold with a lower value for experimentation
optimal_threshold = 0.5
print(f"Overriding optimal threshold to: {optimal_threshold}")

# Evaluate the binary classifier with the overridden threshold
y_pred_bin = (y_pred_prob_bin >= optimal_threshold).astype(int)
print("Binary Classifier (normal vs. non-normal) Classification Report (threshold=0.5):")
print(classification_report(y_test_bin, y_pred_bin, target_names=['normal', 'non-normal']))

# Stage 2: Multi-Class Classifier for non-normal samples
# Select non-normal samples (original labels where y != 15)
non_normal_mask = (y != 15)
X_non_normal = X[non_normal_mask].copy()
y_non_normal = y[non_normal_mask].copy()

# Debug: Print class distribution of non-normal samples
print("Class distribution of non-normal samples:")
print(y_non_normal.value_counts())

# Re-encode the non-normal labels to be zero-based and consecutive
label_encoder_non_normal = LabelEncoder()
y_non_normal_encoded = label_encoder_non_normal.fit_transform(y_non_normal)
# Create a mapping from original labels to new encoded labels
label_mapping = dict(zip(label_encoder_non_normal.classes_, range(len(label_encoder_non_normal.classes_))))
print("Label mapping (original to new encoded):", label_mapping)

# Resampling for non-normal samples
# Undersample majority non-normal classes (e.g., neptune: label 13) to 20,000
undersampler_non_normal = RandomUnderSampler(sampling_strategy={label_mapping[13]: 20000}, random_state=42)
# Oversample minority classes to 10,000 each using SMOTEENN
label_counts_non_normal = pd.Series(y_non_normal_encoded).value_counts()
sampling_strategy = {label: 10000 for label in label_counts_non_normal.index if label_counts_non_normal[label] < 10000}
oversampler_non_normal = SMOTEENN(smote=SMOTE(sampling_strategy=sampling_strategy, random_state=42), random_state=42)

# Define the pipeline
pipeline_non_normal = Pipeline([
    ('undersampler', undersampler_non_normal),
    ('oversampler', oversampler_non_normal)
])

# Apply the pipeline
X_non_normal_resampled, y_non_normal_resampled = pipeline_non_normal.fit_resample(X_non_normal, y_non_normal_encoded)

# Print resampled dataset shape
print(f"Resampled non-normal dataset shape: {X_non_normal_resampled.shape}")
print("Class distribution after resampling non-normal samples (encoded labels):")
print(pd.Series(y_non_normal_resampled).value_counts())

# Split data with stratification
X_train_non_normal, X_test_non_normal, y_train_non_normal, y_test_non_normal = train_test_split(
    X_non_normal_resampled, y_non_normal_resampled, test_size=0.2, stratify=y_non_normal_resampled, random_state=42
)

# Compute custom class weights for the multi-class classifier
class_counts = pd.Series(y_non_normal_resampled).value_counts()
total_samples = len(y_non_normal_resampled)
class_weights = {label: total_samples / (len(class_counts) * count) for label, count in class_counts.items()}

# Increase weights for rare classes (original labels with low support)
for original_label in label_mapping:
    if original_label in [4, 6, 8, 18, 21, 30, 31]:  # Rare classes from original distribution
        encoded_label = label_mapping[original_label]
        class_weights[encoded_label] *= 2  # Double the weight for rare classes

# Map the weights to the new encoded labels
weight_array = np.array([class_weights[label] for label in y_non_normal_resampled])

# Train the multi-class classifier for non-normal samples using XGBoost with tuned hyperparameters
multi_model = xgb.XGBClassifier(
    objective='multi:softmax',
    num_class=len(label_encoder_non_normal.classes_),
    eval_metric='mlogloss',
    random_state=42,
    max_depth=6,  # Increased depth for better learning
    learning_rate=0.1,  # Lower learning rate for better convergence
    min_child_weight=3,  # Prevent overfitting to rare classes
    subsample=0.8,  # Subsampling to prevent overfitting
    colsample_bytree=0.8,  # Feature subsampling
    n_estimators=200  # More trees for better performance
)
multi_model.fit(X_train_non_normal, y_train_non_normal, sample_weight=weight_array[:len(X_train_non_normal)])

# Evaluate the multi-class classifier
y_pred_non_normal = multi_model.predict(X_test_non_normal)
# Map the predicted labels back to the original labels for reporting
y_test_non_normal_original = label_encoder_non_normal.inverse_transform(y_test_non_normal)
y_pred_non_normal_original = label_encoder_non_normal.inverse_transform(y_pred_non_normal)

label_encoder = joblib.load('./datasets/label_encoder.pkl')
unique_classes_non_normal = np.unique(y_non_normal)
target_names_non_normal = [label_encoder.classes_[i] for i in unique_classes_non_normal]

print("Multi-Class Classifier (non-normal) Classification Report:")
print(classification_report(y_test_non_normal_original, y_pred_non_normal_original, target_names=target_names_non_normal))
print("Confusion Matrix for non-normal classes:")
print(confusion_matrix(y_test_non_normal_original, y_pred_non_normal_original))

# Combine the two models for final prediction with the overridden threshold
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

# Evaluate the combined model on the original test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
y_pred_combined = combined_predict(X_test, threshold=optimal_threshold)

# Get unique classes for the final evaluation
unique_classes = np.unique(np.concatenate([y_test, y_pred_combined]))
target_names = [label_encoder.classes_[i] for i in unique_classes]

print("Combined Model Classification Report (threshold=0.5):")
print(classification_report(y_test, y_pred_combined, target_names=target_names))
print("Confusion Matrix for Combined Model:")
print(confusion_matrix(y_test, y_pred_combined))

# Extract and save feature importance
# For RandomForestClassifier (binary model)
feature_importance_binary = pd.DataFrame({
    'feature': feature_names,
    'importance': binary_model.feature_importances_
}).sort_values(by='importance', ascending=False)
print("Feature Importance (Binary Classifier):")
print(feature_importance_binary)
feature_importance_binary.to_csv('feature_importance_binary.csv', index=False)
print("Feature importance for binary classifier saved to 'feature_importance_binary.csv'")

# For XGBoost (multi-class model)
feature_importance_multi = pd.DataFrame({
    'feature': feature_names,
    'importance': multi_model.feature_importances_
}).sort_values(by='importance', ascending=False)
print("Feature Importance (Multi-Class Classifier):")
print(feature_importance_multi)
feature_importance_multi.to_csv('feature_importance_multi.csv', index=False)
print("Feature importance for multi-class classifier saved to 'feature_importance_multi.csv'")

# Save the trained models, feature names, optimal threshold, and label encoder for non-normal classes
joblib.dump(binary_model, 'binary_model.pkl')
joblib.dump(multi_model, 'multi_model.pkl')
joblib.dump(feature_names, 'feature_names.pkl')
joblib.dump(optimal_threshold, 'optimal_threshold.pkl')
joblib.dump(label_encoder_non_normal, 'label_encoder_non_normal.pkl')

print("Model training completed and saved as 'binary_model.pkl' and 'multi_model.pkl'.")
print(f"Overridden threshold saved as 'optimal_threshold.pkl': {optimal_threshold}")
print("Label encoder for non-normal classes saved as 'label_encoder_non_normal.pkl'")