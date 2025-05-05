import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, confusion_matrix

# Load the preprocessed dataset
data = pd.read_csv('C:/Users/Ashwi/OneDrive/Desktop/IDS Project/datasets/processed_data.csv')

# Load the trained model using joblib
model = joblib.load('C:/Users/Ashwi/OneDrive/Desktop/IDS Project/trained_model.pkl')

# Prepare the data for prediction
X_test = data.drop(columns=['label'])
y_test = data['label']

# Make predictions
y_pred = model.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy * 100:.2f}%')

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
print('Confusion Matrix:')
print(cm)
