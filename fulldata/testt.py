import joblib

# Load the saved LabelEncoder
label_encoder = joblib.load('label_encoder.pkl')

# Numeric prediction value
numeric_label = 11

# Decode the label
decoded_label = label_encoder.inverse_transform([numeric_label])
print(f"The decoded label for {numeric_label} is: {decoded_label[0]}")
