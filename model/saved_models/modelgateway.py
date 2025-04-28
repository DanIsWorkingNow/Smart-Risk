from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Load the model and tokenizer
model_name = "KaidoKirito/shariahfin"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)
model.eval()

def predict_shariah_risk(text):
    # Tokenize the input text
    inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True)
    # Perform inference
    with torch.no_grad():
        outputs = model(**inputs)
    # Get the predicted class index
    prediction_idx = torch.argmax(outputs.logits, dim=1).item()
    labels = ["Halal", "Haram"]  # Adjust based on your model's training
    return labels[prediction_idx]
