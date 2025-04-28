from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Load your custom model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("KaidoKirito/shariahfin")
model = AutoModelForSequenceClassification.from_pretrained("KaidoKirito/shariahfin")

# Manually set custom label mappings
custom_id2label = {
    0: "Shariah Compliant",
    1: "Shariah Non-Compliant",
    2: "Neutral"
}

custom_label2id = {label: idx for idx, label in custom_id2label.items()}

# Update the model configuration
model.config.id2label = custom_id2label
model.config.label2id = custom_label2id

# Test it out
print(model.config.id2label)