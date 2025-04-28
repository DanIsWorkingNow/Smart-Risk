# test_auto_label.py

# Your keyword lists and auto_label function with debug prints
SHARIAH_COMPLIANT_KEYWORDS = [
    "mudarabah", "musharakah", "murabaha", "ijara", "sukuk", "takaful",
    "qard al-hasan", "wakalah", "istisna", "profit-sharing", "asset-backed",
    "risk-sharing", "halal financing", "no interest", "interest-free",
    "zero riba", "zakat", "sadaqah", "charitable", "transparent", "fair trade"
]

SHARIAH_NON_COMPLIANT_KEYWORDS = [
    "riba", "interest", "usury", "loan interest", "fixed return",
    "gharar", "uncertainty", "speculation", "gambling", "maisir",
    "alcohol", "pork", "casino", "tobacco", "adult entertainment",
    "conventional banking", "credit cards", "mortgage interest", "haram"
]

def auto_label(text):
    text_lower = str(text).lower()
    print("Input text:", text_lower)
    if any(keyword in text_lower for keyword in SHARIAH_COMPLIANT_KEYWORDS):
        print("Found compliant keyword")
        return 0  # shariah_compliant
    elif any(keyword in text_lower for keyword in SHARIAH_NON_COMPLIANT_KEYWORDS):
        print("Found non-compliant keyword")
        return 1  # shariah_non_compliant
    else:
        print("No keywords found, returning neutral")
        return 2  # neutral

# Test the function with different inputs
texts = [
    "This company offers halal financing and uses musharakah methods.",
    "They charge a high interest rate on all loans.",
    "This business description does not match any specific criteria."
]

for text in texts:
    label = auto_label(text)
    print("Label:", label)
    print("-" * 40)
