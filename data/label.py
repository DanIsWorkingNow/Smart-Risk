import pandas as pd
import os

# Expanded keyword lists
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
    """Label text based on Shariah compliance keywords."""
    text_lower = str(text).lower()
    if any(keyword in text_lower for keyword in SHARIAH_COMPLIANT_KEYWORDS):
        return 0  # shariah_compliant
    elif any(keyword in text_lower for keyword in SHARIAH_NON_COMPLIANT_KEYWORDS):
        return 1  # shariah_non_compliant
    else:
        return 2  # neutral

def process_files(input_dir="data/csv_outputs", output_dir="data/labeled_outputs"):
    """Process all Shareport CSV files in bulk."""
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Get all Shareport CSV files
    csv_files = [f for f in os.listdir(input_dir) 
                if f.startswith("Shareport") and f.endswith(".csv")]
    
    if not csv_files:
        print(f"❌ No CSV files found in {input_dir}")
        return
    
    print(f"🔍 Found {len(csv_files)} files to process:")
    
    for csv_file in csv_files:
        try:
            # Load CSV
            file_path = os.path.join(input_dir, csv_file)
            df = pd.read_csv(file_path)
            
            # Auto-label
            df["label"] = df["text"].apply(auto_label)
            
            # Save labeled data
            base_name = os.path.splitext(csv_file)[0]
            output_csv = os.path.join(output_dir, f"{base_name}_labeled.csv")
            output_json = os.path.join(output_dir, f"{base_name}_labeled.json")
            
            df.to_csv(output_csv, index=False)
            df.to_json(output_json, orient="records", indent=2)
            
            # Print stats
            print(f"\n✅ Processed {csv_file}:")
            print(f"   - Total sentences: {len(df)}")
            print(f"   - Label distribution:")
            print(df["label"].value_counts().to_string())
            
        except Exception as e:
            print(f"❌ Error processing {csv_file}: {str(e)}")

if __name__ == "__main__":
    print("🚀 Starting bulk labeling process...")
    process_files()
    print("\n🎉 All files processed! Check the 'data/labeled_outputs' folder.")