import pdfplumber
import json
import pandas as pd
from nltk.tokenize import sent_tokenize
import os

# Step 1: Extract text from PDF
def extract_text_from_pdf(pdf_path):
    print(f"📄 Extracting text from: {pdf_path}...")
    text = ""
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text += page.extract_text() + "\n"
    return text

# Step 2: Clean and split into sentences
def process_text(text):
    sentences = sent_tokenize(text)
    cleaned_sentences = [
        s.strip() for s in sentences 
        if len(s.split()) > 3 and not s.startswith("Page ")
    ]
    return cleaned_sentences

# Step 3: Save to JSON
def save_to_json(sentences, output_path):
    data = [{"text": sentence} for sentence in sentences]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"✅ Saved {len(data)} sentences to {output_path}")

# Step 4: Save to CSV
def save_to_csv(sentences, output_path):
    df = pd.DataFrame({"text": sentences})
    df.to_csv(output_path, index=False, encoding="utf-8")
    print(f"✅ Saved {len(sentences)} sentences to {output_path}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    # List all PDFs in the current directory
    pdf_files = [f for f in os.listdir() if f.lower().endswith('.pdf')]
    
    if not pdf_files:
        print("❌ No PDF files found in the current directory.")
    else:
        print(f"Found {len(pdf_files)} PDFs to process: {pdf_files}")
        
        for pdf_file in pdf_files:
            try:
                # Generate output filenames based on PDF name
                base_name = os.path.splitext(pdf_file)[0]
                json_output = f"{base_name}_data.json"
                csv_output = f"{base_name}_data.csv"
                
                # Run the pipeline
                extracted_text = extract_text_from_pdf(pdf_file)
                sentences = process_text(extracted_text)
                
                # Save outputs
                save_to_json(sentences, json_output)
                save_to_csv(sentences, csv_output)
                
            except Exception as e:
                print(f"❌ Error processing {pdf_file}: {str(e)}")
        
        print("\n🎉 Bulk processing complete! Next steps:")
        print("- Manually label the CSV files in Excel")
        print("- OR upload JSON files to Hugging Face AutoTrain")