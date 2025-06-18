import openai
import os
from typing import Dict, List, Tuple
import PyPDF2
import docx
from dotenv import load_dotenv

load_dotenv()

class OpenAIShariahAnalyzer:
    def __init__(self):
        openai.api_key = os.getenv('OPENAI_API_KEY')
        self.model = os.getenv('OPENAI_MODEL', 'gpt-4-1106-preview')
        
        # Shariah compliance criteria based on SC Malaysia guidelines
        self.shariah_prompt = """
        You are an expert Shariah compliance analyst. Analyze the provided financial document according to the Securities Commission Malaysia's Shariah-Compliant Securities Screening Methodology.

        CLASSIFICATION CRITERIA:
        
        **HARAM (Non-Compliant):**
        - Conventional banking and lending
        - Conventional insurance
        - Gambling (>5% revenue/profit)
        - Liquor and liquor-related activities (>5% revenue/profit)
        - Pork and pork-related activities (>5% revenue/profit)
        - Non-halal food without certification (>20% revenue/profit)
        - Tobacco and cigarettes (>5% revenue/profit)
        - Interest income >5% of total income
        - Debt-to-assets ratio >33%
        - Cash-to-assets ratio >33%
        - Entertainment activities against Islamic principles (>20% revenue/profit)

        **DOUBTFUL (Requires Review):**
        - Activities approaching the threshold limits
        - Unclear business nature or insufficient information
        - Mixed revenue streams requiring detailed analysis
        - Companies with recent changes in business model

        **HALAL (Compliant):**
        - Business activities align with Islamic principles
        - Financial ratios within acceptable limits
        - No involvement in prohibited activities
        - Transparent and Shariah-compliant operations

        Analyze the document and provide:
        1. Classification: HALAL/DOUBTFUL/HARAM
        2. Confidence Score: 0-100%
        3. Key Findings: List specific compliance/non-compliance factors
        4. Recommendations: Next steps for review
        """

    def extract_text_from_file(self, file_path: str) -> str:
        """Extract text from uploaded files"""
        file_extension = file_path.split('.')[-1].lower()
        
        try:
            if file_extension == 'pdf':
                return self._extract_from_pdf(file_path)
            elif file_extension == 'docx':
                return self._extract_from_docx(file_path)
            elif file_extension == 'txt':
                return self._extract_from_txt(file_path)
            else:
                raise ValueError(f"Unsupported file type: {file_extension}")
        except Exception as e:
            raise Exception(f"Error extracting text: {str(e)}")

    def _extract_from_pdf(self, file_path: str) -> str:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text()
        return text

    def _extract_from_docx(self, file_path: str) -> str:
        doc = docx.Document(file_path)
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text

    def _extract_from_txt(self, file_path: str) -> str:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()

    def analyze_shariah_compliance(self, document_text: str) -> Dict:
        """Analyze document for Shariah compliance using OpenAI"""
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.shariah_prompt},
                    {"role": "user", "content": f"Please analyze this financial document for Shariah compliance:\n\n{document_text}"}
                ],
                max_tokens=1000,
                temperature=0.1
            )
            
            analysis_result = response.choices[0].message.content
            return self._parse_analysis_result(analysis_result)
            
        except Exception as e:
            return {
                "classification": "ERROR",
                "confidence_score": 0,
                "key_findings": [f"Analysis failed: {str(e)}"],
                "recommendations": ["Please check the document and try again"],
                "raw_response": ""
            }

    def _parse_analysis_result(self, analysis_text: str) -> Dict:
        """Parse OpenAI response into structured format"""
        lines = analysis_text.split('\n')
        
        result = {
            "classification": "DOUBTFUL",
            "confidence_score": 50,
            "key_findings": [],
            "recommendations": [],
            "raw_response": analysis_text
        }
        
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if "Classification:" in line or "CLASSIFICATION:" in line:
                classification = line.split(':')[-1].strip().upper()
                if classification in ["HALAL", "DOUBTFUL", "HARAM"]:
                    result["classification"] = classification
                    
            elif "Confidence" in line:
                try:
                    confidence = int(''.join(filter(str.isdigit, line)))
                    result["confidence_score"] = min(100, max(0, confidence))
                except:
                    pass
                    
            elif "Key Findings:" in line or "KEY FINDINGS:" in line:
                current_section = "findings"
            elif "Recommendations:" in line or "RECOMMENDATIONS:" in line:
                current_section = "recommendations"
            elif line.startswith('-') or line.startswith('•'):
                content = line[1:].strip()
                if current_section == "findings":
                    result["key_findings"].append(content)
                elif current_section == "recommendations":
                    result["recommendations"].append(content)
        
        return result