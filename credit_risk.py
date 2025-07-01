# ===== credit_risk.py - Business Logic Module =====
from typing import Dict, Tuple, Optional
import logging

# Configure logging for this module
logger = logging.getLogger(__name__)


class CreditRiskCalculator:
   
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
      
        self.weights = weights or {
            'ltv': 0.30,        # 30% weight for Loan-to-Value
            'dti': 0.25,        # 25% weight for Debt-to-Income  
            'recovery': 0.20,   # 20% weight for Recovery Rate
            'probability': 0.25 # 25% weight for Probability of Default
        }
        
        # Risk thresholds
        self.thresholds = {
            'low': 30,      # 0-30 = Low Risk
            'medium': 70    # 31-70 = Medium, 71-100 = High
        }
    
    def calculate_risk_score(self, ltv: float, dti: float, recovery_rate: float, 
                           probability_of_default: float) -> float:
        """
        Calculate credit risk score based on financial parameters
        
        Args:
            ltv: Loan-to-Value ratio (percentage)
            dti: Debt-to-Income ratio (percentage)  
            recovery_rate: Recovery rate (percentage)
            probability_of_default: Probability of default (percentage)
        
        Returns:
            Credit risk score (0-100, higher = more risky)
        """
        try:
            # Input validation and normalization
            ltv = max(0, min(200, float(ltv)))
            dti = max(0, min(100, float(dti)))
            recovery_rate = max(0, min(100, float(recovery_rate)))
            probability_of_default = max(0, min(100, float(probability_of_default)))
            
            # Calculate weighted components
            ltv_score = (ltv / 100) * self.weights['ltv'] * 100
            dti_score = (dti / 100) * self.weights['dti'] * 100
            recovery_score = ((100 - recovery_rate) / 100) * self.weights['recovery'] * 100
            pd_score = (probability_of_default / 100) * self.weights['probability'] * 100
            
            # Total risk score
            total_score = ltv_score + dti_score + recovery_score + pd_score
            
            # Ensure score is within bounds
            risk_score = max(0, min(100, total_score))
            
            logger.info(f"Risk calculated - LTV: {ltv}%, DTI: {dti}%, Recovery: {recovery_rate}%, PD: {probability_of_default}% → Score: {risk_score:.2f}")
            
            return round(risk_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating credit risk: {e}")
            return 50.0  # Return moderate risk as fallback
    
    def get_risk_level(self, risk_score: float) -> str:
        """
        Determine risk level based on score
        
        Args:
            risk_score: Risk score (0-100)
        
        Returns:
            Risk level ('Low', 'Medium', 'High')
        """
        if risk_score <= self.thresholds['low']:
            return 'Low'
        elif risk_score <= self.thresholds['medium']:
            return 'Medium'
        else:
            return 'High'
    
    def get_recommendation(self, risk_score: float, risk_level: str) -> Dict[str, str]:
       
        recommendations = {
            'Low': {
                'action': 'APPROVE',
                'color': 'success',
                'icon': 'check-circle',
                'message': 'Low risk - Recommend approval',
                'conditions': 'Standard terms and conditions apply',
                'interest_adjustment': 0
            },
            'Medium': {
                'action': 'REVIEW',
                'color': 'warning',
                'icon': 'exclamation-triangle', 
                'message': 'Medium risk - Requires careful review',
                'conditions': 'Consider additional collateral or higher interest rate',
                'interest_adjustment': 1.5
            },
            'High': {
                'action': 'REJECT',
                'color': 'danger',
                'icon': 'times-circle',
                'message': 'High risk - Recommend rejection', 
                'conditions': 'Significant risk factors present',
                'interest_adjustment': 3.0
            }
        }
        
        return recommendations.get(risk_level, recommendations['Medium'])
    
    def calculate_complete_assessment(self, ltv: float, dti: float, recovery_rate: float,
                                    probability_of_default: float) -> Dict:
        """
        Perform complete credit risk assessment
        
        Returns:
            Complete assessment dictionary
        """
        risk_score = self.calculate_risk_score(ltv, dti, recovery_rate, probability_of_default)
        risk_level = self.get_risk_level(risk_score)
        recommendation = self.get_recommendation(risk_score, risk_level)
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'components': {
                'ltv': ltv,
                'dti': dti, 
                'recovery_rate': recovery_rate,
                'probability_of_default': probability_of_default
            }
        }


# ===== UTILITY FUNCTIONS =====

def calculate_credit_risk(ltv: float, dti: float, recovery_rate: float, 
                         probability_of_default: float) -> float:
    """
    Backward compatibility function for existing code
    """
    calculator = CreditRiskCalculator()
    return calculator.calculate_risk_score(ltv, dti, recovery_rate, probability_of_default)


def get_risk_level(risk_score: float) -> str:
    """
    Backward compatibility function for risk level
    """
    calculator = CreditRiskCalculator()
    return calculator.get_risk_level(risk_score)


def validate_financial_inputs(data: Dict) -> Tuple[bool, Dict[str, str]]:
    """
    Validate financial input data
    
    Args:
        data: Dictionary with financial parameters
    
    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = {}
    
    required_fields = ['loan_amount', 'property_value', 'monthly_income', 'monthly_debt']
    
    for field in required_fields:
        if field not in data or data[field] is None:
            errors[field] = f"{field.replace('_', ' ').title()} is required"
            continue
            
        try:
            value = float(data[field])
            if value < 0:
                errors[field] = f"{field.replace('_', ' ').title()} cannot be negative"
        except (ValueError, TypeError):
            errors[field] = f"{field.replace('_', ' ').title()} must be a valid number"
    
    # Business logic validations
    if 'loan_amount' in data and 'property_value' in data:
        try:
            loan_amount = float(data['loan_amount'])
            property_value = float(data['property_value'])
            
            if property_value > 0 and (loan_amount / property_value) > 2.0:
                errors['loan_amount'] = "Loan amount cannot exceed 200% of property value"
        except (ValueError, TypeError):
            pass
    
    return len(errors) == 0, errors


# ===== CONSTANTS =====

RISK_CATEGORIES = {
    'LOW': {'min': 0, 'max': 30, 'color': 'success'},
    'MEDIUM': {'min': 31, 'max': 70, 'color': 'warning'}, 
    'HIGH': {'min': 71, 'max': 100, 'color': 'danger'}
}

DEFAULT_WEIGHTS = {
    'ltv': 0.30,
    'dti': 0.25,
    'recovery': 0.20,
    'probability': 0.25
}