# ===== utils/validators.py - Validation Utilities =====

"""
Input validation utilities for the SMART-Risk application
"""

import re
from typing import Dict, List, Tuple, Any, Optional
from decimal import Decimal, InvalidOperation


class ValidationError(Exception):
    """Custom validation error"""
    pass


class FieldValidator:
    """Field validation utilities"""
    
    @staticmethod
    def validate_required(value: Any, field_name: str) -> Any:
        """Validate required field"""
        if value is None or (isinstance(value, str) and value.strip() == ''):
            raise ValidationError(f"{field_name} is required")
        return value
    
    @staticmethod
    def validate_numeric(value: Any, field_name: str, min_val: float = None, max_val: float = None) -> float:
        """Validate numeric field with optional range"""
        try:
            if isinstance(value, str):
                value = value.strip()
            num_value = float(value)
            
            if min_val is not None and num_value < min_val:
                raise ValidationError(f"{field_name} must be at least {min_val}")
            
            if max_val is not None and num_value > max_val:
                raise ValidationError(f"{field_name} must not exceed {max_val}")
                
            return num_value
            
        except (ValueError, TypeError):
            raise ValidationError(f"{field_name} must be a valid number")
    
    @staticmethod
    def validate_percentage(value: Any, field_name: str) -> float:
        """Validate percentage (0-100)"""
        return FieldValidator.validate_numeric(value, field_name, 0, 100)
    
    @staticmethod
    def validate_currency(value: Any, field_name: str, min_val: float = 0) -> float:
        """Validate currency amount"""
        return FieldValidator.validate_numeric(value, field_name, min_val, None)
    
    @staticmethod
    def validate_application_id(value: str) -> str:
        """Validate application ID format"""
        if not value or not isinstance(value, str):
            raise ValidationError("Application ID is required")
        
        value = value.strip().upper()
        
        # Pattern: 2-3 letters followed by 3-4 digits (e.g., APP007, CR001)
        if not re.match(r'^[A-Z]{2,3}\d{3,4}$', value):
            raise ValidationError("Application ID must be in format like 'APP007' or 'CR001'")
        
        return value
    
    @staticmethod
    def validate_email(value: str) -> str:
        """Validate email format"""
        if not value or not isinstance(value, str):
            raise ValidationError("Email is required")
        
        value = value.strip().lower()
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, value):
            raise ValidationError("Invalid email format")
        
        return value
    
    @staticmethod
    def validate_choice(value: str, choices: List[str], field_name: str) -> str:
        """Validate choice from predefined options"""
        if not value:
            raise ValidationError(f"{field_name} is required")
        
        if value not in choices:
            raise ValidationError(f"{field_name} must be one of: {', '.join(choices)}")
        
        return value


class CreditApplicationValidator:
    """Specific validator for credit applications"""
    
    @staticmethod
    def validate_credit_form(form_data: Dict) -> Tuple[Dict, List[str]]:
        """
        Validate credit application form data
        
        Returns:
            Tuple of (validated_data, errors)
        """
        validated = {}
        errors = []
        
        try:
            # Application ID
            validated['application_id'] = FieldValidator.validate_application_id(
                form_data.get('application_id', '')
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Loan Amount
            validated['loan_amount'] = FieldValidator.validate_currency(
                form_data.get('loan_amount'), 'Loan Amount', min_val=1000
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Property Value
            validated['property_value'] = FieldValidator.validate_currency(
                form_data.get('property_value'), 'Property Value', min_val=10000
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Monthly Income
            validated['monthly_income'] = FieldValidator.validate_currency(
                form_data.get('monthly_income'), 'Monthly Income', min_val=500
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Monthly Debt
            validated['monthly_debt'] = FieldValidator.validate_currency(
                form_data.get('monthly_debt'), 'Monthly Debt', min_val=0
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Recovery Rate
            validated['recovery_rate'] = FieldValidator.validate_percentage(
                form_data.get('recovery_rate'), 'Recovery Rate'
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Probability of Default
            validated['probability_of_default'] = FieldValidator.validate_percentage(
                form_data.get('probability_of_default'), 'Probability of Default'
            )
        except ValidationError as e:
            errors.append(str(e))
        
        # Business logic validations
        if not errors:  # Only if basic validations passed
            try:
                # LTV ratio validation
                ltv = (validated['loan_amount'] / validated['property_value']) * 100
                if ltv > 200:
                    errors.append("Loan amount cannot exceed 200% of property value")
                
                # DTI ratio validation
                dti = (validated['monthly_debt'] / validated['monthly_income']) * 100
                if dti > 80:
                    errors.append("Debt-to-income ratio cannot exceed 80%")
                    
            except (KeyError, ZeroDivisionError):
                pass  # Skip business logic if basic fields failed
        
        return validated, errors


class ShariahApplicationValidator:
    """Specific validator for Shariah applications"""
    
    VALID_RIBA_OPTIONS = ['Yes', 'No']
    VALID_GHARAR_OPTIONS = ['Yes', 'No']
    VALID_MAYSIR_OPTIONS = ['Present', 'Absent']
    VALID_CATEGORIES = ['Corporate', 'Personal']
    
    @staticmethod
    def validate_shariah_form(form_data: Dict) -> Tuple[Dict, List[str]]:
        """
        Validate Shariah application form data
        
        Returns:
            Tuple of (validated_data, errors)
        """
        validated = {}
        errors = []
        
        try:
            # Application ID
            validated['application_id'] = FieldValidator.validate_application_id(
                form_data.get('application_id', '')
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Customer Name
            name = form_data.get('customer_name', '').strip()
            if not name:
                raise ValidationError("Customer name is required")
            if len(name) < 2:
                raise ValidationError("Customer name must be at least 2 characters")
            validated['customer_name'] = name
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Customer Category
            validated['customer_category'] = FieldValidator.validate_choice(
                form_data.get('customer_category'), 
                ShariahApplicationValidator.VALID_CATEGORIES,
                'Customer Category'
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Loan Amount
            validated['loan_amount'] = FieldValidator.validate_currency(
                form_data.get('loan_amount'), 'Loan Amount', min_val=1000
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Riba
            validated['riba'] = FieldValidator.validate_choice(
                form_data.get('riba'),
                ShariahApplicationValidator.VALID_RIBA_OPTIONS,
                'Riba'
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Gharar
            validated['gharar'] = FieldValidator.validate_choice(
                form_data.get('gharar'),
                ShariahApplicationValidator.VALID_GHARAR_OPTIONS,
                'Gharar'
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Maysir
            validated['maysir'] = FieldValidator.validate_choice(
                form_data.get('maysir'),
                ShariahApplicationValidator.VALID_MAYSIR_OPTIONS,
                'Maysir'
            )
        except ValidationError as e:
            errors.append(str(e))
        
        try:
            # Business Description
            description = form_data.get('business_description', '').strip()
            if not description:
                raise ValidationError("Business description is required")
            if len(description) < 10:
                raise ValidationError("Business description must be at least 10 characters")
            validated['business_description'] = description
        except ValidationError as e:
            errors.append(str(e))
        
        return validated, errors


# ===== HELPER FUNCTIONS =====

def validate_form_data(form_data: Dict, validator_class) -> Tuple[bool, Dict, List[str]]:
    """
    Generic form validation helper
    
    Args:
        form_data: Form data dictionary
        validator_class: Validator class to use
    
    Returns:
        Tuple of (is_valid, validated_data, errors)
    """
    if hasattr(validator_class, 'validate_credit_form'):
        validated_data, errors = validator_class.validate_credit_form(form_data)
    elif hasattr(validator_class, 'validate_shariah_form'):
        validated_data, errors = validator_class.validate_shariah_form(form_data)
    else:
        raise ValueError("Invalid validator class")
    
    is_valid = len(errors) == 0
    return is_valid, validated_data, errors


def sanitize_input(value: str) -> str:
    """Sanitize string input"""
    if not isinstance(value, str):
        return str(value) if value is not None else ''
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
    sanitized = value
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()