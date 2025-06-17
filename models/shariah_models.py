# ===============================
# Updated models/shariah_models.py
# ===============================

# models/shariah_models.py
"""
Enhanced Shariah Risk Assessment Models
Updated to use extensions.db to avoid circular import
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from enum import Enum
import json
from sqlalchemy import func
from decimal import Decimal

# Import db from extensions instead of app to avoid circular import
from extensions import db

class ShariahComplianceLevel(Enum):
    """Comprehensive compliance levels based on international standards"""
    FULLY_COMPLIANT = "fully_compliant"          # 90-100% compliance score
    SUBSTANTIALLY_COMPLIANT = "substantially_compliant"  # 75-89% compliance score  
    PARTIALLY_COMPLIANT = "partially_compliant"  # 60-74% compliance score
    NON_COMPLIANT = "non_compliant"             # Below 60% compliance score
    UNDER_REVIEW = "under_review"               # Pending assessment

class ShariahRiskLevel(Enum):
    """Risk categorization based on composite scoring"""
    VERY_LOW = "very_low"      # 90-100% compliance
    LOW = "low"                # 75-89% compliance
    MEDIUM = "medium"          # 60-74% compliance
    HIGH = "high"              # 40-59% compliance
    CRITICAL = "critical"      # Below 40% compliance

class ComprehensiveShariahAssessment(db.Model):
    """
    Enhanced Shariah Risk Assessment Model
    Implements the comprehensive framework we discussed
    """
    __tablename__ = 'comprehensive_shariah_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(100), nullable=False, unique=True)
    assessment_date = db.Column(db.DateTime, default=datetime.utcnow)
    assessed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # === BASIC APPLICATION INFO ===
    customer_name = db.Column(db.String(200), nullable=False)
    customer_category = db.Column(db.String(50), nullable=False)  # Corporate/Personal/SME/Government
    product_type = db.Column(db.String(100), nullable=False)      # Murabaha/Mudarabah/etc
    financing_amount = db.Column(db.Numeric(15,2), nullable=False)
    financing_tenor = db.Column(db.Integer, nullable=False)       # in months
    purpose_of_financing = db.Column(db.Text, nullable=False)
    business_description = db.Column(db.Text, nullable=False)
    
    # === DIMENSION 1: FUNDAMENTAL SHARIAH COMPLIANCE (40%) ===
    
    # Core Prohibition Assessment (JSON fields for flexibility)
    riba_assessment = db.Column(db.JSON, nullable=False, default=lambda: {
        'has_riba': False,
        'riba_type': None,  # 'al_fadl', 'al_nasiah', 'none'
        'riba_percentage': 0.0,
        'mitigation_measures': []
    })
    
    gharar_assessment = db.Column(db.JSON, nullable=False, default=lambda: {
        'gharar_level': 'low',  # 'low', 'medium', 'high', 'excessive'
        'uncertainty_sources': [],
        'risk_mitigation': []
    })
    
    maysir_assessment = db.Column(db.JSON, nullable=False, default=lambda: {
        'has_maysir': False,
        'gambling_elements': [],
        'speculation_level': 'low'
    })
    
    # Contract Structure Analysis
    contract_analysis = db.Column(db.JSON, nullable=False, default=lambda: {
        'contract_type': None,
        'ownership_transfer': False,
        'asset_backing': False,
        'profit_loss_sharing': 'none',  # 'profit_sharing', 'loss_sharing', 'both', 'none'
        'collateral_shariah_compliant': True
    })
    
    # === DIMENSION 2: FINANCIAL STRUCTURE ANALYSIS (25%) ===
    
    # Financial Ratios (Based on SC Malaysia Guidelines)
    cash_to_total_assets = db.Column(db.Numeric(5,2), nullable=True)    # Should be ≤33%
    debt_to_total_assets = db.Column(db.Numeric(5,2), nullable=True)    # Should be ≤33%
    interest_income_ratio = db.Column(db.Numeric(5,2), nullable=True)   # Should be ≤5%
    non_compliant_revenue_ratio = db.Column(db.Numeric(5,2), nullable=True)
    
    # Additional Financial Metrics
    current_ratio = db.Column(db.Numeric(8,4), nullable=True)
    capital_adequacy_ratio = db.Column(db.Numeric(5,2), nullable=True)
    financing_to_deposit_ratio = db.Column(db.Numeric(5,2), nullable=True)
    
    # === DIMENSION 3: BUSINESS ACTIVITY SCREENING (20%) ===
    
    # 5% Threshold Activities (Critical - must be ≤5%)
    prohibited_5pct_activities = db.Column(db.JSON, nullable=False, default=lambda: {
        'conventional_banking': 0.0,
        'conventional_insurance': 0.0,
        'gambling': 0.0,
        'liquor_tobacco': 0.0,
        'pork_products': 0.0,
        'non_halal_food': 0.0,
        'interest_income': 0.0,
        'adult_entertainment': 0.0
    })
    
    # 20% Threshold Activities (Moderate - must be ≤20%)
    prohibited_20pct_activities = db.Column(db.JSON, nullable=False, default=lambda: {
        'share_trading': 0.0,
        'stockbroking': 0.0,
        'cinema_entertainment': 0.0,
        'rental_non_compliant': 0.0,
        'music_industry': 0.0
    })
    
    # === DIMENSION 4: GOVERNANCE AND CONTROLS (10%) ===
    
    # Shariah Governance Structure
    governance_assessment = db.Column(db.JSON, nullable=False, default=lambda: {
        'shariah_board_established': False,
        'shariah_board_members': 0,
        'internal_shariah_audit': False,
        'shariah_compliance_officer': False,
        'fatwa_compliance': 'none',  # 'full', 'partial', 'none'
        'documentation_quality': 'fair',  # 'excellent', 'good', 'fair', 'poor'
        'compliance_monitoring': False,
        'dispute_resolution': False
    })
    
    # === DIMENSION 5: OPERATIONAL RISK ASSESSMENT (3%) ===
    
    operational_controls = db.Column(db.JSON, nullable=False, default=lambda: {
        'staff_training': False,
        'system_controls': False,
        'process_segregation': False,
        'error_rectification': False,
        'compliance_reporting': False
    })
    
    # === DIMENSION 6: MARKET AND CONTEXTUAL FACTORS (2%) ===
    
    market_factors = db.Column(db.JSON, nullable=False, default=lambda: {
        'market_volatility': 'medium',  # 'low', 'medium', 'high'
        'regulatory_environment': 'stable',  # 'stable', 'changing', 'uncertain'
        'competitive_pressure': 'medium'
    })
    
    # === ASSESSMENT RESULTS ===
    
    # Dimension Scores (0-100)
    fundamental_compliance_score = db.Column(db.Numeric(5,2), nullable=True)
    financial_structure_score = db.Column(db.Numeric(5,2), nullable=True)
    business_activity_score = db.Column(db.Numeric(5,2), nullable=True)
    governance_score = db.Column(db.Numeric(5,2), nullable=True)
    operational_score = db.Column(db.Numeric(5,2), nullable=True)
    market_contextual_score = db.Column(db.Numeric(5,2), nullable=True)
    
    # Composite Assessment Results
    weighted_composite_score = db.Column(db.Numeric(5,2), nullable=True)
    compliance_level = db.Column(db.Enum(ShariahComplianceLevel), nullable=True)
    risk_level = db.Column(db.Enum(ShariahRiskLevel), nullable=True)
    
    # AI/NLP Analysis Results
    nlp_analysis = db.Column(db.JSON, nullable=True, default=lambda: {
        'confidence_score': 0.0,
        'extracted_keywords': [],
        'sentiment_analysis': {},
        'risk_flags': [],
        'compliance_indicators': []
    })
    
    # Final Decision and Recommendations
    final_recommendation = db.Column(db.String(50), nullable=True)  # 'approve', 'reject', 'conditional'
    conditions_for_approval = db.Column(db.Text, nullable=True)
    improvement_recommendations = db.Column(db.JSON, nullable=True)
    next_review_date = db.Column(db.Date, nullable=True)
    
    # Audit and Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assessor = db.relationship('User', backref='shariah_assessments')
    
    def calculate_composite_score(self):
        """
        Calculate the weighted composite score based on all dimensions
        This implements the research-backed weighting system
        """
        if not all([
            self.fundamental_compliance_score, 
            self.financial_structure_score,
            self.business_activity_score,
            self.governance_score,
            self.operational_score,
            self.market_contextual_score
        ]):
            return None
            
        # Research-backed weighted calculation
        composite = (
            float(self.fundamental_compliance_score) * 0.40 +    # 40% - Most critical
            float(self.financial_structure_score) * 0.25 +       # 25% - Quantitative measures
            float(self.business_activity_score) * 0.20 +         # 20% - Activity screening
            float(self.governance_score) * 0.10 +                # 10% - Governance
            float(self.operational_score) * 0.03 +               # 3% - Operations
            float(self.market_contextual_score) * 0.02           # 2% - Market factors
        )
        
        self.weighted_composite_score = round(composite, 2)
        
        # Determine compliance and risk levels
        if composite >= 90:
            self.compliance_level = ShariahComplianceLevel.FULLY_COMPLIANT
            self.risk_level = ShariahRiskLevel.VERY_LOW
        elif composite >= 75:
            self.compliance_level = ShariahComplianceLevel.SUBSTANTIALLY_COMPLIANT
            self.risk_level = ShariahRiskLevel.LOW
        elif composite >= 60:
            self.compliance_level = ShariahComplianceLevel.PARTIALLY_COMPLIANT
            self.risk_level = ShariahRiskLevel.MEDIUM
        elif composite >= 40:
            self.compliance_level = ShariahComplianceLevel.NON_COMPLIANT
            self.risk_level = ShariahRiskLevel.HIGH
        else:
            self.compliance_level = ShariahComplianceLevel.NON_COMPLIANT
            self.risk_level = ShariahRiskLevel.CRITICAL
            
        # Calculate next review date based on risk level
        self.next_review_date = self._calculate_next_review_date()
            
        return self.weighted_composite_score
    
    def _calculate_next_review_date(self):
        """Calculate next review date based on risk level"""
        days_map = {
            ShariahRiskLevel.VERY_LOW: 365,    # Annual review
            ShariahRiskLevel.LOW: 180,         # Semi-annual review
            ShariahRiskLevel.MEDIUM: 90,       # Quarterly review
            ShariahRiskLevel.HIGH: 30,         # Monthly review
            ShariahRiskLevel.CRITICAL: 7       # Weekly review
        }
        
        days_to_add = days_map.get(self.risk_level, 90)
        return (datetime.utcnow() + timedelta(days=days_to_add)).date()
    
    def get_dimension_breakdown(self):
        """Get detailed breakdown of all dimension scores"""
        return {
            'fundamental_compliance': {
                'score': float(self.fundamental_compliance_score) if self.fundamental_compliance_score else 0,
                'weight': 40,
                'weighted_score': float(self.fundamental_compliance_score) * 0.40 if self.fundamental_compliance_score else 0
            },
            'financial_structure': {
                'score': float(self.financial_structure_score) if self.financial_structure_score else 0,
                'weight': 25,
                'weighted_score': float(self.financial_structure_score) * 0.25 if self.financial_structure_score else 0
            },
            'business_activity': {
                'score': float(self.business_activity_score) if self.business_activity_score else 0,
                'weight': 20,
                'weighted_score': float(self.business_activity_score) * 0.20 if self.business_activity_score else 0
            },
            'governance': {
                'score': float(self.governance_score) if self.governance_score else 0,
                'weight': 10,
                'weighted_score': float(self.governance_score) * 0.10 if self.governance_score else 0
            },
            'operational': {
                'score': float(self.operational_score) if self.operational_score else 0,
                'weight': 3,
                'weighted_score': float(self.operational_score) * 0.03 if self.operational_score else 0
            },
            'market_contextual': {
                'score': float(self.market_contextual_score) if self.market_contextual_score else 0,
                'weight': 2,
                'weighted_score': float(self.market_contextual_score) * 0.02 if self.market_contextual_score else 0
            }
        }
    
    def to_dict(self):
        """Convert assessment to dictionary for JSON serialization"""
        return {
            'application_id': self.application_id,
            'customer_name': self.customer_name,
            'product_type': self.product_type,
            'financing_amount': float(self.financing_amount),
            'composite_score': float(self.weighted_composite_score) if self.weighted_composite_score else None,
            'compliance_level': self.compliance_level.value if self.compliance_level else None,
            'risk_level': self.risk_level.value if self.risk_level else None,
            'recommendation': self.final_recommendation,
            'assessment_date': self.assessment_date.isoformat() if self.assessment_date else None,
            'next_review_date': self.next_review_date.isoformat() if self.next_review_date else None,
            'dimension_breakdown': self.get_dimension_breakdown()
        }

class ShariahAssessmentAudit(db.Model):
    """Audit trail for comprehensive Shariah assessments"""
    __tablename__ = 'shariah_assessment_audits'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('comprehensive_shariah_assessments.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # CREATE/UPDATE/APPROVE/REJECT
    performed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    previous_values = db.Column(db.JSON, nullable=True)
    new_values = db.Column(db.JSON, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    
    # Relationships
    assessment = db.relationship('ComprehensiveShariahAssessment', backref='audit_trail')
    user = db.relationship('User', backref='audit_actions')

class ShariahProductTemplate(db.Model):
    """Templates for different Islamic financial products"""
    __tablename__ = 'shariah_product_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    product_type = db.Column(db.String(100), nullable=False)  # Murabaha, Mudarabah, etc.
    template_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Template Configuration
    required_parameters = db.Column(db.JSON, nullable=False)    # Which parameters are mandatory
    scoring_weights = db.Column(db.JSON, nullable=False)        # Custom weights for this product
    compliance_thresholds = db.Column(db.JSON, nullable=False)  # Product-specific thresholds
    
    # Shariah Guidelines for this product type
    shariah_requirements = db.Column(db.JSON, nullable=False)
    prohibited_elements = db.Column(db.JSON, nullable=False)
    recommended_practices = db.Column(db.JSON, nullable=True)
    
    # Metadata
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    version = db.Column(db.String(10), default='1.0')
    
    # Relationships
    creator = db.relationship('User', backref='created_templates')