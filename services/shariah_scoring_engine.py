# services/shariah_scoring_engine.py
"""
Advanced Shariah Risk Scoring Engine
Implements the comprehensive multi-dimensional framework
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
import json
import logging
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

# Import db from extensions instead of app
from extensions import db

# Import your existing models and database
from models.shariah_models import (
    ComprehensiveShariahAssessment, 
    ShariahComplianceLevel, 
    ShariahRiskLevel
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ShariahAssessmentInput:
    """
    Structured input for the comprehensive assessment engine
    Maps directly to your enhanced database model
    """
    # Basic Information
    application_id: str
    customer_name: str
    customer_category: str
    product_type: str
    financing_amount: float
    financing_tenor: int
    purpose_of_financing: str
    business_description: str
    
    # Fundamental Compliance Data
    riba_assessment: Dict = None
    gharar_assessment: Dict = None
    maysir_assessment: Dict = None
    contract_analysis: Dict = None
    
    # Financial ratios
    cash_to_total_assets: Optional[float] = None
    debt_to_total_assets: Optional[float] = None
    interest_income_ratio: Optional[float] = None
    
    # Business activities
    prohibited_5pct_activities: Dict = None
    prohibited_20pct_activities: Dict = None
    
    # Governance
    governance_assessment: Dict = None
    operational_controls: Dict = None
    market_factors: Dict = None

class ComprehensiveShariahScoringEngine:
    """
    Main scoring engine that implements the research-backed framework
    """
    
    def __init__(self):
        """Initialize with research-based parameters and thresholds"""
        
        # Dimension weights based on international research
        self.dimension_weights = {
            'fundamental_compliance': 0.40,  # Core Shariah principles - most critical
            'financial_structure': 0.25,     # Quantitative benchmarks
            'business_activity': 0.20,       # Activity screening importance
            'governance': 0.10,              # Shariah governance quality
            'operational': 0.03,             # Operational controls
            'market_contextual': 0.02        # External market factors
        }
        
        # Compliance thresholds (based on SC Malaysia and AAOIFI standards)
        self.compliance_thresholds = {
            # Financial Structure Thresholds
            'cash_to_assets_max': 33.0,      # SC Malaysia guideline
            'debt_to_assets_max': 33.0,      # SC Malaysia guideline
            'interest_income_max': 5.0,      # Critical 5% threshold
            
            # Business Activity Thresholds
            'prohibited_5pct_max': 5.0,      # 5% threshold activities
            'prohibited_20pct_max': 20.0,    # 20% threshold activities
            
            # Score Thresholds
            'minimum_passing_score': 60.0,   # Below this is non-compliant
            'good_score': 75.0,              # Substantially compliant
            'excellent_score': 90.0          # Fully compliant
        }
        
        # Initialize NLP processor
        self.nlp_processor = EnhancedShariahNLP()
    
    def perform_comprehensive_assessment(self, input_data: ShariahAssessmentInput) -> Dict:
        """
        Main assessment function that orchestrates the entire evaluation process
        Returns comprehensive assessment results
        """
        logger.info(f"Starting comprehensive Shariah assessment for {input_data.application_id}")
        
        try:
            # Step 1: Assess each dimension individually
            dimension_scores = self._calculate_all_dimension_scores(input_data)
            
            # Step 2: Calculate weighted composite score
            composite_score = self._calculate_weighted_composite_score(dimension_scores)
            
            # Step 3: Determine compliance level and risk category
            compliance_level, risk_level = self._determine_compliance_and_risk_levels(composite_score)
            
            # Step 4: Generate detailed recommendations
            recommendations = self._generate_comprehensive_recommendations(dimension_scores, input_data)
            
            # Step 5: Perform NLP analysis on textual content
            nlp_analysis = self.nlp_processor.analyze_comprehensive_text(
                input_data.business_description,
                input_data.purpose_of_financing
            )
            
            # Step 6: Make final recommendation
            final_recommendation = self._make_final_recommendation(composite_score, dimension_scores, nlp_analysis)
            
            # Step 7: Compile comprehensive results
            assessment_result = {
                'application_id': input_data.application_id,
                'assessment_timestamp': datetime.utcnow().isoformat(),
                'assessment_version': '2.0_comprehensive',
                
                # Individual dimension scores
                'dimension_scores': dimension_scores,
                'dimension_weights': self.dimension_weights,
                
                # Composite results
                'weighted_composite_score': round(composite_score, 2),
                'compliance_level': compliance_level.value,
                'risk_level': risk_level.value,
                
                # Decision and recommendations
                'final_recommendation': final_recommendation,
                'detailed_recommendations': recommendations,
                'improvement_priority': self._prioritize_improvements(dimension_scores),
                
                # NLP and AI analysis
                'nlp_analysis': nlp_analysis,
                'confidence_level': self._calculate_overall_confidence(dimension_scores, nlp_analysis),
                
                # Administrative
                'next_review_date': self._calculate_next_review_date(risk_level),
                'compliance_gaps': self._identify_compliance_gaps(dimension_scores),
                'regulatory_mapping': self._map_to_regulatory_requirements(dimension_scores)
            }
            
            logger.info(f"Assessment completed for {input_data.application_id}: {composite_score:.2f}% compliance")
            return assessment_result
            
        except Exception as e:
            logger.error(f"Error in comprehensive assessment for {input_data.application_id}: {str(e)}")
            raise Exception(f"Assessment failed: {str(e)}")
    
    def _calculate_all_dimension_scores(self, input_data: ShariahAssessmentInput) -> Dict[str, float]:
        """Calculate scores for all six dimensions"""
        
        scores = {}
        
        # Dimension 1: Fundamental Shariah Compliance (40%)
        scores['fundamental_compliance'] = self._assess_fundamental_compliance(input_data)
        
        # Dimension 2: Financial Structure Analysis (25%)
        scores['financial_structure'] = self._assess_financial_structure(input_data)
        
        # Dimension 3: Business Activity Screening (20%)
        scores['business_activity'] = self._assess_business_activities(input_data)
        
        # Dimension 4: Governance and Controls (10%)
        scores['governance'] = self._assess_governance_quality(input_data)
        
        # Dimension 5: Operational Risk Assessment (3%)
        scores['operational'] = self._assess_operational_controls(input_data)
        
        # Dimension 6: Market and Contextual Factors (2%)
        scores['market_contextual'] = self._assess_market_factors(input_data)
        
        return scores
    
    def _assess_fundamental_compliance(self, input_data: ShariahAssessmentInput) -> float:
        """
        Assess core Shariah principles compliance (40% weight)
        This is the most critical dimension
        """
        score = 100.0  # Start with perfect score
        
        # 1. Riba (Interest) Assessment - Most Critical (40% of fundamental score)
        riba_score = self._evaluate_riba_compliance(input_data.riba_assessment or {})
        
        # 2. Gharar (Uncertainty) Assessment (25% of fundamental score)
        gharar_score = self._evaluate_gharar_compliance(input_data.gharar_assessment or {})
        
        # 3. Maysir (Gambling/Speculation) Assessment (20% of fundamental score)
        maysir_score = self._evaluate_maysir_compliance(input_data.maysir_assessment or {})
        
        # 4. Contract Structure Assessment (15% of fundamental score)
        contract_score = self._evaluate_contract_structure(input_data.contract_analysis or {})
        
        # Calculate weighted fundamental compliance score
        fundamental_score = (
            riba_score * 0.40 +      # Riba is most critical
            gharar_score * 0.25 +    # Uncertainty analysis
            maysir_score * 0.20 +    # Speculation/gambling
            contract_score * 0.15    # Contract structure
        )
        
        return max(0, min(100, fundamental_score))
    
    def _evaluate_riba_compliance(self, riba_data: Dict) -> float:
        """Evaluate Riba (interest) compliance"""
        if riba_data.get('has_riba', False):
            riba_percentage = riba_data.get('riba_percentage', 0)
            if riba_percentage > 0:
                # Any presence of Riba is a critical violation
                return max(0, 100 - (riba_percentage * 20))  # Heavy penalty
        
        # Check for mitigation measures if borderline cases exist
        mitigation_measures = riba_data.get('mitigation_measures', [])
        if len(mitigation_measures) > 0:
            return 95  # Slight deduction for needing mitigation
        
        return 100  # Perfect score if no Riba detected
    
    def _evaluate_gharar_compliance(self, gharar_data: Dict) -> float:
        """Evaluate Gharar (uncertainty) compliance"""
        gharar_level = gharar_data.get('gharar_level', 'low')
        
        score_map = {
            'low': 100,
            'medium': 80,
            'high': 40,
            'excessive': 0
        }
        
        base_score = score_map.get(gharar_level, 60)
        
        # Adjust based on risk mitigation measures
        mitigation_measures = gharar_data.get('risk_mitigation', [])
        if len(mitigation_measures) > 0 and gharar_level in ['medium', 'high']:
            base_score += min(15, len(mitigation_measures) * 5)  # Bonus for mitigation
        
        return min(100, base_score)
    
    def _evaluate_maysir_compliance(self, maysir_data: Dict) -> float:
        """Evaluate Maysir (gambling/speculation) compliance"""
        if maysir_data.get('has_maysir', False):
            gambling_elements = maysir_data.get('gambling_elements', [])
            if len(gambling_elements) > 0:
                return max(0, 100 - (len(gambling_elements) * 25))  # Heavy penalty
        
        speculation_level = maysir_data.get('speculation_level', 'low')
        speculation_scores = {
            'low': 100,
            'medium': 75,
            'high': 25,
            'excessive': 0
        }
        
        return speculation_scores.get(speculation_level, 60)
    
    def _evaluate_contract_structure(self, contract_data: Dict) -> float:
        """Evaluate contract structure compliance"""
        score = 100.0
        
        # Check for proper ownership transfer
        if not contract_data.get('ownership_transfer', False):
            score -= 20
        
        # Check for asset backing
        if not contract_data.get('asset_backing', False):
            score -= 15
        
        # Evaluate profit/loss sharing arrangement
        pls_arrangement = contract_data.get('profit_loss_sharing', 'none')
        if pls_arrangement == 'none':
            score -= 10
        elif pls_arrangement in ['profit_sharing', 'both']:
            score += 5  # Bonus for proper Islamic structure
        
        # Check collateral compliance
        if not contract_data.get('collateral_shariah_compliant', True):
            score -= 25
        
        return max(0, min(100, score))
    
    def _assess_financial_structure(self, input_data: ShariahAssessmentInput) -> float:
        """
        Assess financial ratios and structure (25% weight)
        Based on Securities Commission Malaysia guidelines
        """
        score = 100.0
        
        # Cash-to-Assets Ratio Assessment (should be ≤ 33%)
        if input_data.cash_to_total_assets is not None:
            if input_data.cash_to_total_assets > self.compliance_thresholds['cash_to_assets_max']:
                excess = input_data.cash_to_total_assets - self.compliance_thresholds['cash_to_assets_max']
                score -= min(30, excess * 1.5)  # Penalty for excess
        
        # Debt-to-Assets Ratio Assessment (should be ≤ 33%)
        if input_data.debt_to_total_assets is not None:
            if input_data.debt_to_total_assets > self.compliance_thresholds['debt_to_assets_max']:
                excess = input_data.debt_to_total_assets - self.compliance_thresholds['debt_to_assets_max']
                score -= min(30, excess * 1.5)
        
        # Interest Income Assessment (should be ≤ 5%) - CRITICAL
        if input_data.interest_income_ratio is not None:
            if input_data.interest_income_ratio > self.compliance_thresholds['interest_income_max']:
                excess = input_data.interest_income_ratio - self.compliance_thresholds['interest_income_max']
                score -= min(70, excess * 10)  # Heavy penalty for interest income
        
        return max(0, min(100, score))
    
    def _assess_business_activities(self, input_data: ShariahAssessmentInput) -> float:
        """
        Assess business activity compliance (20% weight)
        Using SC Malaysia thresholds
        """
        score = 100.0
        
        # 5% threshold activities assessment (critical violations)
        prohibited_5pct = input_data.prohibited_5pct_activities or {}
        for activity, percentage in prohibited_5pct.items():
            if percentage > self.compliance_thresholds['prohibited_5pct_max']:
                excess = percentage - self.compliance_thresholds['prohibited_5pct_max']
                score -= min(40, excess * 6)  # Heavy penalty for 5% violations
        
        # 20% threshold activities assessment (moderate violations)
        prohibited_20pct = input_data.prohibited_20pct_activities or {}
        for activity, percentage in prohibited_20pct.items():
            if percentage > self.compliance_thresholds['prohibited_20pct_max']:
                excess = percentage - self.compliance_thresholds['prohibited_20pct_max']
                score -= min(25, excess * 2)  # Moderate penalty for 20% violations
        
        return max(0, min(100, score))
    
    def _assess_governance_quality(self, input_data: ShariahAssessmentInput) -> float:
        """Assess Shariah governance quality (10% weight)"""
        governance_data = input_data.governance_assessment or {}
        score = 0.0  # Start from 0 and add points for good governance
        
        # Shariah Supervisory Board (40 points)
        if governance_data.get('shariah_board_established', False):
            score += 30
            # Bonus for board size
            board_members = governance_data.get('shariah_board_members', 0)
            if board_members >= 3:
                score += 10
        
        # Internal Shariah Audit (30 points)
        if governance_data.get('internal_shariah_audit', False):
            score += 30
        
        # Shariah Compliance Officer (20 points)
        if governance_data.get('shariah_compliance_officer', False):
            score += 20
        
        # Documentation Quality (10 points)
        doc_quality = governance_data.get('documentation_quality', 'fair')
        quality_scores = {'excellent': 10, 'good': 7, 'fair': 4, 'poor': 0}
        score += quality_scores.get(doc_quality, 0)
        
        return min(100, score)
    
    def _assess_operational_controls(self, input_data: ShariahAssessmentInput) -> float:
        """Assess operational risk controls (3% weight)"""
        operational_data = input_data.operational_controls or {}
        score = 50.0  # Base score assuming basic controls
        
        # Add points for specific controls
        controls = [
            'staff_training', 'system_controls', 'process_segregation',
            'error_rectification', 'compliance_reporting'
        ]
        
        for control in controls:
            if operational_data.get(control, False):
                score += 10
        
        return min(100, score)
    
    def _assess_market_factors(self, input_data: ShariahAssessmentInput) -> float:
        """Assess market and contextual factors (2% weight)"""
        market_data = input_data.market_factors or {}
        
        # Base score depending on market conditions
        volatility = market_data.get('market_volatility', 'medium')
        volatility_scores = {'low': 85, 'medium': 75, 'high': 60}
        
        regulatory = market_data.get('regulatory_environment', 'stable')
        regulatory_scores = {'stable': 85, 'changing': 70, 'uncertain': 50}
        
        # Average the market factor scores
        score = (volatility_scores.get(volatility, 75) + regulatory_scores.get(regulatory, 75)) / 2
        
        return score
    
    def _calculate_weighted_composite_score(self, dimension_scores: Dict[str, float]) -> float:
        """Calculate the weighted composite score"""
        composite = 0.0
        for dimension, score in dimension_scores.items():
            weight = self.dimension_weights.get(dimension, 0.0)
            composite += score * weight
        
        return composite
    
    def _determine_compliance_and_risk_levels(self, composite_score: float) -> Tuple[ShariahComplianceLevel, ShariahRiskLevel]:
        """Determine compliance level and risk category"""
        if composite_score >= 90:
            return ShariahComplianceLevel.FULLY_COMPLIANT, ShariahRiskLevel.VERY_LOW
        elif composite_score >= 75:
            return ShariahComplianceLevel.SUBSTANTIALLY_COMPLIANT, ShariahRiskLevel.LOW
        elif composite_score >= 60:
            return ShariahComplianceLevel.PARTIALLY_COMPLIANT, ShariahRiskLevel.MEDIUM
        elif composite_score >= 40:
            return ShariahComplianceLevel.NON_COMPLIANT, ShariahRiskLevel.HIGH
        else:
            return ShariahComplianceLevel.NON_COMPLIANT, ShariahRiskLevel.CRITICAL
    
    def _generate_comprehensive_recommendations(self, dimension_scores: Dict[str, float], input_data: ShariahAssessmentInput) -> List[Dict]:
        """Generate detailed, actionable recommendations"""
        recommendations = []
        
        for dimension, score in dimension_scores.items():
            if score < 80:  # Needs improvement
                priority = 'high' if score < 60 else 'medium' if score < 75 else 'low'
                
                recommendations.append({
                    'dimension': dimension,
                    'current_score': round(score, 2),
                    'priority': priority,
                    'recommendations': self._get_specific_recommendations(dimension, score, input_data),
                    'expected_improvement': self._estimate_score_improvement(dimension, score),
                    'implementation_timeframe': self._estimate_implementation_time(dimension, priority)
                })
        
        return sorted(recommendations, key=lambda x: {'high': 3, 'medium': 2, 'low': 1}[x['priority']], reverse=True)
    
    def _get_specific_recommendations(self, dimension: str, score: float, input_data: ShariahAssessmentInput) -> List[str]:
        """Get dimension-specific recommendations"""
        
        recommendations_map = {
            'fundamental_compliance': [
                "Review and restructure contract to eliminate any Riba elements",
                "Reduce Gharar through clearer contract terms and conditions",
                "Ensure proper asset backing for all financing structures",
                "Implement stricter Shariah compliance verification procedures",
                "Consult with qualified Shariah scholars for complex structures"
            ],
            'financial_structure': [
                "Reduce cash holdings in conventional interest-bearing accounts",
                "Restructure debt portfolio to comply with 33% threshold",
                "Diversify revenue sources away from interest-based income",
                "Improve balance sheet structure for better compliance ratios",
                "Implement regular financial ratio monitoring system"
            ],
            'business_activity': [
                "Divest from activities exceeding 5% threshold immediately",
                "Reduce exposure to 20% threshold activities gradually",
                "Implement comprehensive business activity screening",
                "Establish regular monitoring of revenue source compliance",
                "Create clear investment and business activity guidelines"
            ],
            'governance': [
                "Establish qualified Shariah Supervisory Board with minimum 3 members",
                "Implement dedicated internal Shariah audit function",
                "Appoint qualified Shariah Compliance Officer",
                "Improve contract documentation quality and standardization",
                "Develop comprehensive Shariah governance framework"
            ],
            'operational': [
                "Provide comprehensive Shariah compliance training for staff",
                "Implement automated system controls for compliance monitoring",
                "Segregate Islamic and conventional banking processes",
                "Establish clear error rectification procedures",
                "Create regular compliance reporting mechanisms"
            ],
            'market_contextual': [
                "Implement hedging strategies for market volatility",
                "Monitor regulatory changes and adapt accordingly",
                "Diversify market exposure to reduce concentration risk",
                "Develop stress testing scenarios for market conditions"
            ]
        }
        
        return recommendations_map.get(dimension, ["Review and improve current practices"])
    
    def _estimate_score_improvement(self, dimension: str, current_score: float) -> str:
        """Estimate potential score improvement"""
        if current_score < 50:
            return "20-40 points with comprehensive improvements"
        elif current_score < 70:
            return "10-25 points with targeted improvements"
        else:
            return "5-15 points with fine-tuning"
    
    def _estimate_implementation_time(self, dimension: str, priority: str) -> str:
        """Estimate implementation timeframe"""
        timeframes = {
            'high': {
                'fundamental_compliance': '1-3 months',
                'financial_structure': '3-6 months',
                'business_activity': '6-12 months',
                'governance': '2-4 months',
                'operational': '1-3 months',
                'market_contextual': '1-2 months'
            },
            'medium': {
                'fundamental_compliance': '2-4 months',
                'financial_structure': '4-8 months',
                'business_activity': '8-15 months',
                'governance': '3-6 months',
                'operational': '2-4 months',
                'market_contextual': '2-3 months'
            },
            'low': {
                'fundamental_compliance': '3-6 months',
                'financial_structure': '6-12 months',
                'business_activity': '12-18 months',
                'governance': '4-8 months',
                'operational': '3-6 months',
                'market_contextual': '3-4 months'
            }
        }
        
        return timeframes.get(priority, {}).get(dimension, '3-6 months')
    
    def _make_final_recommendation(self, composite_score: float, dimension_scores: Dict, nlp_analysis: Dict) -> str:
        """Make final approval/rejection recommendation"""
        
        # Critical check: If fundamental compliance is too low, auto-reject
        if dimension_scores.get('fundamental_compliance', 0) < 40:
            return 'reject'
        
        # Critical check: If any critical violations detected by NLP
        critical_violations = nlp_analysis.get('critical_violations', [])
        if len(critical_violations) > 0:
            return 'reject'
        
        # Standard scoring thresholds
        if composite_score >= 75:
            return 'approve'
        elif composite_score >= 60:
            return 'conditional_approval'
        else:
            return 'reject'
    
    def _prioritize_improvements(self, dimension_scores: Dict[str, float]) -> List[Dict]:
        """Prioritize improvements based on impact and urgency"""
        improvements = []
        
        for dimension, score in dimension_scores.items():
            if score < 80:
                weight = self.dimension_weights.get(dimension, 0.0)
                impact = weight * (80 - score)  # Potential weighted score improvement
                
                improvements.append({
                    'dimension': dimension,
                    'current_score': score,
                    'potential_impact': round(impact, 2),
                    'urgency': 'high' if score < 50 else 'medium' if score < 70 else 'low'
                })
        
        return sorted(improvements, key=lambda x: x['potential_impact'], reverse=True)
    
    def _calculate_overall_confidence(self, dimension_scores: Dict, nlp_analysis: Dict) -> float:
        """Calculate confidence level in the assessment"""
        # Base confidence
        confidence = 0.8
        
        # Increase confidence if all dimensions have data
        complete_dimensions = sum(1 for score in dimension_scores.values() if score > 0)
        confidence += (complete_dimensions / len(dimension_scores)) * 0.15
        
        # Factor in NLP confidence
        nlp_confidence = nlp_analysis.get('confidence', 0.7)
        confidence = (confidence * 0.7) + (nlp_confidence * 0.3)
        
        return min(1.0, confidence)
    
    def _calculate_next_review_date(self, risk_level: ShariahRiskLevel) -> str:
        """Calculate next review date based on risk level"""
        days_map = {
            ShariahRiskLevel.VERY_LOW: 365,    # Annual review
            ShariahRiskLevel.LOW: 180,         # Semi-annual review
            ShariahRiskLevel.MEDIUM: 90,       # Quarterly review
            ShariahRiskLevel.HIGH: 30,         # Monthly review
            ShariahRiskLevel.CRITICAL: 7       # Weekly review
        }
        
        days_to_add = days_map.get(risk_level, 90)
        next_review = datetime.utcnow() + timedelta(days=days_to_add)
        return next_review.strftime('%Y-%m-%d')
    
    def _identify_compliance_gaps(self, dimension_scores: Dict[str, float]) -> List[Dict]:
        """Identify specific compliance gaps"""
        gaps = []
        
        for dimension, score in dimension_scores.items():
            if score < 100:
                gap_percentage = 100 - score
                gaps.append({
                    'dimension': dimension,
                    'gap_percentage': round(gap_percentage, 2),
                    'severity': 'critical' if gap_percentage > 40 else 'high' if gap_percentage > 20 else 'medium'
                })
        
        return sorted(gaps, key=lambda x: x['gap_percentage'], reverse=True)
    
    def _map_to_regulatory_requirements(self, dimension_scores: Dict[str, float]) -> Dict:
        """Map assessment results to regulatory requirements"""
        return {
            'sc_malaysia_compliance': self._check_sc_malaysia_compliance(dimension_scores),
            'aaoifi_compliance': self._check_aaoifi_compliance(dimension_scores),
            'ifsb_guidelines': self._check_ifsb_compliance(dimension_scores),
            'overall_regulatory_score': self._calculate_regulatory_score(dimension_scores)
        }
    
    def _check_sc_malaysia_compliance(self, dimension_scores: Dict[str, float]) -> Dict:
        """Check Securities Commission Malaysia compliance"""
        return {
            'financial_ratio_compliance': dimension_scores.get('financial_structure', 0) >= 75,
            'business_activity_compliance': dimension_scores.get('business_activity', 0) >= 80,
            'overall_compliance': dimension_scores.get('financial_structure', 0) >= 75 and dimension_scores.get('business_activity', 0) >= 80
        }
    
    def _check_aaoifi_compliance(self, dimension_scores: Dict[str, float]) -> Dict:
        """Check AAOIFI standards compliance"""
        return {
            'governance_compliance': dimension_scores.get('governance', 0) >= 70,
            'shariah_compliance': dimension_scores.get('fundamental_compliance', 0) >= 80,
            'overall_compliance': all(score >= 70 for score in dimension_scores.values())
        }
    
    def _check_ifsb_compliance(self, dimension_scores: Dict[str, float]) -> Dict:
        """Check IFSB guidelines compliance"""
        return {
            'risk_management_compliance': dimension_scores.get('operational', 0) >= 60,
            'governance_compliance': dimension_scores.get('governance', 0) >= 70,
            'overall_compliance': all(score >= 60 for score in dimension_scores.values())
        }
    
    def _calculate_regulatory_score(self, dimension_scores: Dict[str, float]) -> float:
        """Calculate overall regulatory compliance score"""
        # Weighted average emphasizing critical dimensions for regulatory compliance
        regulatory_weights = {
            'fundamental_compliance': 0.35,
            'financial_structure': 0.25,
            'business_activity': 0.20,
            'governance': 0.15,
            'operational': 0.03,
            'market_contextual': 0.02
        }
        
        regulatory_score = sum(
            dimension_scores.get(dimension, 0) * weight 
            for dimension, weight in regulatory_weights.items()
        )
        
        return round(regulatory_score, 2)


class EnhancedShariahNLP:
    """
    Enhanced NLP processor for comprehensive Shariah compliance analysis
    Builds upon your existing FinBERT implementation
    """
    
    def __init__(self):
        # Enhanced keyword dictionaries based on research
        self.compliance_keywords = {
            'positive_indicators': [
                'mudarabah', 'musharakah', 'murabaha', 'ijara', 'istisna', 'salam',
                'wakalah', 'kafalah', 'takaful', 'sukuk', 'profit-sharing',
                'asset-backed', 'halal', 'shariah-compliant', 'islamic banking',
                'riba-free', 'interest-free', 'ethical investment', 'socially responsible'
            ],
            'riba_indicators': [
                'interest', 'riba', 'usury', 'fixed return', 'guaranteed return',
                'interest rate', 'conventional banking', 'loan interest',
                'compound interest', 'simple interest', 'apr', 'annual percentage rate'
            ],
            'gharar_indicators': [
                'gharar', 'uncertainty', 'speculation', 'ambiguity', 'unclear terms',
                'undefined conditions', 'excessive risk', 'uncertain outcome',
                'vague contract', 'incomplete information'
            ],
            'maysir_indicators': [
                'maysir', 'gambling', 'lottery', 'speculation', 'betting', 'casino',
                'games of chance', 'derivatives trading', 'short selling',
                'margin trading', 'options trading'
            ],
            'prohibited_activities': [
                'alcohol', 'liquor', 'wine', 'beer', 'pork', 'tobacco', 'cigarettes',
                'adult entertainment', 'casino', 'nightclub', 'weapons', 'arms trade'
            ]
        }
    
    def analyze_comprehensive_text(self, business_description: str, purpose_of_financing: str) -> Dict:
        """Perform comprehensive NLP analysis"""
        
        combined_text = f"{business_description} {purpose_of_financing}".lower()
        
        # Keyword analysis
        keyword_analysis = self._analyze_keywords(combined_text)
        
        # Sentiment analysis (placeholder for your FinBERT integration)
        sentiment_analysis = self._analyze_sentiment_with_finbert(combined_text)
        
        # Risk pattern detection
        risk_patterns = self._detect_risk_patterns(combined_text)
        
        # Critical violation detection
        critical_violations = self._detect_critical_violations(combined_text)
        
        # Calculate confidence
        confidence = self._calculate_nlp_confidence(keyword_analysis, sentiment_analysis)
        
        return {
            'keyword_analysis': keyword_analysis,
            'sentiment_analysis': sentiment_analysis,
            'risk_patterns': risk_patterns,
            'critical_violations': critical_violations,
            'confidence': confidence,
            'overall_risk_score': self._calculate_text_risk_score(keyword_analysis, risk_patterns)
        }
    
    def _analyze_keywords(self, text: str) -> Dict:
        """Analyze text for Shariah-related keywords"""
        analysis = {}
        
        for category, keywords in self.compliance_keywords.items():
            found_keywords = [kw for kw in keywords if kw in text]
            analysis[category] = {
                'count': len(found_keywords),
                'keywords_found': found_keywords,
                'density': len(found_keywords) / len(keywords) if keywords else 0
            }
        
        return analysis
    
    def _analyze_sentiment_with_finbert(self, text: str) -> Dict:
        """
        Integrate with your existing FinBERT model
        This is where you'd call your existing model
        """
        # Placeholder - integrate with your existing FinBERT implementation
        return {
            'sentiment': 'neutral',
            'confidence': 0.8,
            'shariah_compliance_probability': 0.75,
            'risk_sentiment': 'low'
        }
    
    def _detect_risk_patterns(self, text: str) -> List[Dict]:
        """Detect patterns that indicate compliance risks"""
        patterns = []
        
        # Pattern detection logic
        risk_patterns = {
            'interest_patterns': ['%', 'rate', 'annual', 'monthly interest', 'fixed rate'],
            'guarantee_patterns': ['guaranteed', 'assured return', 'fixed profit', 'guaranteed profit'],
            'speculation_patterns': ['high risk', 'volatile', 'speculative', 'derivatives'],
            'prohibited_business': ['alcohol sales', 'tobacco distribution', 'casino operations']
        }
        
        for pattern_type, pattern_keywords in risk_patterns.items():
            detected = [p for p in pattern_keywords if p in text]
            if detected:
                patterns.append({
                    'pattern_type': pattern_type,
                    'detected_patterns': detected,
                    'severity': self._assess_pattern_severity(pattern_type, len(detected))
                })
        
        return patterns
    
    def _detect_critical_violations(self, text: str) -> List[str]:
        """Detect critical Shariah violations that warrant immediate rejection"""
        violations = []
        
        critical_terms = [
            'interest-based lending', 'conventional banking operations',
            'alcohol production', 'gambling operations', 'adult entertainment',
            'weapons manufacturing', 'tobacco production'
        ]
        
        for term in critical_terms:
            if term in text:
                violations.append(term)
        
        return violations
    
    def _assess_pattern_severity(self, pattern_type: str, count: int) -> str:
        """Assess the severity of detected patterns"""
        severity_map = {
            'interest_patterns': 'high',
            'guarantee_patterns': 'medium',
            'speculation_patterns': 'medium',
            'prohibited_business': 'critical'
        }
        
        base_severity = severity_map.get(pattern_type, 'low')
        
        # Escalate based on count
        if count > 3 and base_severity != 'critical':
            severity_levels = ['low', 'medium', 'high', 'critical']
            current_index = severity_levels.index(base_severity)
            return severity_levels[min(current_index + 1, len(severity_levels) - 1)]
        
        return base_severity
    
    def _calculate_nlp_confidence(self, keyword_analysis: Dict, sentiment_analysis: Dict) -> float:
        """Calculate overall confidence in NLP analysis"""
        base_confidence = 0.7
        
        # Increase confidence based on keyword detection
        total_keywords = sum(cat['count'] for cat in keyword_analysis.values())
        if total_keywords > 5:
            base_confidence += 0.15
        
        # Factor in sentiment analysis confidence
        sentiment_confidence = sentiment_analysis.get('confidence', 0.5)
        combined_confidence = (base_confidence * 0.6) + (sentiment_confidence * 0.4)
        
        return min(1.0, combined_confidence)
    
    def _calculate_text_risk_score(self, keyword_analysis: Dict, risk_patterns: List[Dict]) -> float:
        """Calculate risk score based on text analysis"""
        risk_score = 0.0
        
        # Add risk based on negative indicators
        riba_indicators = keyword_analysis.get('riba_indicators', {}).get('count', 0)
        gharar_indicators = keyword_analysis.get('gharar_indicators', {}).get('count', 0)
        maysir_indicators = keyword_analysis.get('maysir_indicators', {}).get('count', 0)
        prohibited_activities = keyword_analysis.get('prohibited_activities', {}).get('count', 0)
        
        risk_score += riba_indicators * 20  # High weight for Riba
        risk_score += gharar_indicators * 15
        risk_score += maysir_indicators * 15
        risk_score += prohibited_activities * 25
        
        # Add risk based on patterns
        for pattern in risk_patterns:
            severity_weights = {'low': 5, 'medium': 10, 'high': 20, 'critical': 40}
            risk_score += severity_weights.get(pattern['severity'], 5)
        
        return min(100, risk_score)  # Cap at 100