# routes/shariah_routes.py
"""
Enhanced Shariah Risk Assessment Routes
Separate routes module to keep app.py clean
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from datetime import datetime
import json
import logging

# Import your existing authentication decorators
from app import role_required, login_required, UserRole, get_current_user, db, AuditLog

# Import the new models and services
from models.shariah_models import (
    ComprehensiveShariahAssessment, 
    ShariahAssessmentAudit, 
    ShariahProductTemplate,
    ShariahComplianceLevel,
    ShariahRiskLevel
)

from services.shariah_scoring_engine import (
    ComprehensiveShariahScoringEngine, 
    ShariahAssessmentInput
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint for Shariah routes
shariah_bp = Blueprint('shariah', __name__, url_prefix='/shariah')

# Initialize the scoring engine
scoring_engine = ComprehensiveShariahScoringEngine()

@shariah_bp.route('/comprehensive-assessment', methods=['GET', 'POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def comprehensive_assessment():
    """
    Main comprehensive Shariah risk assessment interface
    This replaces your existing basic shariah_risk_assessment route
    """
    if request.method == 'GET':
        # Load product templates for the interface
        templates = ShariahProductTemplate.query.filter_by(is_active=True).all()
        
        return render_template('shariah/comprehensive_assessment.html', 
                             templates=templates,
                             current_user=get_current_user())
    
    elif request.method == 'POST':
        try:
            # Get the action (analyze or save)
            action = request.form.get('action', 'analyze')
            
            # Extract form data and create assessment input
            assessment_input = _extract_assessment_input_from_form(request.form)
            
            if action == 'analyze':
                # Perform comprehensive assessment
                assessment_results = scoring_engine.perform_comprehensive_assessment(assessment_input)
                
                # Return results for display (AJAX response)
                if request.headers.get('Content-Type') == 'application/json':
                    return jsonify(assessment_results)
                
                # For regular form submission, render with results
                return render_template('shariah/comprehensive_assessment.html',
                                     assessment_results=assessment_results,
                                     form_data=request.form)
            
            elif action == 'save':
                # Save the assessment to database
                saved_assessment = _save_comprehensive_assessment(assessment_input, request.form)
                
                # Log the action
                AuditLog.log_action(
                    user_id=session['user_id'],
                    action='COMPREHENSIVE_SHARIAH_ASSESSMENT_CREATED',
                    resource='shariah_assessment',
                    resource_id=saved_assessment.application_id,
                    details={'assessment_type': 'comprehensive'},
                    request_obj=request
                )
                
                flash(f'Comprehensive Shariah assessment saved for application {saved_assessment.application_id}', 'success')
                return redirect(url_for('shariah.assessment_dashboard'))
                
        except Exception as e:
            logger.error(f"Error in comprehensive assessment: {str(e)}")
            flash(f'Error processing assessment: {str(e)}', 'danger')
            return render_template('shariah/comprehensive_assessment.html')

@shariah_bp.route('/assessment-dashboard')
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def assessment_dashboard():
    """
    Enhanced dashboard showing comprehensive assessment statistics
    """
    try:
        # Get comprehensive statistics
        stats = _get_comprehensive_dashboard_stats()
        
        # Get recent assessments
        recent_assessments = ComprehensiveShariahAssessment.query\
            .order_by(ComprehensiveShariahAssessment.assessment_date.desc())\
            .limit(10).all()
        
        # Convert to dictionaries for JSON serialization
        recent_assessments_data = [assessment.to_dict() for assessment in recent_assessments]
        
        return render_template('shariah/enhanced_dashboard.html',
                             stats=stats,
                             recent_assessments=recent_assessments_data)
                             
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash('Error loading dashboard data', 'danger')
        return redirect(url_for('dashboard'))

@shariah_bp.route('/saved-assessments')
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def saved_assessments():
    """
    View all saved comprehensive assessments with filtering
    """
    try:
        # Get filter parameters
        compliance_filter = request.args.get('compliance_level', '')
        risk_filter = request.args.get('risk_level', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Build query with filters
        query = ComprehensiveShariahAssessment.query
        
        if compliance_filter:
            query = query.filter(ComprehensiveShariahAssessment.compliance_level == compliance_filter)
        
        if risk_filter:
            query = query.filter(ComprehensiveShariahAssessment.risk_level == risk_filter)
        
        if date_from:
            query = query.filter(ComprehensiveShariahAssessment.assessment_date >= datetime.strptime(date_from, '%Y-%m-%d'))
        
        if date_to:
            query = query.filter(ComprehensiveShariahAssessment.assessment_date <= datetime.strptime(date_to, '%Y-%m-%d'))
        
        # Order by most recent first
        assessments = query.order_by(ComprehensiveShariahAssessment.assessment_date.desc()).all()
        
        return render_template('shariah/saved_assessments.html',
                             assessments=assessments,
                             compliance_levels=ShariahComplianceLevel,
                             risk_levels=ShariahRiskLevel,
                             current_filters={
                                 'compliance_level': compliance_filter,
                                 'risk_level': risk_filter,
                                 'date_from': date_from,
                                 'date_to': date_to
                             })
                             
    except Exception as e:
        logger.error(f"Error loading saved assessments: {str(e)}")
        flash('Error loading assessments', 'danger')
        return redirect(url_for('shariah.assessment_dashboard'))

@shariah_bp.route('/assessment-details/<int:assessment_id>')
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def assessment_details(assessment_id):
    """
    View detailed assessment results and recommendations
    """
    try:
        assessment = ComprehensiveShariahAssessment.query.get_or_404(assessment_id)
        
        # Get dimension breakdown
        dimension_breakdown = assessment.get_dimension_breakdown()
        
        # Get audit trail
        audit_trail = ShariahAssessmentAudit.query\
            .filter_by(assessment_id=assessment_id)\
            .order_by(ShariahAssessmentAudit.action_timestamp.desc())\
            .all()
        
        return render_template('shariah/assessment_details.html',
                             assessment=assessment,
                             dimension_breakdown=dimension_breakdown,
                             audit_trail=audit_trail)
                             
    except Exception as e:
        logger.error(f"Error loading assessment details: {str(e)}")
        flash('Error loading assessment details', 'danger')
        return redirect(url_for('shariah.saved_assessments'))

@shariah_bp.route('/bulk-assessment', methods=['GET', 'POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def bulk_assessment():
    """
    Bulk assessment functionality for multiple applications
    """
    if request.method == 'GET':
        return render_template('shariah/bulk_assessment.html')
    
    elif request.method == 'POST':
        try:
            uploaded_file = request.files.get('assessment_file')
            
            if not uploaded_file:
                flash('No file uploaded', 'danger')
                return redirect(url_for('shariah.bulk_assessment'))
            
            # Process bulk assessment file
            results = _process_bulk_assessment_file(uploaded_file)
            
            flash(f'Processed {len(results)} assessments successfully', 'success')
            return render_template('shariah/bulk_assessment_results.html', results=results)
            
        except Exception as e:
            logger.error(f"Error in bulk assessment: {str(e)}")
            flash(f'Error processing bulk assessment: {str(e)}', 'danger')
            return redirect(url_for('shariah.bulk_assessment'))

@shariah_bp.route('/api/quick-assessment', methods=['POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def api_quick_assessment():
    """
    API endpoint for quick assessment (AJAX calls)
    """
    try:
        data = request.get_json()
        
        # Create quick assessment input
        assessment_input = ShariahAssessmentInput(
            application_id=data.get('application_id', ''),
            customer_name=data.get('customer_name', ''),
            customer_category=data.get('customer_category', ''),
            product_type=data.get('product_type', ''),
            financing_amount=float(data.get('financing_amount', 0)),
            financing_tenor=int(data.get('financing_tenor', 12)),
            purpose_of_financing=data.get('purpose_of_financing', ''),
            business_description=data.get('business_description', '')
        )
        
        # Perform quick assessment
        results = scoring_engine.perform_comprehensive_assessment(assessment_input)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error in API quick assessment: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@shariah_bp.route('/reports/compliance-summary')
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def compliance_summary_report():
    """
    Generate comprehensive compliance summary report
    """
    try:
        # Get date range
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Generate report data
        report_data = _generate_compliance_summary_report(date_from, date_to)
        
        return render_template('shariah/compliance_report.html',
                             report_data=report_data,
                             date_from=date_from,
                             date_to=date_to)
                             
    except Exception as e:
        logger.error(f"Error generating compliance report: {str(e)}")
        flash('Error generating report', 'danger')
        return redirect(url_for('shariah.assessment_dashboard'))

@shariah_bp.route('/product-templates')
@role_required(UserRole.ADMIN)
def manage_product_templates():
    """
    Manage Shariah product templates (Admin only)
    """
    try:
        templates = ShariahProductTemplate.query.all()
        return render_template('shariah/product_templates.html', templates=templates)
        
    except Exception as e:
        logger.error(f"Error loading product templates: {str(e)}")
        flash('Error loading templates', 'danger')
        return redirect(url_for('shariah.assessment_dashboard'))

# === HELPER FUNCTIONS ===

def _extract_assessment_input_from_form(form_data) -> ShariahAssessmentInput:
    """Extract and validate form data into ShariahAssessmentInput"""
    
    # Extract basic information
    assessment_input = ShariahAssessmentInput(
        application_id=form_data.get('application_id', ''),
        customer_name=form_data.get('customer_name', ''),
        customer_category=form_data.get('customer_category', ''),
        product_type=form_data.get('product_type', ''),
        financing_amount=float(form_data.get('financing_amount', 0)),
        financing_tenor=int(form_data.get('financing_tenor', 12)),
        purpose_of_financing=form_data.get('purpose_of_financing', ''),
        business_description=form_data.get('business_description', '')
    )
    
    # Extract fundamental compliance data
    assessment_input.riba_assessment = {
        'has_riba': form_data.get('has_riba') == 'true',
        'riba_type': form_data.get('riba_type', 'none'),
        'riba_percentage': float(form_data.get('riba_percentage', 0)),
        'mitigation_measures': form_data.getlist('mitigation_measures')
    }
    
    assessment_input.gharar_assessment = {
        'gharar_level': form_data.get('gharar_level', 'low'),
        'uncertainty_sources': form_data.getlist('uncertainty_sources'),
        'risk_mitigation': form_data.getlist('gharar_mitigation')
    }
    
    assessment_input.maysir_assessment = {
        'has_maysir': form_data.get('has_maysir') == 'true',
        'gambling_elements': form_data.getlist('gambling_elements'),
        'speculation_level': form_data.get('speculation_level', 'low')
    }
    
    # Extract financial ratios
    assessment_input.cash_to_total_assets = _safe_float_convert(form_data.get('cash_to_total_assets'))
    assessment_input.debt_to_total_assets = _safe_float_convert(form_data.get('debt_to_total_assets'))
    assessment_input.interest_income_ratio = _safe_float_convert(form_data.get('interest_income_ratio'))
    
    # Extract business activities (5% threshold)
    assessment_input.prohibited_5pct_activities = {
        'conventional_banking': _safe_float_convert(form_data.get('conventional_banking', 0)),
        'conventional_insurance': _safe_float_convert(form_data.get('conventional_insurance', 0)),
        'gambling': _safe_float_convert(form_data.get('gambling', 0)),
        'liquor_tobacco': _safe_float_convert(form_data.get('liquor_tobacco', 0)),
        'pork_products': _safe_float_convert(form_data.get('pork_products', 0)),
        'non_halal_food': _safe_float_convert(form_data.get('non_halal_food', 0)),
        'interest_income': _safe_float_convert(form_data.get('interest_income_business', 0)),
        'adult_entertainment': _safe_float_convert(form_data.get('adult_entertainment', 0))
    }
    
    # Extract business activities (20% threshold)
    assessment_input.prohibited_20pct_activities = {
        'share_trading': _safe_float_convert(form_data.get('share_trading', 0)),
        'stockbroking': _safe_float_convert(form_data.get('stockbroking', 0)),
        'cinema_entertainment': _safe_float_convert(form_data.get('cinema_entertainment', 0)),
        'rental_non_compliant': _safe_float_convert(form_data.get('rental_non_compliant', 0)),
        'music_industry': _safe_float_convert(form_data.get('music_industry', 0))
    }
    
    # Extract governance data
    assessment_input.governance_assessment = {
        'shariah_board_established': form_data.get('shariah_board_established') == 'true',
        'shariah_board_members': int(form_data.get('shariah_board_members', 0)),
        'internal_shariah_audit': form_data.get('internal_shariah_audit') == 'true',
        'shariah_compliance_officer': form_data.get('shariah_compliance_officer') == 'true',
        'fatwa_compliance': form_data.get('fatwa_compliance', 'none'),
        'documentation_quality': form_data.get('documentation_quality', 'fair'),
        'compliance_monitoring': form_data.get('compliance_monitoring') == 'true',
        'dispute_resolution': form_data.get('dispute_resolution') == 'true'
    }
    
    # Extract operational controls
    assessment_input.operational_controls = {
        'staff_training': form_data.get('staff_training') == 'true',
        'system_controls': form_data.get('system_controls') == 'true',
        'process_segregation': form_data.get('process_segregation') == 'true',
        'error_rectification': form_data.get('error_rectification') == 'true',
        'compliance_reporting': form_data.get('compliance_reporting') == 'true'
    }
    
    # Extract market factors
    assessment_input.market_factors = {
        'market_volatility': form_data.get('market_volatility', 'medium'),
        'regulatory_environment': form_data.get('regulatory_environment', 'stable'),
        'competitive_pressure': form_data.get('competitive_pressure', 'medium')
    }
    
    return assessment_input

def _save_comprehensive_assessment(assessment_input: ShariahAssessmentInput, form_data) -> ComprehensiveShariahAssessment:
    """Save comprehensive assessment to database"""
    
    # Perform the assessment to get scores
    assessment_results = scoring_engine.perform_comprehensive_assessment(assessment_input)
    
    # Create database record
    new_assessment = ComprehensiveShariahAssessment(
        application_id=assessment_input.application_id,
        assessed_by=session['user_id'],
        customer_name=assessment_input.customer_name,
        customer_category=assessment_input.customer_category,
        product_type=assessment_input.product_type,
        financing_amount=assessment_input.financing_amount,
        financing_tenor=assessment_input.financing_tenor,
        purpose_of_financing=assessment_input.purpose_of_financing,
        business_description=assessment_input.business_description,
        
        # Store assessment data as JSON
        riba_assessment=assessment_input.riba_assessment,
        gharar_assessment=assessment_input.gharar_assessment,
        maysir_assessment=assessment_input.maysir_assessment,
        contract_analysis=assessment_input.contract_analysis or {},
        
        # Financial ratios
        cash_to_total_assets=assessment_input.cash_to_total_assets,
        debt_to_total_assets=assessment_input.debt_to_total_assets,
        interest_income_ratio=assessment_input.interest_income_ratio,
        
        # Business activities
        prohibited_5pct_activities=assessment_input.prohibited_5pct_activities,
        prohibited_20pct_activities=assessment_input.prohibited_20pct_activities,
        
        # Governance and controls
        governance_assessment=assessment_input.governance_assessment,
        operational_controls=assessment_input.operational_controls,
        market_factors=assessment_input.market_factors,
        
        # Assessment results
        fundamental_compliance_score=assessment_results['dimension_scores']['fundamental_compliance'],
        financial_structure_score=assessment_results['dimension_scores']['financial_structure'],
        business_activity_score=assessment_results['dimension_scores']['business_activity'],
        governance_score=assessment_results['dimension_scores']['governance'],
        operational_score=assessment_results['dimension_scores']['operational'],
        market_contextual_score=assessment_results['dimension_scores']['market_contextual'],
        
        # NLP analysis
        nlp_analysis=assessment_results.get('nlp_analysis', {}),
        
        # Final results
        final_recommendation=assessment_results['final_recommendation'],
        improvement_recommendations=assessment_results.get('detailed_recommendations', [])
    )
    
    # Calculate composite score
    new_assessment.calculate_composite_score()
    
    # Save to database
    db.session.add(new_assessment)
    db.session.commit()
    
    # Create audit record
    audit_record = ShariahAssessmentAudit(
        assessment_id=new_assessment.id,
        action_type='CREATE',
        performed_by=session['user_id'],
        new_values=assessment_results,
        comments='Comprehensive Shariah assessment created',
        ip_address=request.remote_addr
    )
    
    db.session.add(audit_record)
    db.session.commit()
    
    return new_assessment

def _get_comprehensive_dashboard_stats() -> Dict:
    """Get comprehensive dashboard statistics"""
    
    total_assessments = ComprehensiveShariahAssessment.query.count()
    
    # Compliance level distribution
    compliance_stats = {}
    for level in ShariahComplianceLevel:
        count = ComprehensiveShariahAssessment.query.filter_by(compliance_level=level).count()
        compliance_stats[level.value] = count
    
    # Risk level distribution
    risk_stats = {}
    for level in ShariahRiskLevel:
        count = ComprehensiveShariahAssessment.query.filter_by(risk_level=level).count()
        risk_stats[level.value] = count
    
    # Average scores by dimension
    from sqlalchemy import func
    avg_scores = db.session.query(
        func.avg(ComprehensiveShariahAssessment.fundamental_compliance_score).label('fundamental'),
        func.avg(ComprehensiveShariahAssessment.financial_structure_score).label('financial'),
        func.avg(ComprehensiveShariahAssessment.business_activity_score).label('business'),
        func.avg(ComprehensiveShariahAssessment.governance_score).label('governance'),
        func.avg(ComprehensiveShariahAssessment.operational_score).label('operational'),
        func.avg(ComprehensiveShariahAssessment.market_contextual_score).label('market')
    ).first()
    
    return {
        'total_assessments': total_assessments,
        'compliance_distribution': compliance_stats,
        'risk_distribution': risk_stats,
        'average_dimension_scores': {
            'fundamental_compliance': round(avg_scores.fundamental or 0, 2),
            'financial_structure': round(avg_scores.financial or 0, 2),
            'business_activity': round(avg_scores.business or 0, 2),
            'governance': round(avg_scores.governance or 0, 2),
            'operational': round(avg_scores.operational or 0, 2),
            'market_contextual': round(avg_scores.market or 0, 2)
        }
    }

def _safe_float_convert(value) -> float:
    """Safely convert value to float"""
    try:
        return float(value) if value else 0.0
    except (ValueError, TypeError):
        return 0.0

def _process_bulk_assessment_file(uploaded_file) -> List[Dict]:
    """Process bulk assessment file"""
    # Implementation for bulk processing
    # This would read CSV/Excel files and process multiple assessments
    results = []
    # Add your bulk processing logic here
    return results

def _generate_compliance_summary_report(date_from: str, date_to: str) -> Dict:
    """Generate compliance summary report"""
    # Implementation for report generation
    # This would create comprehensive compliance reports
    report_data = {
        'summary': {},
        'trends': {},
        'recommendations': []
    }
    return report_data