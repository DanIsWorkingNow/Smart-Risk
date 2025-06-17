def migrate_existing_shariah_data():
    """
    Optional: Migrate your existing ShariahRiskApplication data 
    to the new ComprehensiveShariahAssessment format
    """
    try:
        # Import your existing model
        from app import ShariahRiskApplication
        
        existing_assessments = ShariahRiskApplication.query.all()
        
        for old_assessment in existing_assessments:
            # Check if already migrated
            existing_new = ComprehensiveShariahAssessment.query.filter_by(
                application_id=old_assessment.application_id
            ).first()
            
            if not existing_new:
                # Create new comprehensive assessment from old data
                new_assessment = ComprehensiveShariahAssessment(
                    application_id=old_assessment.application_id,
                    assessment_date=old_assessment.application_date,
                    assessed_by=1,  # Default to admin user
                    customer_name=old_assessment.customer_name,
                    customer_category=old_assessment.customer_category,
                    product_type='legacy_tawarruq',  # Default for legacy data
                    financing_amount=old_assessment.loan_amount,
                    financing_tenor=12,  # Default value
                    purpose_of_financing=old_assessment.purpose_of_financing,
                    business_description=old_assessment.business_description,
                    
                    # Map legacy fields to new structure
                    riba_assessment={
                        'has_riba': old_assessment.riba == 'Yes',
                        'riba_type': 'unknown',
                        'riba_percentage': 0.0,
                        'mitigation_measures': []
                    },
                    
                    gharar_assessment={
                        'gharar_level': 'high' if old_assessment.gharar == 'Yes' else 'low',
                        'uncertainty_sources': [],
                        'risk_mitigation': []
                    },
                    
                    maysir_assessment={
                        'has_maysir': old_assessment.maysir == 'Present',
                        'gambling_elements': [],
                        'speculation_level': 'medium' if old_assessment.maysir == 'Present' else 'low'
                    },
                    
                    # Set default values for missing fields
                    prohibited_5pct_activities={k: 0.0 for k in [
                        'conventional_banking', 'conventional_insurance', 'gambling',
                        'liquor_tobacco', 'pork_products', 'non_halal_food',
                        'interest_income', 'adult_entertainment'
                    ]},
                    
                    prohibited_20pct_activities={k: 0.0 for k in [
                        'share_trading', 'stockbroking', 'cinema_entertainment',
                        'rental_non_compliant', 'music_industry'
                    ]},
                    
                    governance_assessment={
                        'shariah_board_established': False,
                        'shariah_board_members': 0,
                        'internal_shariah_audit': False,
                        'shariah_compliance_officer': False,
                        'fatwa_compliance': 'none',
                        'documentation_quality': 'fair',
                        'compliance_monitoring': False,
                        'dispute_resolution': False
                    },
                    
                    operational_controls={
                        'staff_training': False,
                        'system_controls': False,
                        'process_segregation': False,
                        'error_rectification': False,
                        'compliance_reporting': False
                    },
                    
                    market_factors={
                        'market_volatility': 'medium',
                        'regulatory_environment': 'stable',
                        'competitive_pressure': 'medium'
                    },
                    
                    # Map legacy risk score
                    final_recommendation='approve' if old_assessment.shariah_risk_score in ['Halal', 'Compliant'] else 'reject'
                )
                
                # Set basic scores based on legacy assessment
                if old_assessment.shariah_risk_score == 'Halal':
                    new_assessment.fundamental_compliance_score = 90
                    new_assessment.compliance_level = ShariahComplianceLevel.SUBSTANTIALLY_COMPLIANT
                    new_assessment.risk_level = ShariahRiskLevel.LOW
                elif old_assessment.shariah_risk_score == 'Haram':
                    new_assessment.fundamental_compliance_score = 30
                    new_assessment.compliance_level = ShariahComplianceLevel.NON_COMPLIANT
                    new_assessment.risk_level = ShariahRiskLevel.HIGH
                else:
                    new_assessment.fundamental_compliance_score = 60
                    new_assessment.compliance_level = ShariahComplianceLevel.PARTIALLY_COMPLIANT
                    new_assessment.risk_level = ShariahRiskLevel.MEDIUM
                
                # Set default scores for other dimensions
                new_assessment.financial_structure_score = 75
                new_assessment.business_activity_score = 80
                new_assessment.governance_score = 50
                new_assessment.operational_score = 60
                new_assessment.market_contextual_score = 75
                
                # Calculate composite score
                new_assessment.calculate_composite_score()
                
                db.session.add(new_assessment)
        
        db.session.commit()
        print(f"Migrated {len(existing_assessments)} legacy assessments to comprehensive format")
        
    except Exception as e:
        print(f"Migration error: {str(e)}")
        db.session.rollback()