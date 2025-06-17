# scripts/init_enhanced_shariah.py
"""
Enhanced Shariah Risk Assessment Initialization Script
Run this script to set up the enhanced Shariah system properly
"""

import os
import sys
from datetime import datetime

# Add the parent directory to path to import from app.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    print("🚀 SMART-Risk Enhanced Shariah System Initialization")
    print("=" * 60)
    
    try:
        # Import Flask app and dependencies
        from app import app, db
        
        print("✅ Flask app imported successfully")
        
        # Try to import enhanced Shariah modules
        try:
            import models.shariah_models as shariah_models
            from services.shariah_scoring_engine import ComprehensiveShariahScoringEngine
            enhanced_available = True
            print("✅ Enhanced Shariah modules imported successfully")
        except ImportError as e:
            print(f"❌ Enhanced Shariah modules not available: {e}")
            enhanced_available = False
            return False
        
        with app.app_context():
            print("\n📊 Initializing database...")
            
            # Initialize the enhanced models with database
            shariah_models.init_shariah_models(db)
            print("✅ Enhanced Shariah models initialized")
            
            # Create all tables
            db.create_all()
            print("✅ Database tables created")
            
            # Create sample product templates
            create_sample_templates(shariah_models, db)
            
            # Test the scoring engine
            test_scoring_engine()
            
            print("\n🎉 Enhanced Shariah system initialization completed successfully!")
            print("\nNext steps:")
            print("1. Update your app.py with the integration code")
            print("2. Create the HTML templates")
            print("3. Update your navigation menu")
            print("4. Run python app.py to start the enhanced system")
            
            return True
            
    except Exception as e:
        print(f"❌ Error during initialization: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_sample_templates(shariah_models, db):
    """Create sample Shariah product templates"""
    print("\n📋 Creating sample product templates...")
    
    sample_templates = [
        {
            'product_type': 'murabaha',
            'template_name': 'Standard Murabaha Financing',
            'description': 'Cost-plus sale financing template for asset acquisition',
            'required_parameters': [
                'asset_identification', 'cost_price', 'profit_margin', 
                'ownership_transfer', 'payment_terms'
            ],
            'scoring_weights': {
                'fundamental_compliance': 0.45,
                'financial_structure': 0.25,
                'business_activity': 0.15,
                'governance': 0.10,
                'operational': 0.03,
                'market_contextual': 0.02
            },
            'compliance_thresholds': {
                'asset_backing_required': True,
                'ownership_transfer_required': True,
                'profit_margin_disclosure': True
            },
            'shariah_requirements': [
                'Asset must be owned by financier before sale',
                'Clear identification of asset required',
                'Profit margin must be disclosed',
                'No penalty for early settlement'
            ],
            'prohibited_elements': [
                'Interest-based penalty',
                'Uncertain profit margin',
                'Sale of non-existent assets',
                'Riba al-fadl'
            ]
        },
        {
            'product_type': 'mudarabah',
            'template_name': 'Profit-Sharing Investment',
            'description': 'Mudarabah investment template for business partnerships',
            'required_parameters': [
                'capital_contribution', 'profit_sharing_ratio', 
                'loss_sharing_terms', 'management_responsibilities'
            ],
            'scoring_weights': {
                'fundamental_compliance': 0.40,
                'financial_structure': 0.20,
                'business_activity': 0.25,
                'governance': 0.12,
                'operational': 0.02,
                'market_contextual': 0.01
            },
            'compliance_thresholds': {
                'profit_sharing_predetermined': True,
                'loss_sharing_based_on_capital': True,
                'management_by_mudarib': True
            },
            'shariah_requirements': [
                'Profit sharing ratio predetermined',
                'Losses borne by capital provider',
                'Mudarib provides management expertise',
                'No guaranteed return to investor'
            ],
            'prohibited_elements': [
                'Guaranteed profit',
                'Fixed return to mudarib',
                'Penalty for loss',
                'Investor interference in management'
            ]
        },
        {
            'product_type': 'ijara',
            'template_name': 'Islamic Leasing',
            'description': 'Ijara (leasing) template for asset rental',
            'required_parameters': [
                'asset_description', 'lease_period', 'rental_amount',
                'maintenance_responsibility', 'end_of_lease_options'
            ],
            'scoring_weights': {
                'fundamental_compliance': 0.42,
                'financial_structure': 0.23,
                'business_activity': 0.18,
                'governance': 0.12,
                'operational': 0.03,
                'market_contextual': 0.02
            },
            'compliance_thresholds': {
                'asset_ownership_by_lessor': True,
                'clear_lease_terms': True,
                'maintenance_responsibility_defined': True
            },
            'shariah_requirements': [
                'Lessor must own the asset',
                'Asset must be usufruct',
                'Rental amount predetermined',
                'Clear maintenance responsibilities'
            ],
            'prohibited_elements': [
                'Penalty for late payment without actual damage',
                'Rental of non-existent assets',
                'Unclear lease terms'
            ]
        }
    ]
    
    created_count = 0
    for template_data in sample_templates:
        # Check if template already exists
        existing = shariah_models.ShariahProductTemplate.query.filter_by(
            product_type=template_data['product_type']
        ).first()
        
        if not existing:
            template = shariah_models.ShariahProductTemplate(
                product_type=template_data['product_type'],
                template_name=template_data['template_name'],
                description=template_data['description'],
                required_parameters=template_data['required_parameters'],
                scoring_weights=template_data['scoring_weights'],
                compliance_thresholds=template_data['compliance_thresholds'],
                shariah_requirements=template_data['shariah_requirements'],
                prohibited_elements=template_data['prohibited_elements'],
                created_by=1,  # Default admin user
                is_active=True
            )
            
            db.session.add(template)
            created_count += 1
            print(f"  ✅ Created template: {template_data['template_name']}")
        else:
            print(f"  ⏭️ Template already exists: {template_data['template_name']}")
    
    if created_count > 0:
        db.session.commit()
        print(f"✅ Created {created_count} product templates")
    else:
        print("ℹ️ All templates already exist")

def test_scoring_engine():
    """Test the comprehensive scoring engine"""
    print("\n🧪 Testing comprehensive scoring engine...")
    
    try:
        from services.shariah_scoring_engine import ComprehensiveShariahScoringEngine, ShariahAssessmentInput
        
        # Initialize scoring engine
        scoring_engine = ComprehensiveShariahScoringEngine()
        print("✅ Scoring engine initialized")
        
        # Create test assessment input
        test_input = ShariahAssessmentInput(
            application_id="TEST001",
            customer_name="Test Halal Company",
            customer_category="corporate", 
            product_type="murabaha",
            financing_amount=500000.0,
            financing_tenor=24,
            purpose_of_financing="Equipment purchase for halal food production",
            business_description="Halal food manufacturing company with full Shariah compliance and ethical business practices"
        )
        
        # Set up comprehensive test data
        test_input.riba_assessment = {
            'has_riba': False,
            'riba_type': 'none',
            'riba_percentage': 0.0,
            'mitigation_measures': ['Interest-free structure']
        }
        
        test_input.gharar_assessment = {
            'gharar_level': 'low',
            'uncertainty_sources': [],
            'risk_mitigation': ['Clear contract terms', 'Asset backing']
        }
        
        test_input.maysir_assessment = {
            'has_maysir': False,
            'gambling_elements': [],
            'speculation_level': 'low'
        }
        
        test_input.prohibited_5pct_activities = {
            'conventional_banking': 0.0,
            'conventional_insurance': 0.0,
            'gambling': 0.0,
            'liquor_tobacco': 0.0,
            'pork_products': 0.0,
            'non_halal_food': 0.0,
            'interest_income': 0.0,
            'adult_entertainment': 0.0
        }
        
        test_input.prohibited_20pct_activities = {
            'share_trading': 0.0,
            'stockbroking': 0.0,
            'cinema_entertainment': 0.0,
            'rental_non_compliant': 0.0,
            'music_industry': 0.0
        }
        
        test_input.governance_assessment = {
            'shariah_board_established': True,
            'shariah_board_members': 3,
            'internal_shariah_audit': True,
            'shariah_compliance_officer': True,
            'fatwa_compliance': 'full',
            'documentation_quality': 'excellent',
            'compliance_monitoring': True,
            'dispute_resolution': True
        }
        
        test_input.operational_controls = {
            'staff_training': True,
            'system_controls': True,
            'process_segregation': True,
            'error_rectification': True,
            'compliance_reporting': True
        }
        
        test_input.market_factors = {
            'market_volatility': 'low',
            'regulatory_environment': 'stable',
            'competitive_pressure': 'medium'
        }
        
        # Perform assessment
        results = scoring_engine.perform_comprehensive_assessment(test_input)
        
        # Display results
        print("\n📊 Test Assessment Results:")
        print(f"  Application ID: {results['application_id']}")
        print(f"  Composite Score: {results['weighted_composite_score']}%")
        print(f"  Compliance Level: {results['compliance_level']}")
        print(f"  Risk Level: {results['risk_level']}")
        print(f"  Final Recommendation: {results['final_recommendation']}")
        
        print("\n📈 Dimension Scores:")
        for dimension, score in results['dimension_scores'].items():
            print(f"  {dimension.replace('_', ' ').title()}: {score:.1f}%")
        
        print("\n💡 NLP Analysis:")
        nlp = results['nlp_analysis']
        print(f"  Confidence Score: {nlp['confidence_score']}%")
        print(f"  Compliant Keywords: {nlp['compliant_keywords']}")
        print(f"  Non-compliant Keywords: {nlp['non_compliant_keywords']}")
        
        if results['detailed_recommendations']:
            print("\n📋 Recommendations:")
            for rec in results['detailed_recommendations'][:3]:  # Show first 3
                print(f"  • {rec}")
        
        print("✅ Scoring engine test completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing scoring engine: {e}")
        import traceback
        traceback.print_exc()

def create_directory_structure():
    """Create necessary directory structure"""
    print("\n📁 Creating directory structure...")
    
    directories = [
        'models',
        'services', 
        'routes',
        'templates/shariah',
        'scripts'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"  ✅ Created directory: {directory}")
    
    print("✅ Directory structure created")

def check_requirements():
    """Check if all required dependencies are available"""
    print("\n🔍 Checking requirements...")
    
    required_modules = [
        'flask',
        'flask_sqlalchemy', 
        'datetime',
        'enum',
        'json',
        'typing'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError:
            missing_modules.append(module)
            print(f"  ❌ {module} - MISSING")
    
    if missing_modules:
        print(f"\n⚠️ Missing modules: {', '.join(missing_modules)}")
        print("Please install missing modules with:")
        print(f"pip install {' '.join(missing_modules)}")
        return False
    else:
        print("✅ All required modules available")
        return True

if __name__ == "__main__":
    print("Starting enhanced Shariah system initialization...\n")
    
    # Check requirements
    if not check_requirements():
        print("❌ Please install missing requirements before proceeding")
        sys.exit(1)
    
    # Create directory structure
    create_directory_structure()
    
    # Run main initialization
    success = main()
    
    if success:
        print(f"\n{'='*60}")
        print("🎉 INITIALIZATION COMPLETED SUCCESSFULLY!")
        print("🚀 Your enhanced Shariah risk assessment system is ready!")
        print(f"{'='*60}")
        sys.exit(0)
    else:
        print(f"\n{'='*60}")
        print("❌ INITIALIZATION FAILED")
        print("Please check the error messages above and try again")
        print(f"{'='*60}")
        sys.exit(1)