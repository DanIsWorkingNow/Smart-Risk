from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps 
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from credit_risk import calculate_credit_risk
from sqlalchemy import func
from collections import Counter
from flask import request, jsonify
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import Response
from io import BytesIO



import pandas as pd
import torch

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'  # for flash messages

db = SQLAlchemy(app)

# Load the custom FinBERT model and tokenizer globally
tokenizer = AutoTokenizer.from_pretrained("KaidoKirito/shariahfin")
model = AutoModelForSequenceClassification.from_pretrained("KaidoKirito/shariahfin")


# 1) Create a User model for login credentials
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # For production, store hashed passwords instead of plain text.

    def __repr__(self):
        return f'<User {self.staff_id}>'


# Database model for a loan
class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    customer_name = db.Column(db.String(100), nullable=False)
    amount_requested = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.String(50), nullable=True)  # e.g., "Low Risk", "High Risk"
    remarks = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<Loan {self.id} - {self.customer_name}>'
    
#Database model for scoring credit
class CreditApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(100), nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    property_value = db.Column(db.Float, nullable=False)
    monthly_debt = db.Column(db.Float, nullable=False)
    monthly_income = db.Column(db.Float, nullable=False)
    recovery_rate = db.Column(db.Float, nullable=False)
    probability_of_default = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)

class ShariahRiskApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(100), nullable=False)
    application_date = db.Column(db.Date, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_category = db.Column(db.String(50), nullable=False)  # Corporate / Personal
    loan_amount = db.Column(db.Float, nullable=False)
    purpose_of_financing = db.Column(db.String(200), nullable=False)
    riba = db.Column(db.String(10), nullable=False)   # Yes / No
    gharar = db.Column(db.String(10), nullable=False) # Yes / No
    maysir = db.Column(db.String(10), nullable=False) # Present / Absent
    business_description = db.Column(db.Text, nullable=False)
    shariah_risk_score = db.Column(db.String(50), nullable=False)  # Halal, Haram, Doubtful, etc.

    def __repr__(self):
        return f'<ShariahRiskApplication {self.application_id} - {self.customer_name}>'


    
    # 3) Optional: A decorator to require login on certain routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 4) Add a Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        staff_id = request.form['staff_id']
        password = request.form['password']

        user = User.query.filter_by(staff_id=staff_id).first()
        if user and user.password == password:
            # If storing hashed passwords, use check_password_hash(user.password, password)
            session['user_id'] = user.id
            session['staff_id'] = user.staff_id
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')  # We'll create this template

# 5) Add a Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('staff_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Home: list all loans
@app.route('/')
@login_required
def index():
    loans = Loan.query.order_by(Loan.application_date.desc()).all()
    return render_template('index.html', loans=loans)

# Create a new loan record
@app.route('/loan/create', methods=['GET', 'POST'])
@login_required
def create_loan():
    if request.method == 'POST':
        customer_name = request.form['customer_name']
        amount_requested = request.form['amount_requested']
        risk_score = request.form.get('risk_score', '')
        remarks = request.form.get('remarks', '')

        # You could add your risk assessment logic here (example below)
        try:
            amount = float(amount_requested)
            # Simple risk logic: if amount > 50000, mark as "High Risk", else "Low Risk"
            if amount > 50000:
                risk_score = "High Risk"
            else:
                risk_score = "Low Risk"
        except ValueError:
            flash("Invalid amount entered!", "danger")
            return redirect(url_for('create_loan'))

        new_loan = Loan(
            customer_name=customer_name,
            amount_requested=amount,
            risk_score=risk_score,
            remarks=remarks
        )
        db.session.add(new_loan)
        db.session.commit()
        flash("Loan record created successfully!", "success")
        return redirect(url_for('index'))
    return render_template('create.html')

# Edit an existing loan record
@app.route('/loan/edit/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def edit_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    if request.method == 'POST':
        loan.customer_name = request.form['customer_name']
        loan.amount_requested = float(request.form['amount_requested'])
        loan.remarks = request.form.get('remarks', '')
        # Optionally update risk score; you can recalculate based on your logic
        if loan.amount_requested > 50000:
            loan.risk_score = "High Risk"
        else:
            loan.risk_score = "Low Risk"
        db.session.commit()
        flash("Loan record updated successfully!", "success")
        return redirect(url_for('index'))
    return render_template('edit.html', loan=loan)

# Route for Shariah Risk Assessment
@app.route('/shariah-risk-assessment', methods=['GET', 'POST'])
@login_required
def shariah_risk_assessment():
    risk_score = None
    if request.method == 'POST':
        action = request.form.get('action')

        application_id = request.form['application_id']
        application_date = request.form['application_date']
        customer_name = request.form['customer_name']
        amount_requested = float(request.form['amount_requested'])
        purpose_of_financing = request.form['purpose_of_financing']
        customer_category = request.form['customer_category']
        riba = request.form['riba']
        gharar = request.form['gharar']
        maysir = request.form['maysir']
        business_description = request.form['business_description']

        # Predict Shariah Risk using model
        inputs = tokenizer(business_description, return_tensors="pt", truncation=True, padding=True)
        with torch.no_grad():
            outputs = model(**inputs)
        predicted_class_id = torch.argmax(outputs.logits, dim=-1).item()
        risk_score = model.config.id2label[predicted_class_id]

        if action == 'save':
            # Save to DB
            new_shariah_risk = ShariahRiskApplication(
                application_id=application_id,
                application_date=datetime.strptime(application_date, '%Y-%m-%d'),
                customer_name=customer_name,
                customer_category=customer_category,
                loan_amount=amount_requested,
                purpose_of_financing=purpose_of_financing,
                riba=riba,
                gharar=gharar,
                maysir=maysir,
                business_description=business_description,
                shariah_risk_score=risk_score
            )
            db.session.add(new_shariah_risk)
            db.session.commit()
            flash(f'Shariah Risk Application saved: {risk_score}', 'success')
            return redirect(url_for('shariah_risk_applications'))

    return render_template('shariah.html', risk_score=risk_score)



# -------------------------
# NEW: Route for testing the model functionality
# -------------------------
@app.route('/test-shariah-model', methods=['GET', 'POST'])
@login_required
def test_shariah_model():
    risk_score = None
    if request.method == 'POST':
        # Get the business description input from the form
        business_description = request.form['business_description']
        
        # Tokenize and run inference using your custom model
        inputs = tokenizer(business_description, return_tensors="pt", truncation=True, padding=True)
        
        # Perform inference
        with torch.no_grad():
            outputs = model(**inputs)
        
        # Get the predicted class id and map it to the label using the model configuration
        predicted_class_id = torch.argmax(outputs.logits, dim=-1).item()
        risk_score = model.config.id2label[predicted_class_id]  # Map to human-readable label
        
        flash(f'Model prediction: {risk_score}', 'success')
    return render_template('testmodel.html', risk_score=risk_score)



# Delete a loan record
@app.route('/loan/delete/<int:loan_id>', methods=['POST'])
@login_required
def delete_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    db.session.delete(loan)
    db.session.commit()
    flash("Loan record deleted successfully!", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)




#Credit risk logic
@app.route('/credit-risk', methods=['GET', 'POST'])
@login_required
def credit_risk_page():
    results = None
    risk_level = None
    risk_score = None

    if request.method == 'POST':
        action = request.form.get('action')  # 'analyze' or 'save'

        # Get form values
        application_id = request.form['application_id']
        loan_amount = float(request.form['loan_amount'])
        property_value = float(request.form['property_value'])
        monthly_debt = float(request.form['monthly_debt'])
        monthly_income = float(request.form['monthly_income'])
        recovery_rate = float(request.form['recovery_rate']) / 100
        probability_of_default = float(request.form['probability_of_default']) / 100

        # Perform credit risk calculations
        results = calculate_credit_risk(
            loan_amount, property_value, monthly_debt,
            monthly_income, recovery_rate, probability_of_default * 100
        )

        ltv = results['Loan-to-Value (LTV %)']
        dti = results['Debt-to-Income (DTI %)']
        pd = probability_of_default * 100

        risk_score = (ltv * 0.4) + (dti * 0.3) + (pd * 0.3)

        if risk_score < 30:
            risk_level = 'Low'
        elif 30 <= risk_score < 60:
            risk_level = 'Medium'
        else:
            risk_level = 'High'

        # If action is 'save', then save into database
        if action == 'save':
            new_application = CreditApplication(
                application_id=application_id,
                loan_amount=loan_amount,
                property_value=property_value,
                monthly_debt=monthly_debt,
                monthly_income=monthly_income,
                recovery_rate=recovery_rate * 100,
                probability_of_default=probability_of_default * 100,
                risk_score=risk_score,
                risk_level=risk_level
            )
            db.session.add(new_application)
            db.session.commit()
            flash('Credit application saved successfully!', 'success')
            return redirect(url_for('credit_applications'))  # redirect to saved page

    return render_template('credit_risks.html', results=results, risk_level=risk_level, risk_score=risk_score)




@app.route('/credit-applications', methods=['GET'])
@login_required
def credit_applications():
    risk_filter = request.args.get('risk_level')
    if risk_filter:
        applications = CreditApplication.query.filter_by(risk_level=risk_filter).order_by(CreditApplication.id.desc()).all()
    else:
        applications = CreditApplication.query.order_by(CreditApplication.id.desc()).all()
    return render_template('credit_applications.html', applications=applications)


@app.route('/credit-application/delete-selected', methods=['POST'])
@login_required
def delete_selected_credit_applications():
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        for app_id in selected_ids:
            application = CreditApplication.query.get(app_id)
            if application:
                db.session.delete(application)
        db.session.commit()
        flash(f'Successfully deleted {len(selected_ids)} application(s).', 'success')
    else:
        flash('No applications selected.', 'warning')
    return redirect(url_for('credit_applications'))


@app.route('/shariah-applications', methods=['GET'])
@login_required
def shariah_risk_applications():
    risk_filter = request.args.get('risk_score')
    # Define the mapping of numeric scores to human-readable labels
    risk_score_mapping = {
        0: "Halal",
        1: "Haram",
        2: "Doubtful"
    }

    if risk_filter:
        # Reverse map the human-readable filter to numeric values
        numeric_filter = {v: k for k, v in risk_score_mapping.items()}.get(risk_filter)
        applications = ShariahRiskApplication.query.filter_by(shariah_risk_score=numeric_filter).order_by(ShariahRiskApplication.id.desc()).all()
    else:
        applications = ShariahRiskApplication.query.order_by(ShariahRiskApplication.id.desc()).all()

    # Map numeric scores to human-readable labels for rendering
    for app in applications:
        app.shariah_risk_score = risk_score_mapping.get(int(app.shariah_risk_score), "Unknown")

    return render_template('shariah_applications.html', applications=applications)

@app.route('/shariah-application/delete-selected', methods=['POST'])
@login_required
def delete_selected_shariah_applications():
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        for app_id in selected_ids:
            application = ShariahRiskApplication.query.get(app_id)
            if application:
                db.session.delete(application)
        db.session.commit()
        flash(f'Successfully deleted {len(selected_ids)} Shariah application(s).', 'success')
    else:
        flash('No applications selected.', 'warning')
    return redirect(url_for('shariah_risk_applications'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # <-- Add this line
    app.run(debug=True)

@app.route('/shariah-dashboard')
@login_required
def shariah_dashboard():
    # Total count
    total_count = ShariahRiskApplication.query.count()

    # Count by risk_score
    halal_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Halal').count()
    haram_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Haram').count()
    doubtful_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Doubtful').count()

    # Top 5 purposes of financing
    purpose_data = db.session.query(
        ShariahRiskApplication.purpose_of_financing,
        func.count(ShariahRiskApplication.purpose_of_financing).label('count')
    ).group_by(
        ShariahRiskApplication.purpose_of_financing
    ).order_by(
        func.count(ShariahRiskApplication.purpose_of_financing).desc()
    ).limit(5).all()

    top_purposes = [{"purpose": row[0], "count": row[1]} for row in purpose_data]

    return render_template(
        'dboard.html',
        total_count=total_count,
        halal_count=halal_count,
        haram_count=haram_count,
        doubtful_count=doubtful_count,
        top_purposes=top_purposes
    )


@app.route('/credit-dashboard')
@login_required
def credit_dashboard():
    total_count = CreditApplication.query.count()

    # Risk level counts
    low_count = CreditApplication.query.filter_by(risk_level='Low').count()
    medium_count = CreditApplication.query.filter_by(risk_level='Medium').count()
    high_count = CreditApplication.query.filter_by(risk_level='High').count()

    # Group by loan amount ranges
    applications = CreditApplication.query.with_entities(CreditApplication.loan_amount).all()
    ranges = {'<100k': 0, '100k-500k': 0, '500k-1M': 0, '>1M': 0}
    for (amount,) in applications:
        if amount < 100000:
            ranges['<100k'] += 1
        elif amount < 500000:
            ranges['100k-500k'] += 1
        elif amount < 1000000:
            ranges['500k-1M'] += 1
        else:
            ranges['>1M'] += 1

    top_ranges = [{'range': k, 'count': v} for k, v in ranges.items() if v > 0]

    return render_template(
        'dboardcr.html',
        total_count=total_count,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
        top_ranges=top_ranges
    )

@app.route('/upload-credit-file', methods=['POST'])
def upload_credit_file():
    file = request.files['file']
    if file:
        try:
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            elif file.filename.endswith(('.xls', '.xlsx')):
                df = pd.read_excel(file)
            else:
                return jsonify({'error': 'Unsupported file format'}), 400

            if df.empty:
                return jsonify({'error': 'File is empty'}), 400

            # Assume columns match the input field names
            first_row = df.iloc[0].to_dict()
            return jsonify(first_row)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'No file uploaded'}), 400


@app.route('/upload-batch-credit', methods=['POST'])
@login_required
def upload_batch_credit():
    file = request.files.get('file')
    if not file:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('credit_risk_page'))

    try:
        import pandas as pd

        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file)
        else:
            flash('Unsupported file format.', 'danger')
            return redirect(url_for('credit_risk_page'))

        applications = []
        errors = 0

        for _, row in df.iterrows():
            try:
                # Extract necessary fields
                monthly_debt = row['monthly_debt']
                monthly_income = row['monthly_income']
                loan_amount = row['loan_amount']
                property_value = row['property_value']
                probability_of_default = row['probability_of_default']

                # Calculate risk score
                dti = monthly_debt / monthly_income
                ltv = loan_amount / property_value
                pd_normalized = probability_of_default / 100

                risk_score = (0.4 * dti + 0.3 * ltv + 0.3 * pd_normalized) * 100

                # Determine risk level
                if risk_score < 40:
                    risk_level = 'Low'
                elif risk_score < 70:
                    risk_level = 'Medium'
                else:
                    risk_level = 'High'

                app = CreditApplication(
                    application_id=row['application_id'],
                    loan_amount=loan_amount,
                    property_value=property_value,
                    monthly_debt=monthly_debt,
                    monthly_income=monthly_income,
                    recovery_rate=row['recovery_rate'],
                    probability_of_default=probability_of_default,
                    risk_score=risk_score,
                    risk_level=risk_level
                )
                applications.append(app)
            except Exception as e:
                errors += 1
                continue

        db.session.bulk_save_objects(applications)
        db.session.commit()

        flash(f'{len(applications)} applications saved successfully. {errors} failed.', 'success')
    except Exception as e:
        flash(f'Error processing file: {str(e)}', 'danger')

    return redirect(url_for('credit_risk_page'))


@app.route('/preview-credit-file', methods=['POST'])
@login_required
def preview_credit_file():
    file = request.files['file']
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    try:
        import pandas as pd

        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file)
        else:
            return jsonify({'error': 'Unsupported file format'}), 400

        preview_data = []
        for _, row in df.iterrows():
            # Define the calculate_risk function logic
            def calculate_risk(row):
                monthly_debt = row['monthly_debt']
                monthly_income = row['monthly_income']
                loan_amount = row['loan_amount']
                property_value = row['property_value']
                probability_of_default = row['probability_of_default']

                # Calculate risk score
                dti = monthly_debt / monthly_income
                ltv = loan_amount / property_value
                pd_normalized = probability_of_default / 100

                risk_score = (0.4 * dti + 0.3 * ltv + 0.3 * pd_normalized) * 100

                # Determine risk level
                if risk_score < 40:
                    risk_level = 'Low'
                elif risk_score < 70:
                    risk_level = 'Medium'
                else:
                    risk_level = 'High'

                return risk_score, risk_level

            risk_score, risk_level = calculate_risk(row)
            preview_data.append({
                'application_id': row['application_id'],
                'loan_amount': row['loan_amount'],
                'property_value': row['property_value'],
                'monthly_debt': row['monthly_debt'],
                'monthly_income': row['monthly_income'],
                'recovery_rate': row['recovery_rate'],
                'probability_of_default': row['probability_of_default'],
                'risk_score': risk_score,
                'risk_level': risk_level
            })

        return jsonify(preview_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate-pdf-report', methods=['POST'])
@login_required
def generate_pdf_report():
    data = request.get_json()

    # Ensure there is data
    if not data.get('applications'):
        return "No applications data found", 400

    # Create a BytesIO buffer to hold the PDF content in memory
    buffer = BytesIO()

    # Create the PDF using the buffer
    c = canvas.Canvas(buffer, pagesize=letter)

    # Add content to the PDF
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "Credit Application Report")

    y_position = 730
    for application in data['applications']:
        c.drawString(100, y_position, f"Application ID: {application['application_id']}")
        c.drawString(100, y_position - 15, f"Loan Amount: {application['loan_amount']}")
        c.drawString(100, y_position - 30, f"Risk Level: {application['risk_level']}")
        y_position -= 60

        # Check for page overflow, create a new page if necessary
        if y_position < 100:
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = 750

    # Save the PDF to the buffer
    c.save()

    # Get the PDF data from the buffer
    pdf_data = buffer.getvalue()

    # Close the buffer
    buffer.close()

    # Create the response with the correct headers
    response = Response(pdf_data, content_type='application/pdf')
    response.headers['Content-Disposition'] = 'attachment; filename=credit_application_report.pdf'

    # Return the response containing the PDF
    return response