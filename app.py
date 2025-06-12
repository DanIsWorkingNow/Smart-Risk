from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps 
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from credit_risk import calculate_credit_risk

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
    if request.method == 'POST':
        # Capture form inputs here as before
        application_id = request.form['application_id']
        application_date = request.form['application_date']
        customer_name = request.form['customer_name']
        category = request.form['category']
        amount_requested = float(request.form['amount_requested'])
        purpose_of_financing = request.form['purpose_of_financing']
        customer_category = request.form['customer_category']
        riba = request.form['riba']
        gharar = request.form['gharar']
        maysir = request.form['maysir']
        business_description = request.form['business_description']

        # Ensure model input is correctly tokenized
        inputs = tokenizer(business_description, return_tensors="pt", truncation=True, padding=True)
        
        # Run inference to get the model prediction
        with torch.no_grad():
            outputs = model(**inputs)

        # Get the predicted class id (highest logit)
        predicted_class_id = torch.argmax(outputs.logits, dim=-1).item()
        
        # Get the human-readable label for the prediction using the model's label mapping
        risk_score = model.config.id2label[predicted_class_id]

        # Store the loan with the prediction in the database
        new_loan = Loan(
            application_date=datetime.strptime(application_date, '%Y-%m-%d'),
            customer_name=customer_name,
            amount_requested=amount_requested,
            risk_score=risk_score,  # Save the risk score as a label (e.g., 'Halal', 'Haram')
            remarks=f'Riba: {riba}, Gharar: {gharar}, Maysir: {maysir}, Purpose: {purpose_of_financing}'
        )
        db.session.add(new_loan)
        db.session.commit()

        flash(f'Loan risk assessment completed: {risk_score}', 'success')
        return redirect(url_for('index'))

    return render_template('shariah.html')

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


@app.route('/credit-applications')
@login_required  # Ensure only logged-in users can access
def credit_applications():
    applications = CreditApplication.query.order_by(CreditApplication.id.desc()).all()
    return render_template('credit_applications.html', applications=applications)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # <-- Add this line
    app.run(debug=True)
