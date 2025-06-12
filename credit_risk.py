# credit_risk.py

def calculate_credit_risk(loan_amount, property_value, monthly_debt, monthly_income, recovery_rate, probability_of_default):
    # Calculate Loan-to-Value (LTV) Ratio
    ltv = (loan_amount / property_value) * 100 if property_value else 0

    # Calculate Debt-to-Income (DTI) Ratio
    dti = (monthly_debt / monthly_income) * 100 if monthly_income else 0

    # Exposure at Default (EAD) is just the loan amount
    ead = loan_amount

    # Calculate Loss Given Default (LGD)
    lgd = (1 - recovery_rate) * 100

    # Calculate Expected Loss (EL)
    expected_loss = (probability_of_default / 100) * (lgd / 100) * ead

    return {
        'Loan-to-Value (LTV %)': round(ltv, 2),
        'Debt-to-Income (DTI %)': round(dti, 2),
        'Exposure at Default (EAD RM)': round(ead, 2),
        'Loss Given Default (LGD %)': round(lgd, 2),
        'Expected Loss (RM)': round(expected_loss, 2)
    }
