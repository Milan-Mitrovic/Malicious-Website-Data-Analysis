# Malicious Website Data Analysis
This project focuses on classifying websites as malicious or benign using supervised machine learning techniques, specifically classification algorithms. The analysis leverages advanced data analytics and rigorous evaluation metrics to determine the most effective algorithm for early detection of malicious websites, ultimately enhancing cybersecurity strategies.

## Project Overview
Malicious websites pose significant threats to individuals and organizations, leading to financial losses, data breaches, and compromised security. This project aims to build predictive models capable of identifying malicious websites based on critical website attributes and network traffic data. The study involves data cleaning, exploratory data analysis (EDA), feature engineering/selection, and modeling to achieve robust and accurate predictions.

## Key Features
- Comprehensive **data cleaning and preprocessing** to ensure data integrity, including handling null values and standardizing certain categorical feature values.
- Conducted **Exploratory Data Analysis (EDA)** to uncover key patterns and trends in the data, such as the relationship between URL length, content size, and website type.
- **Feature Selection:**
  - Removed irrelevant features, such as `WHOIS_REGDATE`, and `WHOIS_UPDATED_DATE`, to improve model performance.
- **Modeling:**
  - Built and compared three machine learning models: **Decision Tree, K-Nearest Neighbors (KNN), and Random Forest.**
  - Conducted hyperparameter tuning and cross-validation for model optimization.
  - Achieved very high accuracy with the **Random Forest model** despite class imbalances.  
- **Evaluation Metrics:**
  - Accuracy, Recall (Sensitivity), Specificity, Precision (Positive Predictive Value), and Balanced Accuracy.
  - Emphasized specificity to minimize false negatives and improve malicious website detection.

## Dataset
- **Source:** `malicious_and_benign_websites1.csv`
- **Features:** 21 attributes, including URL length, number of special characters, server information, WHOIS data, and network traffic metrics.
- **Target Feature:** `Type` (0 = Benign, 1 = Malicious)

## Technologies Used
- **Programming Language:** R
- **Key Libraries:** `caret`, `ggplot2`, `RColorBrewer`
