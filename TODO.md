# TODO List for Error Resolution

## Completed Tasks
- [x] Fixed SQL Server driver name from '{pyodbc}' to '{ODBC Driver 17 for SQL Server}'
- [x] Corrected connection string to use variables instead of hardcoded values
- [x] Fixed password format in connection string (removed braces)
- [x] Fixed typo in main block: `if _name_ == '_main_':` to `if __name__ == '__main__':`
- [x] Replaced query placeholders with actual table/column names ('vulnerabilities' table, 'id' column)
- [x] Created requirements.txt with necessary Python dependencies (pyodbc, flask, flask-cors, requests)

## Remaining Tasks
- [ ] Test the database connection by running db.py
- [ ] Verify chatbot.py integration if needed
- [ ] Ensure all dependencies are installed via pip install -r requirements.txt

## Notes
- Database connection details are hardcoded; consider using environment variables for production
- Assumed table name 'vulnerabilities' and column 'id'; adjust if different
- ODBC Driver 17 for SQL Server must be installed on the system