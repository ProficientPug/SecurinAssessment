# CVE Database Web Application

This is a FastAPI web application that allows users to search and view details of Common Vulnerabilities and Exposures (CVE) entries. The application uses SQLite as the database to store CVE data.

## Features

- Search for CVE entries by ID, year, or last modified date.
- View detailed information about each CVE entry.
- Pagination support for search results.

## Requirements

- Python 3.7 or higher
- FastAPI
- SQLAlchemy
- Jinja2
- SQLite

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/ProficientPug/SecurinAssessment.git
   cd SecurinAssessment
2. **Setup a virtual environment (not required, but recommended):**

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```
3. **Install all the required packages**
   ```bash
   pip install fastapi[all] sqlalchemy uvicorn jinja2```
4. **Create an SQLite Database:**
   Make sure to create the cve_database.db file and populate it with CVE data. You can use a script or manually insert data into the database.
   
5. **Running the Application**
to run the application, use the following command.
```bash
uvicorn main:app --reload
```
**Endpoints**
Home Page: GET /

Displays a search form and lists CVE entries.
Supports filtering by CVE ID, year, and last modified date.
CVE Details Page: GET /{cve_id}

Displays detailed information about a specific CVE entry.

**Templates and Static Files**
The application uses Jinja2 for templating. The templates are located in the templates directory. Static files (like CSS, JavaScript, images) should be placed in the static directory.

**Database Models**
The application uses two main database models:

CVEEntry: Represents the basic information of a CVE entry.
CVEDetail: Contains detailed information about the CVE.
