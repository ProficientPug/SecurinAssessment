import json
import sqlite3
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

def create_tables():
    """Creates the necessary tables in SQLite if they don't exist."""
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS CVE_Entries (
                        id TEXT PRIMARY KEY,
                        identifier TEXT,
                        published_date TEXT,
                        last_modified_date TEXT,
                        status TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS CVE_Details (
                        id TEXT PRIMARY KEY,
                        description TEXT,
                        access_vector TEXT,
                        access_complexity TEXT,
                        authentication TEXT,
                        confidentiality_impact TEXT,
                        integrity_impact TEXT,
                        availability_impact TEXT,
                        exploitability_score REAL,
                        impact_score REAL,
                        cvss_v2_score REAL,
                        cvss_v3_score REAL,
                        criteria TEXT,
                        match_criteria_id TEXT,
                        FOREIGN KEY (id) REFERENCES CVE_Entries(id)
                    )''')

    conn.commit()
    conn.close()

def fetch_all_data():
    """Fetches all CVE data from the NVD API and returns a list of vulnerabilities."""
    vulnerabilities = []
    start_index = 258000

    while True:
        print(f"Fetching records from index {start_index}...")
        response = requests.get(
            NVD_API_URL,
            params={"startIndex": start_index, "resultsPerPage": RESULTS_PER_PAGE}
        )

        if response.status_code != 200:
            print(f"Error fetching data: {response.status_code}")
            break

        data = response.json()
        page_vulnerabilities = data.get("vulnerabilities", [])

        if not page_vulnerabilities:
            break

        vulnerabilities.extend(page_vulnerabilities)
        start_index += RESULTS_PER_PAGE

    print(f"Total records fetched: {len(vulnerabilities)}")
    return vulnerabilities

def insert_data(vulnerabilities):
    """Inserts fetched CVE data into SQLite database."""
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()

    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        identifier = cve.get("sourceIdentifier", "")
        published_date = cve.get("published", "")
        last_modified_date = cve.get("lastModified", "")
        status = cve.get("vulnStatus", "")

        cursor.execute("INSERT OR IGNORE INTO CVE_Entries VALUES (?, ?, ?, ?, ?)",
                       (cve_id, identifier, published_date, last_modified_date, status))

        description = ""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang", "") == "en":
                description = desc.get("value", "")
                break

        metrics_v2 = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {})
        access_vector = metrics_v2.get("accessVector", "")
        access_complexity = metrics_v2.get("accessComplexity", "")
        authentication = metrics_v2.get("authentication", "")
        confidentiality_impact = metrics_v2.get("confidentialityImpact", "")
        integrity_impact = metrics_v2.get("integrityImpact", "")
        availability_impact = metrics_v2.get("availabilityImpact", "")
        exploitability_score = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("exploitabilityScore", 0)
        impact_score = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("impactScore", 0)
        cvss_v2_score = metrics_v2.get("baseScore", 0)
        metrics_v3 = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_v3_score = metrics_v3.get("baseScore", 0)
        cpe_data = cve.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0]
        criteria = cpe_data.get("criteria", "")
        match_criteria_id = cpe_data.get("matchCriteriaId", "")
        vulnerability = str(cpe_data.get("vulnerable", ""))

        cursor.execute("INSERT OR IGNORE INTO CVE_Details VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)",
                       (cve_id, description, access_vector, access_complexity, authentication,
                        confidentiality_impact, integrity_impact, availability_impact,
                        exploitability_score, impact_score, cvss_v2_score, cvss_v3_score,
                        criteria, match_criteria_id,vulnerability))

    conn.commit()
    conn.close()

def main():
    create_tables()  # Create the necessary tables
    vulnerabilities = fetch_all_data()  # Fetch CVE data from the API
    insert_data(vulnerabilities)  # Insert the fetched data into the database
    print("Data imported successfully!")

if __name__ == "__main__":
    main()
