import sqlite3
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

def add_columns():
    """Adds cvss_v2_score and cvss_v3_score columns to CVE_Details if they don’t exist."""
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()

    # Check existing columns
    cursor.execute("PRAGMA table_info(CVE_Details)")
    existing_columns = [row[1] for row in cursor.fetchall()]

    if "cvss_v2_score" not in existing_columns:
        cursor.execute("ALTER TABLE CVE_Details ADD COLUMN cvss_v2_score REAL DEFAULT 0")

    if "cvss_v3_score" not in existing_columns:
        cursor.execute("ALTER TABLE CVE_Details ADD COLUMN cvss_v3_score REAL DEFAULT 0")

    conn.commit()
    conn.close()

def fetch_all_data():
    """Fetches all CVE data from the NVD API and returns a list of vulnerabilities."""
    vulnerabilities = []
    start_index = 262000

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

def update_cve_details(vulnerabilities):
    """Updates CVSS scores in the CVE_Details table."""
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()

    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract CVSS V2 score
        cvss_v2_score = (
            cve.get("metrics", {})
            .get("cvssMetricV2", [{}])[0]
            .get("cvssData", {})
            .get("baseScore", 0)
        )

        # Extract CVSS V3 score
        cvss_v3_score = (
            cve.get("metrics", {})
            .get("cvssMetricV31", [{}])[0]
            .get("cvssData", {})
            .get("baseScore", 0)
        )

        # Update or insert into CVE_Details
        cursor.execute("""
            UPDATE CVE_Details
            SET cvss_v2_score = ?, cvss_v3_score = ?
            WHERE id = ?
        """, (cvss_v2_score, cvss_v3_score, cve_id))

    conn.commit()
    conn.close()

def main():
    add_columns()  # Ensure the new columns exist
    vulnerabilities = fetch_all_data()
    update_cve_details(vulnerabilities)
    print("CVSS scores updated successfully!")

if __name__ == "__main__":
    main()
