import requests

def fetch_cve_data(start_index=0, results_per_page=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    print(f"Fetching data from: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status() 
        data = response.json()
        print("API Response Status Code:", response.status_code)
        print("Full API Response:", data)
        return data
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")
    return None
if __name__ == "__main__":
    print("Testing fetch_cve_data...")
    start_index = 0
    results_per_page = 5 #testing
    cve_data = fetch_cve_data(start_index, results_per_page)

    if cve_data:
        print("Fetched CVEs:")
        for item in cve_data.get('CVE_Items', []):
            print(f"CVE ID: {item['cve']['CVE_data_meta']['ID']}")
            print(f"Published Date: {item['published']}")
            print(f"Last Modified Date: {item['lastModified']}")
            print(f"Severity Score: {item.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'N/A')}")
            print("-" * 40)
    else:
        print("No data fetched or an error occurred.")