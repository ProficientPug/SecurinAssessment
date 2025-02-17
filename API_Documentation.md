# CVE Information API Documentation

## Overview

This API provides access to a database of Common Vulnerabilities and Exposures (CVEs). It allows users to search CVE records, filter them based on different criteria, and retrieve details about individual CVEs.

## Base URL

```
http://localhost:8000
```

## Endpoints

### 1. Home Page - List CVEs

```
GET /
```

#### Description

Fetches a paginated list of CVE records. Allows filtering based on CVE ID, year, last modified date, and CVSS score.

#### Query Parameters

| Parameter##    | Type   | Description                                                              |
| -------------- | ------ | ------------------------------------------------------------------------ |
| `page`         | int    | (Optional) Page number for pagination (default: 1)                       |
| `search_type`  | string | (Optional) Filter type (`cve_id`, `year`, `last_modified`, `cvss_score`) |
| `search_value` | string | (Optional) Value for the filter                                          |

#### Response

Returns an HTML page displaying a table of CVE records.

---

### 2. Get CVE Details

```
GET /{cve_id}
```

#### Description

Fetches details of a specific CVE.

#### Path Parameters

| Parameter | Type   | Description                                              |
| --------- | ------ | -------------------------------------------------------- |
| `cve_id`  | string | The unique identifier of the CVE (e.g., `CVE-2023-1234`) |

#### Response

Returns an HTML page displaying detailed information about the requested CVE, including:

- CVE ID
- Description
- Published Date
- Last Modified Date
- Status
- CVSS Scores (if available)
- Other relevant metadata

---

## Search Filters

The `search_type` parameter allows filtering results by different criteria:

| Search Type     | Expected `search_value`                                  |
| --------------- | -------------------------------------------------------- |
| `cve_id`        | A partial or full CVE identifier (e.g., `CVE-2023-1234`) |
| `year`          | A four-digit year (e.g., `2023`)                         |
| `last_modified` | A number of days (e.g., `30` for last 30 days)           |
| `cvss_score`    | A numeric value or range (e.g., `7.5` or `>5.0`)         |

---

## Database Structure

### 1. `CVE_Entries` Table

| Column Name          | Type   | Description                        |
| -------------------- | ------ | ---------------------------------- |
| `id`                 | string | Unique CVE identifier              |
| `identifier`         | string | CVE identifier string              |
| `published_date`     | string | Date when the CVE was published    |
| `last_modified_date` | string | Date when the CVE was last updated |
| `status`             | string | Current status of the CVE          |

### 2. `CVE_Details` Table

| Column Name              | Type   | Description                          |
| ------------------------ | ------ | ------------------------------------ |
| `id`                     | string | CVE ID (Foreign Key)                 |
| `description`            | string | Detailed description of the CVE      |
| `access_vector`          | string | Attack vector (e.g., Network, Local) |
| `access_complexity`      | string | Complexity required to exploit       |
| `authentication`         | string | Authentication requirements          |
| `confidentiality_impact` | string | Impact on confidentiality            |
| `integrity_impact`       | string | Impact on integrity                  |
| `availability_impact`    | string | Impact on availability               |
| `exploitability_score`   | float  | Score indicating exploitability      |
| `impact_score`           | float  | Score indicating overall impact      |
| `criteria`               | string | Matching criteria for vulnerability  |
| `match_criteria_id`      | string | Match criteria ID                    |
| `vulnerability`          | string | Vulnerability description            |

---

## Example Requests

### Fetch CVEs from 2023 (JSON Response Example)

```
GET http://localhost:8000/?search_type=year&search_value=2023
```

### Fetch CVE Details

```
GET http://localhost:8000/CVE-2023-1234
```

---

## Notes

- The API returns HTML pages instead of JSON.
- Pagination is set to 50 results per page.
- Searching by CVSS score includes both v2 and v3 scores.
- The database must be properly initialized before running the FastAPI server.

For further enhancements, consider adding a JSON API response format and implementing authentication for secure access.

