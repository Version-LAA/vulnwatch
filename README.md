# VulnWatch 🔍

> Real-time critical vulnerability intelligence — automated daily from NVD and CVE.org.

## What It Does

VulnWatch is a personal vulnerability monitoring dashboard that automatically
ingests, normalizes, and displays critical CVEs daily.

## Tech Stack

- **Backend:** Django 6.0.5, Python 3.13
- **Database:** PostgreSQL
- **Automation:** AWS Lambda + EventBridge
- **Data Sources:** NVD API, CVE.org GitHub delta feed
- **Frontend:** Tailwind CSS v4, DaisyUI
- **Package Management:** uv

## Architecture

**AWS EventBridge** service handles handles the daily cron/scheduling that triggers the AWS Lambda service)
        ↓
**AWS Lambda** handles the automation of backend services.
        ↓
**CVE.org + NVD API** are both fetched via backend services daily.
        ↓
**PostgreSQL** is utilized to store vulnerability data obtained.
        ↓
**Django** is the webframework used to host a read only dashboard.

## Features
- Daily automated CVE ingestion via AWS Lambda
- NVD API integration with CVSS score parsing
- CVE.org delta file processing
- Dashboard with critical vulnerability stats
- Paginated vulnerability table
- Upsert logic — no duplicates on re-runs

## Roadmap
V2
- [ ] EPSS score integration
- [ ] KEV status tracking
- [ ] Filter by CVSS Score, Date range, and CVE
- [ ] Information pages on CVE's

## Local Development

**Prerequisites:**
- Python 3.13+
- PostgreSQL
- uv

**Setup:**
```bash
# Clone the repo
git clone https://github.com/yourusername/vulnwatch.git
cd vulnwatch

# Install dependencies
uv sync

# Create .env file
cp .env.example .env
# Fill in your database credentials

# Set up database
psql -U postgres -c "CREATE DATABASE vulnwatch;"
python manage.py migrate

# Pull initial data
python manage.py fetch_nvd
python manage.py fetch_cve_org

# Run the server
python manage.py runserver
```

## Environment Variables

Create a `.env` file in the project root:

## Author

Built by LatoyaA (https://github.com/version-LAA)
