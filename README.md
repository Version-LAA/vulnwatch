

<p align="center">
  <img width="800" height="400" alt="vulnwatch_logo_mint_background" src="https://github.com/user-attachments/assets/8e0d959a-e60f-47ca-8556-54a01f25982d" />
</p>

> Real-time critical vulnerability intelligence, automated daily from NVD and CVE.org.

## What It Does

VulnWatch is a personal vulnerability monitoring dashboard that automatically
ingests, normalizes, and displays critical CVEs daily.

## Tech Stack I Used

- **Backend:** Django 6.0.5, Python 3.13
- **Database:** PostgreSQL
- **Automation:** AWS Lambda + EventBridge
- **Data Sources:** NVD API, CVE.org feed
- **Frontend:** Tailwind CSS v4, DaisyUI
- **Package Management:** uv

## Architecture

1. **AWS EventBridge** service handles the daily cron/scheduling that triggers the AWS Lambda service)

2. **AWS Lambda** handles the automation of backend services.

3. **CVE.org + NVD API** are both fetched via backend services multiple times daily.
      
4. **PostgreSQL** is used to store vulnerability data obtained.
     
5. **Django** is the web framework used to host a read-only dashboard.

## Features
- Daily automated CVE ingestion via AWS Lambda and EventBridge
- NVD API integration with CVSS score parsing
- CVE.org delta file processing
- Dashboard with critical vulnerability stats of cve's that currently have a cvss score.
- Paginated vulnerability table

<img width="800" height="400" alt="Screenshot 2026-06-08 at 8 08 15 PM" src="https://github.com/user-attachments/assets/cacb718c-ba24-4fef-a394-d603076c47f9" />


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
