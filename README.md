
<p align="center">
  <img width="600" height="400" alt="cve_watchr_logo_mint_background_4000x3000" src="https://github.com/user-attachments/assets/c8d4b541-acf6-4474-8979-baa6bae51545" />
</p>

> Real-time critical vulnerability intelligence, automated daily from NVD and CVE.org.

## What It Does

CVE Watchr is a vulnerability monitoring dashboard that automatically
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


<img width="800" height="400" alt="CVE Watchr" src="https://github.com/user-attachments/assets/47293165-5f54-4138-991e-033a8ea471b3" />


## Roadmap
V2
- [x] Sort and Search by CVSS Score, Date range, and CVE
- [ ] EPSS score integration $\color{orange}\textsf{-In Progress}$
- [ ] Information pages on CVE's $\color{orange}\textsf{-In Progress}$
- [ ] KEV status tracking


## Local Development

**Prerequisites:**
- Python 3.13+
- PostgreSQL
- uv

**Setup:**
```bash
# Clone the repo
git clone https://github.com/yourusername/cvewatchr.git
cd cvewatchr

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
- DB_NAME=vulnwatch
- DB_USER=[user name you create]
- DB_PASSWORD=[db password]
- DB_HOST=localhost
- DB_PORT=5432
- DEBUG=True
- SECRET_KEY=your-secret-key-here

## Author

Built by LatoyaA (https://github.com/version-LAA)
