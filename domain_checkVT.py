import requests
import time
import pandas as pd

# Setting API key
API_KEY = 'YOUR_VT_API'
API_URL = 'https://www.virustotal.com/api/v3/domains/'

# Setting Req
USE_FREE_API = True
DELAY_SECONDS = 16 if USE_FREE_API else 1
REQUEST_TIMEOUT = 60  # setting timeout

# Read domain on file
try:
    with open('input.txt', 'r') as file:
        domains = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print("❌ File input.txt not found.")
    exit(1)

headers = {
    'x-apikey': API_KEY
}

print(f"Total domain will be check: {len(domains)}")
print(f"Mode API: {'FREE' if USE_FREE_API else 'PREMIUM'} (Delay {DELAY_SECONDS} second per request)\n")

results = []

for idx, domain in enumerate(domains, start=1):
    print(f'🔍 [{idx}/{len(domains)}] Checking domain: {domain}')
    try:
        response = requests.get(API_URL + domain, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            country = attributes.get('country', 'None')

            malicious_count = last_analysis_stats.get('malicious', 0)
            harmless_count = last_analysis_stats.get('harmless', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            timeout_count = last_analysis_stats.get('timeout', 0)

            total_engines = harmless_count + malicious_count + suspicious_count + undetected_count + timeout_count
            reputation_score = f"{malicious_count}/{total_engines}"

            results.append({
                'Domain': domain,
                'Country': country,
                'Last Analysis Results Count': malicious_count,
                'Malicious Count': malicious_count,
                'Total Engines': total_engines,
                'Reputation Score': reputation_score
            })

            print(f"  ➔ Reputation Score for {domain}: {reputation_score}")

        elif response.status_code == 429:
            print(f"❌ Rate limit exceeded when checking {domain}. Stop process and export the result...")
            break  # done if get 429

        else:
            try:
                error_info = response.json().get('error', {})
                error_code = error_info.get('code', 'UnknownError')
                error_message = error_info.get('message', 'No error message provided')
                print(f"❌ Error when checking {domain}: {error_code} - {error_message}")
            except Exception:
                print(f"❌ Failed get data for {domain}. Status code: {response.status_code}")

            results.append({
                'Domain': domain,
                'Country': 'Error',
                'Last Analysis Results Count': 'Error',
                'Malicious Count': 'Error',
                'Total Engines': 'Error',
                'Reputation Score': 'Error'
            })

    except requests.exceptions.Timeout:
        print(f"⏰ Timeout when checking {domain} (> {REQUEST_TIMEOUT} second), go to next domain...")
        results.append({
            'Domain': domain,
            'Country': 'Timeout',
            'Last Analysis Results Count': 'Timeout',
            'Malicious Count': 'Timeout',
            'Total Engines': 'Timeout',
            'Reputation Score': 'Timeout'
        })

    except Exception as e:
        print(f"⚠️ Error when checking {domain}: {e}")
        results.append({
            'Domain': domain,
            'Country': 'Error',
            'Last Analysis Results Count': 'Error',
            'Malicious Count': 'Error',
            'Total Engines': 'Error',
            'Reputation Score': 'Error'
        })

    if idx != len(domains):
        time.sleep(DELAY_SECONDS)

# After done / break, export to Excel
df = pd.DataFrame(results)
output_file = 'checker_result.xlsx'
df.to_excel(output_file, index=False)

print(f"\n✅ Checking done! Result in: {output_file}")

