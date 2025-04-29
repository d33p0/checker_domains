import requests
import time
import pandas as pd

# Ganti dengan API key Anda
API_KEY = '55d85efd1fa88b65627c3a00796b101c078ad8644ff319156b6ab9da68bc3761'
API_URL = 'https://www.virustotal.com/api/v3/domains/'

# Setting
USE_FREE_API = True
DELAY_SECONDS = 16 if USE_FREE_API else 1
REQUEST_TIMEOUT = 60  # Timeout request per domain dalam detik (1 menit)

# Baca domain dari file
try:
    with open('input.txt', 'r') as file:
        domains = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print("❌ File input.txt tidak ditemukan.")
    exit(1)

headers = {
    'x-apikey': API_KEY
}

print(f"Total domain yang akan dicek: {len(domains)}")
print(f"Mode API: {'FREE' if USE_FREE_API else 'PREMIUM'} (Delay {DELAY_SECONDS} detik per request)\n")

results = []

for idx, domain in enumerate(domains, start=1):
    print(f'🔍 [{idx}/{len(domains)}] Memeriksa domain: {domain}')
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

            print(f"  ➔ Reputation Score untuk {domain}: {reputation_score}")

        elif response.status_code == 429:
            print(f"❌ Rate limit exceeded saat cek {domain}. Menghentikan proses dan export hasil...")
            break  # Hentikan loop kalau dapat 429

        else:
            try:
                error_info = response.json().get('error', {})
                error_code = error_info.get('code', 'UnknownError')
                error_message = error_info.get('message', 'No error message provided')
                print(f"❌ Error saat cek {domain}: {error_code} - {error_message}")
            except Exception:
                print(f"❌ Gagal mendapatkan data untuk {domain}. Status code: {response.status_code}")

            results.append({
                'Domain': domain,
                'Country': 'Error',
                'Last Analysis Results Count': 'Error',
                'Malicious Count': 'Error',
                'Total Engines': 'Error',
                'Reputation Score': 'Error'
            })

    except requests.exceptions.Timeout:
        print(f"⏰ Timeout saat cek {domain} (> {REQUEST_TIMEOUT} detik), lanjut domain berikutnya...")
        results.append({
            'Domain': domain,
            'Country': 'Timeout',
            'Last Analysis Results Count': 'Timeout',
            'Malicious Count': 'Timeout',
            'Total Engines': 'Timeout',
            'Reputation Score': 'Timeout'
        })

    except Exception as e:
        print(f"⚠️ Error saat memeriksa {domain}: {e}")
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

# Setelah selesai / break, export ke Excel
df = pd.DataFrame(results)
output_file = 'hasil_cek_domain77.xlsx'
df.to_excel(output_file, index=False)

print(f"\n✅ Pemeriksaan selesai! Hasil disimpan di: {output_file}")

