import requests
import matplotlib.pyplot as plt
from datetime import datetime

# Define the NVD API base URL and your product name
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0?cpeMatchString=cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
PRODUCT_NAME = "microsoft"

# Function to fetch and parse NVD data for a specific version
def fetch_nvd_data(version):
    url = f"{NVD_BASE_URL}&version={version}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        cves = []
        for cve_entry in data["result"]["CVE_Items"]:
            products = cve_entry["configurations"]["nodes"][0]["children"][0]["cpe_match"]
            for product in products:
                if product["cpe23Uri"].startswith(f"cpe:2.3:o:{PRODUCT_NAME}:{version}"):
                    cves.append(cve_entry["cve"]["CVE_data_meta"]["ID"])
        return cves
    else:
        print("Failed to fetch NVD data.")
        return []

# Function to calculate shared vulnerabilities between two versions
def calculate_shared_vulnerabilities(version1, version2):
    cves_version1 = set(fetch_nvd_data(version1))
    cves_version2 = set(fetch_nvd_data(version2))
    shared_cves = cves_version1.intersection(cves_version2)
    return shared_cves

# Function to create a plot of shared vulnerabilities with time
def plot_shared_vulnerabilities_over_time(versions, shared_vulnerabilities):
    dates = [datetime.now().strftime("%Y-%m-%d")]
    num_shared = [len(shared_vulnerabilities)]

    for i in range(1, len(versions)):
        dates.append(datetime.now().strftime("%Y-%m-%d"))
        num_shared.append(len(calculate_shared_vulnerabilities(versions[i - 1], versions[i])))

    plt.plot(dates, num_shared, marker='o')
    plt.title("Shared Vulnerabilities Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of Shared Vulnerabilities")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# Define the product versions you want to analyze
product_versions = ["Windows 10", "Windows 11"]

# Calculate shared vulnerabilities and create a plot
shared_vulnerabilities = calculate_shared_vulnerabilities(product_versions[0], product_versions[1])
plot_shared_vulnerabilities_over_time(product_versions, shared_vulnerabilities)
