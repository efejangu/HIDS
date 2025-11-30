from dotenv import load_dotenv
import os
import requests
import json
import datetime
import time
from HIDS.threat_detector.rate_limiter import vt_rate_limiter
import logging

load_dotenv()

class GatherThreatData:
    
    def __init__(self):
        self.__API_KEY = os.getenv("VIRUS_TOTAL")
        self.headers = {
            "accept": "application/json",
            "X-Apikey": self.__API_KEY
        }
        self.logger = logging.getLogger(__name__)
        self.max_retries = 3
        self.retry_delay = 5  # seconds between retries

    @vt_rate_limiter.rate_limited
    def gather_ipv4_info(self, ip) -> dict:
        return self._make_request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}")

    @vt_rate_limiter.rate_limited
    def gather_domain_info(self, domain: str) -> dict:
        return self._make_request(f"https://www.virustotal.com/api/v3/domains/{domain}")

    @vt_rate_limiter.rate_limited
    def gather_file_info(self, file_hash: str) -> dict:
        return self._make_request(f"https://www.virustotal.com/api/v3/files/{file_hash}")

    def _make_request(self, url: str) -> dict:
        """Centralized request method with error handling and retries."""
        for attempt in range(self.max_retries):
            try:
                response = requests.get(url, headers=self.headers, timeout=30)
                
                # Handle rate limit responses from API
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    self.logger.warning(f"API rate limit hit. Retry after {retry_after} seconds.")
                    if attempt < self.max_retries - 1:
                        time.sleep(retry_after)
                        continue
                
                response.raise_for_status()
                data = response.json()
                
                # Check for API errors in response
                if "error" in data:
                    self.logger.error(f"VirusTotal API error: {data['error']}")
                    return {"error": f"VirusTotal API error: {data['error']}"}
                
                return data if "data" in data and data["data"] is not None else {"data": None}
                
            except requests.exceptions.Timeout:
                self.logger.error(f"Request timeout for {url}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                return {"error": "Request timeout after multiple attempts"}
                
            except requests.exceptions.ConnectionError as e:
                self.logger.error(f"Connection error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                return {"error": f"Connection error: {e}"}
                
            except requests.RequestException as e:
                self.logger.error(f"Request error: {e}")
                return {"error": f"Error during request: {e}"}
        
        return {"error": "Max retries exceeded"}

     
#______________________________________IS it malicious THO?____________________________
def is_file_malicious(file_hash: str) -> bool:
    """
    Uses VirusTotal to determine if a file hash is likely malicious.
    Analyzes last_analysis_stats from multiple engines.
    """
    threat_data = GatherThreatData()
    result = threat_data.gather_file_info(file_hash)

    # Handle errors gracefully
    if "error" in result:
        logging.warning(f"Could not check file hash {file_hash}: {result['error']}")
        return False  # Default to safe if we can't check

    if "data" in result and result["data"] is not None:
        stats = result["data"]["attributes"].get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious >= 3:
            return True
        elif malicious >= 1 and suspicious >= 2:
            return True
        elif (malicious + suspicious) > harmless:
            return True
        else:
            return False
    return False


def is_domain_malicious(domain: str) -> bool:
    """
    Uses VirusTotal to determine if a domain is likely malicious.
    Analyzes last_analysis_stats and considers multiple heuristics.
    """
    threat_data = GatherThreatData()
    result = threat_data.gather_domain_info(domain)

    # Handle errors gracefully
    if "error" in result:
        logging.warning(f"Could not check domain {domain}: {result['error']}")
        return False  # Default to safe if we can't check

    if "data" in result and result["data"] is not None:
        stats = result["data"]["attributes"].get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious >= 3:
            return True
        elif malicious >= 1 and suspicious >= 2:
            return True
        elif (malicious + suspicious) > harmless:
            return True
        else:
            return False
    return False


def is_ipv4_malicious(ip: str) -> bool:
    """
    Uses VirusTotal to determine if an IP address is likely malicious.
    Analyzes last_analysis_stats with more nuanced rules.
    """
    threat_data = GatherThreatData()
    result = threat_data.gather_ipv4_info(ip)

    # Handle errors gracefully
    if "error" in result:
        logging.warning(f"Could not check IP {ip}: {result['error']}")
        return False  # Default to safe if we can't check

    if "data" in result and result["data"] is not None:
        stats = result["data"]["attributes"].get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious >= 3:
            return True
        elif malicious >= 1 and suspicious >= 2:
            return True
        elif (malicious + suspicious) > harmless:
            return True
        else:
            return False
    return False

#________________________________Displayng the data all cute and stuff__________________________________     
def display_malware_info(data: dict):
    """
    Parses VirusTotal JSON data and generates a professional malware analysis report.

    Args:
        data (dict): The JSON data from the VirusTotal API file report endpoint.
    """
    # Safely get the main attributes dictionary.

    attributes = data.get("data", {}).get("attributes", {}) 
    if not attributes:
        print("❌ Error: Could not find attribute data in the provided JSON.")
        return

    # --- 1. Executive Summary ---
    stats = attributes.get("last_analysis_stats", {})
    malicious_hits = stats.get("malicious", 0)
    total_scans = sum(stats.values()) if stats else 0
    threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A")

    print("=" * 60)
    print("        Malware Analysis Report")
    print("=" * 60)

    print("\n📋 **Executive Summary**")
    summary = f"The file '{attributes.get('meaningful_name', 'N/A')}' was analyzed, with "
    if malicious_hits > 0:
        summary += (f"a significant number of security vendors ({malicious_hits}/{total_scans}) "
                    f"flagging it as malicious. The primary classification is **{threat_label}**.")
    else:
        summary += "no security vendors flagging it as malicious. It appears to be clean."
    print(summary)

    # --- 2. File Identification ---
    print("\n🔎 **File Identification**")
    print(f"  - **File Name(s):** {', '.join(attributes.get('names', ['N/A']))}")
    # Convert bytes to MB for readability
    file_size_mb = attributes.get('size', 0) / (1024 * 1024)
    print(f"  - **File Size:** {file_size_mb:.2f} MB")
    print(f"  - **File Type:** {attributes.get('type_description', 'N/A')}")
    print(f"  - **MD5:** {attributes.get('md5', 'N/A')}")
    print(f"  - **SHA-256:** {attributes.get('sha256', 'N/A')}")

    # --- 3. Security Analysis ---
    if stats:
        print("\n🛡️ **Security Analysis**")
        print(f"  - **Detection Ratio:** {malicious_hits} / {total_scans} vendors flagged this file.")
        print(f"  - **Suggested Threat:** {threat_label if threat_label != 'N/A' else 'Not Classified'}")

        # List specific detections only if there are any
        if malicious_hits > 0:
            print("  - **Malicious Detections:**")
            analysis_results = attributes.get("last_analysis_results", {})
            for engine, result in analysis_results.items():
                if result.get("category") == "malicious":
                    print(f"    - **{engine}:** `{result.get('result')}`")
    
    # --- 4. Digital Signature Analysis ---
    signature_info = attributes.get("signature_info")
    if signature_info:
        print("\n✍️ **Digital Signature Analysis**")
        print(f"  - **Signer:** {signature_info.get('signers', 'Not Signed')}")
        verification = signature_info.get('verified', 'N/A')
        print(f"  - **Status:** {verification}")
        # Add a clear warning for untrusted certificates
        if "not trusted" in verification:
            print("  - ❗ **Warning:** The certificate is not trusted. This is a major security risk.")
        elif "Verified" in verification:
            print("  - ✅ **Info:** The certificate is trusted.")

    # --- 5. Submission History ---
    first_submission_unix = attributes.get("first_submission_date")
    last_submission_unix = attributes.get("last_submission_date")
    
    if first_submission_unix:
        first_sub_date = datetime.fromtimestamp(first_submission_unix).strftime('%Y-%m-%d %H:%M:%S UTC')
        last_sub_date = datetime.fromtimestamp(last_submission_unix).strftime('%Y-%m-%d %H:%M:%S UTC')
        print("\n🗓️ **Submission History**")
        print(f"  - **First Seen:** {first_sub_date}")
        print(f"  - **Last Seen:** {last_sub_date}")
        print(f"  - **Times Submitted:** {attributes.get('times_submitted', 'N/A')}")

    # --- 6. Recommendation ---
    print("\n➡️ **Recommendation**")
    if malicious_hits > 10:
        print("  - **Verdict:** HIGHLY MALICIOUS. Immediate deletion is recommended. Do not execute this file under any circumstances.")
    elif malicious_hits > 0:
        print("  - **Verdict:** SUSPICIOUS. Handle with extreme caution. It is advised to delete the file.")
    else:
        print("  - **Verdict:** Likely safe. No malicious indicators were found by automated tools.")

    print("=" * 60)




#_________________________________Display domain info_______________________________

def display_domain_info(data: dict):
    """
    Analyzes domain information from a VirusTotal-like data structure to determine
    if the domain is malicious. This function is designed to be robust and
    presents its findings with helpful emojis for a cooler report.

    Args:
        data (dict): A dictionary containing the domain report data.
    """
    # 1. --- Initial Input Validation ---
    if not isinstance(data, dict):
        print("Error: The provided input data is not a valid dictionary.")
        return
    
    print(data.keys())

    attributes = data.get('data').get('attributes')
    if not isinstance(attributes, dict):
        print("Error: 'attributes' key is missing or not a dictionary. Cannot analyze domain.")
        return

    domain_id = data.get('id', 'N/A')
    print(f"--- 🌐 Analysis Report for Domain: {domain_id} ---")

    analysis_stats = attributes.get('last_analysis_stats', {})
    analysis_results = attributes.get('last_analysis_results', {})

    malicious_count = analysis_stats.get('malicious', 0)
    harmless_count = analysis_stats.get('harmless', 0)
    suspicious_count = analysis_stats.get('suspicious', 0)
    undetected_count = analysis_stats.get('undetected', 0)
    timeout_count = analysis_stats.get('timeout', 0)

    total_scans = (malicious_count + harmless_count + suspicious_count +
                   undetected_count + timeout_count)

    print("\n--- ⚖️ Verdict ---")
    if total_scans > 0:
        malicious_percentage = (malicious_count / total_scans) * 100
        print(f"Malicious Detection Rate: {malicious_percentage:.2f}% ({malicious_count} out of {total_scans} vendors)")

        if malicious_percentage > 5.0:
            print("Status: 🔴 MALICIOUS")
            print("This domain is flagged as malicious by a significant number of security vendors.")
        elif malicious_percentage > 0:
            print("Status: 🟡 POTENTIALLY MALICIOUS / HIGH RISK")
            print("One or more security vendors have flagged this domain. Proceed with extreme caution.")
        else:
            print("Status: 🟢 LIKELY HARMLESS")
            print("No security vendors have flagged this domain as malicious.")
    else:
        print("Status: ❓ UNKNOWN")
        print("No security analysis data is available for this domain.")

    if malicious_count > 0 and isinstance(analysis_results, dict):
        print("\n--- 🚩 Vendors Flagging as Malicious ---")
        for vendor, result in analysis_results.items():
            if isinstance(result, dict) and result.get('category') == 'malicious':
                threat_type = result.get('result', 'N/A')
                print(f"  - {vendor}: Tagged as '{threat_type}'")

    print("\n--- 📝 Domain Registration Details ---")
    registrar = attributes.get('registrar', 'N/A')
    creation_timestamp = attributes.get('creation_date')
    expiration_timestamp = attributes.get('expiration_date')

    try:
        creation_date = datetime.datetime.fromtimestamp(creation_timestamp).strftime('%Y-%m-%d')
    except (TypeError, ValueError, OSError):
        creation_date = 'N/A'

    try:
        expiration_date = datetime.datetime.fromtimestamp(expiration_timestamp).strftime('%Y-%m-%d')
    except (TypeError, ValueError, OSError):
        expiration_date = 'N/A'

    print(f"  🏢 Registrar: {registrar}")
    print(f"  🗓️ Creation Date: {creation_date}")
    print(f"  ⏳ Expiration Date: {expiration_date}")


#______________________________display ipv4 data______________________________________________________________

def display_ipv4_info(data: dict):
    """
    Analyzes IP address information from a VirusTotal-like data structure.
    This function is robust, handles missing data, and uses emojis
    to create a cool, readable report.

    Args:
        data (dict): A dictionary containing the IP address report data.
    """
    # 1. --- Initial Input Validation ---
    if not isinstance(data, dict):
        print("Error: The provided input data is not a valid dictionary.")
        return

    attributes = data.get('data').get('attributes')
    if not isinstance(attributes, dict):
        print("Error: 'attributes' key is missing or not a dictionary. Cannot analyze IP.")
        return

    ip_address = data.get('id', 'N/A')
    print(f"--- 💻 Analysis Report for IP Address: {ip_address} ---")

    # 2. --- Security Analysis & Verdict ---
    analysis_stats = attributes.get('last_analysis_stats', {})
    analysis_results = attributes.get('last_analysis_results', {})
    reputation = attributes.get('reputation', 0) # Default to neutral reputation

    # Safely get individual counts, defaulting to 0
    malicious_count = analysis_stats.get('malicious', 0)
    harmless_count = analysis_stats.get('harmless', 0)
    suspicious_count = analysis_stats.get('suspicious', 0)
    undetected_count = analysis_stats.get('undetected', 0)
    timeout_count = analysis_stats.get('timeout', 0)

    total_scans = (malicious_count + harmless_count + suspicious_count +
                   undetected_count + timeout_count)

    print("\n--- 🛡️ Security Verdict ---")
    print(f"Reputation Score: {reputation}")

    if total_scans > 0:
        malicious_percentage = (malicious_count / total_scans) * 100
        print(f"Malicious Detection Rate: {malicious_percentage:.2f}% ({malicious_count} out of {total_scans} vendors)")

        if malicious_percentage > 5.0 or reputation < 0:
            print("Status: 🔴 MALICIOUS")
            print("This IP is flagged as malicious by security vendors or has a negative reputation.")
        elif malicious_percentage > 0:
            print("Status: 🟡 POTENTIALLY MALICIOUS / HIGH RISK")
            print("One or more security vendors have flagged this IP. Proceed with caution.")
        else:
            print("Status: 🟢 LIKELY HARMLESS")
            print("No security vendors have flagged this IP as malicious.")
    else:
        print("Status: ❓ UNKNOWN")
        print("No security analysis data is available for this IP.")

    # 3. --- Detailed Malicious Vendor Listing ---
    if malicious_count > 0 and isinstance(analysis_results, dict):
        print("\n--- 🚩 Vendors Flagging as Malicious ---")
        for vendor, result in analysis_results.items():
            if isinstance(result, dict) and result.get('category') == 'malicious':
                threat_type = result.get('result', 'N/A')
                print(f"  - {vendor}: Tagged as '{threat_type}'")

    # 4. --- Geolocation & Ownership ---
    print("\n--- 🌍 Geolocation & Network Details ---")
    owner = attributes.get('as_owner', 'N/A')
    country = attributes.get('country', 'N/A')
    continent = attributes.get('continent', 'N/A')
    registry = attributes.get('regional_internet_registry', 'N/A')

    print(f"  🏢 AS Owner: {owner}")
    print(f"  🌐 Country: {country} ({continent})")
    print(f"  📒 Registry: {registry}")

    community_context = attributes.get('crowdsourced_context')
    if isinstance(community_context, list) and community_context:
        print("\n--- 👥 Community Intelligence ---")
        for context_item in community_context:
            source = context_item.get('source', 'Unknown Source')
            title = context_item.get('title', 'No Title')
            details = context_item.get('details', 'No Details')
            print(f"  Source: {source}")
            print(f"  - Title: {title}")
            print(f"  - Details: {details}")


  #"dca26fecbe9cd681c3e630161797d9db76d32ce42fb825d1f5f9c6029df8c52a" #"178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1" Tested the code with these hashes ?

