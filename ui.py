import re
import ast
import argparse
import sys
from widevine import WidevineExtractor

# ألوان للترمكس لتسهيل القراءة
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def log(message, type="info"):
    if type == "info":
        print(f"{Colors.BLUE}[*] {message}{Colors.END}")
    elif type == "success":
        print(f"{Colors.GREEN}[+] {message}{Colors.END}")
    elif type == "error":
        print(f"{Colors.RED}[!] {message}{Colors.END}")
    elif type == "warning":
        print(f"{Colors.YELLOW}[!] {message}{Colors.END}")

def parse_fetch_request(fetch_text):
    """تحليل نص الـ fetch المستخرج من المتصفح لاستخراج الرابط والترويسات"""
    if not fetch_text:
        return None, None
    
    try:
        # استخراج رابط الترخيص
        license_url_match = re.search(r'fetch\s*\(\s*["\']([^"\']+)["\']', fetch_text)
        if not license_url_match:
            return None, None
        
        license_url = license_url_match.group(1)
        
        # استخراج الترويسات (Headers) باستخدام Regex متطور
        headers_match = re.search(r'["\']headers["\']\s*:\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', fetch_text, re.DOTALL)
        
        if headers_match:
            headers_str = "{" + headers_match.group(1) + "}"
            # تنظيف النص ليوافق تنسيق قاموس بايثون
            headers_str = re.sub(r'"([^"]+)"\s*:', r"'\1':", headers_str)
            headers_str = re.sub(r':\s*"([^"]*)"', r": '\1'", headers_str)
            headers_str = headers_str.replace('\n', ' ')
            headers_str = re.sub(r',\s*}', '}', headers_str)
            
            try:
                headers_dict = ast.literal_eval(headers_str)
                return license_url, headers_dict
            except:
                return license_url, None
        return license_url, None
            
    except Exception as e:
        log(f"Parsing Error: {str(e)}", "error")
        return None, None

def main():
    print(f"{Colors.BOLD}{Colors.BLUE}")
    print("="*50)
    print("      Widevine Key Extractor (Termux Edition)      ")
    print("="*50 + f"{Colors.END}\n")

    parser = argparse.ArgumentParser(description="Extract Widevine L3 Keys via Termux")
    
    # تعريف المدخلات
    parser.add_argument("-w", "--wvd", help="Path to your .wvd file")
    parser.add_argument("-p", "--pssh", help="PSSH Base64 string")
    parser.add_argument("-f", "--fetch", help="Full fetch request from browser (Optional)")
    parser.add_argument("-u", "--url", help="License URL (If not using --fetch)")

    args = parser.parse_args()

    # التحقق من المدخلات
    wvd_path = args.wvd or input(f"{Colors.YELLOW}Enter WVD file path: {Colors.END}")
    pssh_b64 = args.pssh or input(f"{Colors.YELLOW}Enter PSSH string: {Colors.END}")
    
    license_url = args.url
    headers_dict = {}

    # إذا قام المستخدم بإدخال نص الـ fetch
    if args.fetch:
        log("Parsing fetch request...")
        license_url, headers_dict = parse_fetch_request(args.fetch)
    
    # إذا لم يوجد رابط أو ترويسات، نطلبها يدوياً
    if not license_url:
        license_url = input(f"{Colors.YELLOW}Enter License URL: {Colors.END}")
    
    if not headers_dict:
        log("No headers found in fetch, using default headers.", "warning")
        headers_dict = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
            'Content-Type': 'application/octet-stream'
        }

    # بدء عملية الاستخراج
    try:
        log("Initializing Extraction...")
        extractor = WidevineExtractor(
            wvd_path,
            pssh_b64,
            license_url,
            headers_dict
        )
        
        # تنفيذ الاستخراج
        keys, error = extractor.extract_keys(lambda msg: log(msg))
        
        if error:
            log(f"Failed: {error}", "error")
        elif keys:
            print(f"\n{Colors.GREEN}{'='*20} EXTRACTED KEYS {'='*20}{Colors.END}")
            for key in keys:
                print(f"{Colors.BOLD}{Colors.GREEN}[KEY] {key}{Colors.END}")
            print(f"{Colors.GREEN}{'='*56}{Colors.END}")
            
    except Exception as e:
        log(f"Fatal Error: {str(e)}", "error")

if __name__ == "__main__":
    main()
