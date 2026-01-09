from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
import requests

class WidevineExtractor:
    def __init__(self, wvd_path, pssh_b64, license_url, headers_dict):
        self.wvd_path = wvd_path
        self.pssh_b64 = pssh_b64
        self.license_url = license_url
        self.headers_dict = headers_dict
    
    def extract_keys(self, log_callback):
        try:
            log_callback("Initializing CDM...")
            
            pssh = PSSH(self.pssh_b64)
            device = Device.load(self.wvd_path)
            cdm = Cdm.from_device(device)
            
            session_id = cdm.open()
            challenge = cdm.get_license_challenge(session_id, pssh)
            
            log_callback(f"Requesting license from: {self.license_url}")
            
            headers = {}
            for key, value in self.headers_dict.items():
                clean_value = str(value)
                
                if any(ord(c) > 127 for c in clean_value):
                    clean_value = clean_value.replace('\u2026', '')
                    clean_value = ''.join(c for c in clean_value if ord(c) < 128)
                
                headers[key] = clean_value
            
            resp = requests.post(
                self.license_url, 
                headers=headers, 
                data=challenge,
                timeout=10
            )
            
            if resp.status_code != 200:
                raise Exception(f"License server returned {resp.status_code}")
            
            cdm.parse_license(session_id, resp.content)
            
            keys = []
            for key in cdm.get_keys(session_id):
                if key.type == "CONTENT":
                    key_str = f"{key.kid.hex}:{key.key.hex()}"
                    keys.append(key_str)
            
            cdm.close(session_id)
            
            if keys:
                for key in keys:
                    log_callback(f"KEY: {key}")
            else:
                log_callback("ERROR: No content keys found")
            
            return keys, None
            
        except Exception as e:
            error_msg = f"ERROR: Extraction failed: {str(e)}"
            log_callback(error_msg)
            return [], str(e)