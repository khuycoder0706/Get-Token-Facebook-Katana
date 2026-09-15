import requests
import json
import time
import random
import uuid
import base64
import io
import struct
import re
import email.utils
from typing import Optional, Dict, Tuple
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import pyotp
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


sys_dont_write_bytecode = True
print_lock = threading.Lock()

def safe_print(text):
    with print_lock:
        if not text.startswith('\033['):
            text = f"\033[1m{text}\033[0m"
        print(text)

def log_system(msg):
    safe_print(f"[Hệ Thống] | {msg}")

def log_account(uid, msg):
    safe_print(f"[{uid}] | {msg}")

def bold_input(prompt):
    import sys
    sys.stdout.write(f"\033[1m{prompt}\033[0m")
    sys.stdout.flush()
    return sys.stdin.readline().strip()

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner_text = """
===================================
      TOOL GET TOKEN FACEBOOK      
===================================
Author: HuyCoder
"""
    safe_print(banner_text)

def parse_input_line(line):
    parts = line.split('|')
    parts = [p.strip() for p in parts]
    if len(parts) == 2:
        uid, pwd = parts
        return uid, pwd, "", "", False
    elif len(parts) == 3:
        uid, pwd, third = parts
        if ';' in third or '=' in third:
            return uid, pwd, "", third, False
        else:
            return uid, pwd, third, "", True
    elif len(parts) == 4:
        uid, pwd, twofa, cookie = parts
        return uid, pwd, twofa, cookie, True
    else:
        raise ValueError(f"Số trường không hợp lệ: {len(parts)}. Cần 2, 3 hoặc 4 trường.")

def extract_datr_from_cookie(cookie_str: str) -> str:
    if not cookie_str:
        return ""
    match = re.search(r'datr=([^;]+)', cookie_str)
    return match.group(1) if match else cookie_str


def parse_proxy(proxy_str: Optional[str]) -> Optional[Dict[str, str]]:
    if not proxy_str or not str(proxy_str).strip():
        return None
    p = str(proxy_str).strip()
    if p.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
        return {'http': p, 'https': p}
    parts = p.split(':')
    if len(parts) == 4:
        host, port, user, pwd = parts
        formatted = f"http://{user}:{pwd}@{host}:{port}"
        return {'http': formatted, 'https': formatted}
    elif len(parts) == 2:
        host, port = parts
        formatted = f"http://{host}:{port}"
        return {'http': formatted, 'https': formatted}
    else:
        formatted = f"http://{p}"
        return {'http': formatted, 'https': formatted}

class FacebookPasswordEncryptor:
    @staticmethod
    def get_public_key(proxy: Optional[str] = None) -> Tuple[str, str, float]:
        url = 'https://b-graph.facebook.com/pwd_key_fetch'
        params = {
            'version': '2',
            'flow': 'CONTROLLER_INITIALIZATION',
            'method': 'GET',
            'fb_api_req_friendly_name': 'pwdKeyFetch',
            'fb_api_caller_class': 'com.facebook.auth.login.AuthOperations',
            'access_token': '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
        }
        headers = {
            'User-Agent': 'okhttp/5.1.0',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip',
            'content-length': '0'
        }
        r = requests.post(url, params=params, headers=headers, proxies=parse_proxy(proxy), timeout=15)
        response = r.json()
        pub_key = response.get('public_key')
        key_id = str(response.get('key_id', '25'))

        server_ts = time.time()
        date_hdr = r.headers.get('Date')
        if date_hdr:
            try:
                server_ts = email.utils.parsedate_to_datetime(date_hdr).timestamp()
            except Exception:
                pass

        if not pub_key:
            raise Exception(f"Không nhận được public key: {response}")
        return pub_key, key_id, server_ts

    @staticmethod
    def encrypt(password: str, proxy: Optional[str] = None) -> Tuple[str, float]:
        public_key, key_id, server_ts = FacebookPasswordEncryptor.get_public_key(proxy)

        rand_key = get_random_bytes(32)
        iv = get_random_bytes(12)

        pubkey = RSA.import_key(public_key)
        cipher_rsa = PKCS1_v1_5.new(pubkey)
        encrypted_rand_key = cipher_rsa.encrypt(rand_key)

        cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
        current_time = int(server_ts)
        cipher_aes.update(str(current_time).encode('utf-8'))
        (encrypted_passwd, auth_tag) = cipher_aes.encrypt_and_digest(password.encode('utf-8'))

        buf = io.BytesIO()
        buf.write(bytes([1, int(key_id)]))
        buf.write(iv)
        buf.write(struct.pack('<h', len(encrypted_rand_key)))
        buf.write(encrypted_rand_key)
        buf.write(auth_tag)
        buf.write(encrypted_passwd)

        encoded = base64.b64encode(buf.getvalue()).decode('utf-8')
        return f'#PWD_FB4A:2:{current_time}:{encoded}', server_ts


class FacebookLogin:
    GQL_URL = 'https://b-graph.facebook.com/graphql'
    AUTH_URL = 'https://b-graph.facebook.com/auth/login'
    ACCESS_TOKEN = '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
    BLOKS_VERSION = '3469837656910fc29c9aa968ab33845cd52eb5253ae110610b944c8e9028d8f6'
    CLIENT_DOC_ID = '119940804214876861379510865434'
    TWO_FA_ENTRYPOINT_DOC_ID = '105373461558397492702779496'
    ATTESTATION_SIG = 'MEQCIDHrmQ86yvC7yeVBi0eYpIr2cnhtaSWxYm8I ZcZ081fAiBLzhHez6CMvaQqaFrCvfCMYker7WNLiQ4L99JpVR9K Q=='
    ATTESTATION_KEY = '9c620c1c59a053c07d9ce2f1166b1385e359254b6c461b3b55ca256d75e0976e'
    FB4A_UA = '[FBAN/FB4A;FBAV/542.0.0.46.151;FBBV/840338789;FBDM/{density=0.75,width=300,height=540};FBLC/vi_VN;FBRV/0;FBCR/MobiFone;FBMF/MTool-Max;FBBD/MTool-Max;FBPN/com.facebook.katana;FBDV/MTool-Max;FBSV/9;FBOP/1;FBCA/x86_64:arm64-v8a;]'

    def __init__(self, uid_phone_mail: str, password: str, twofa_secret: Optional[str] = None, machine_id: Optional[str] = None, proxy: Optional[str] = None):
        self.uid_phone_mail = str(uid_phone_mail).strip()
        self.twofa_secret = re.sub(r'[\s\-]+', '', str(twofa_secret or '')).upper()
        self.raw_password = password
        self.proxy = proxy
        self.px_dict = parse_proxy(proxy)
        self.server_time_offset = 0.0

        if password.startswith('#PWD_FB4A'):
            self.password = password
        else:
            self.password, server_ts = FacebookPasswordEncryptor.encrypt(password, proxy=proxy)
            self.server_time_offset = server_ts - time.time()

        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
        self.secure_family_device_id = str(uuid.uuid4())
        self.waterfall_id = str(uuid.uuid4())
        self.infra_flow_id = str(uuid.uuid4())
        self.client_trace_id = str(uuid.uuid4())
        self.machine_id = machine_id or ''

    def _get_server_now(self) -> float:
        return time.time() + self.server_time_offset

    def _build_attestation(self):
        nonce = base64.b64encode(get_random_bytes(32)).decode()
        data_json = json.dumps({'challenge_nonce': nonce, 'username': self.uid_phone_mail})
        return {
            'data': base64.b64encode(data_json.encode()).decode(),
            'signature': self.ATTESTATION_SIG,
            'keyHash': self.ATTESTATION_KEY
        }

    def _build_gql_headers(self):
        return {
            'User-Agent': self.FB4A_UA,
            'Accept': 'application/json, text/json, text/x-json, text/javascript, application/xml, text/xml',
            'Accept-Encoding': 'gzip',
            'x-fb-connection-type': 'WIFI',
            'x-fb-http-engine': 'Tigon/Liger',
            'x-fb-client-ip': 'True',
            'x-fb-server-cluster': 'True',
            'x-tigon-is-retry': 'False',
            'x-fb-device-group': '5427',
            'x-graphql-request-purpose': 'fetch',
            'x-fb-privacy-context': '3643298472347298',
            'x-graphql-client-library': 'graphservice',
            'x-fb-net-hni': '45201',
            'x-fb-sim-hni': '45201',
            'authorization': f'OAuth {self.ACCESS_TOKEN}',
            'x-fb-request-analytics-tags': json.dumps({
                'network_tags': {
                    'product': '350685531728',
                    'purpose': 'fetch',
                    'request_category': 'graphql',
                    'retry_attempt': '0'
                },
                'application_tags': 'graphservice'
            })
        }

    def _build_client_input_params(self):
        return {
            'password': self.password,
            'device_id': self.device_id,
            'family_device_id': self.device_id,
            'contact_point': self.uid_phone_mail,
            'login_attempt_count': 1,
            'event_flow': 'login_manual',
            'sim_phones': [],
            'secure_family_device_id': self.secure_family_device_id,
            'attestation_result': self._build_attestation(),
            'auth_secure_device_id': '',
            'has_whatsapp_installed': 0,
            'sso_token_map_json_string': '',
            'password_contains_non_ascii': 'false',
            'sim_serials': [],
            'client_known_key_hash': '',
            'encrypted_msisdn': '',
            'should_show_nested_nta_from_aymh': 0,
            'machine_id': self.machine_id,
            'flash_call_permission_status': {
                'READ_PHONE_STATE': 'DENIED',
                'READ_CALL_LOG': 'DENIED',
                'ANSWER_PHONE_CALLS': 'DENIED'
            },
            'accounts_list': [],
            'fb_ig_device_id': [],
            'device_emails': [],
            'try_num': 1,
            'lois_settings': {'lois_token': '', 'lara_override': ''},
            'event_step': 'home_page',
            'headers_infra_flow_id': self.infra_flow_id,
            'openid_tokens': {}
        }

    def _build_server_params(self):
        return {
            'should_trigger_override_login_2fa_action': 0,
            'is_from_logged_out': 0,
            'should_trigger_override_login_success_action': 0,
            'login_credential_type': 'none',
            'server_login_source': 'login',
            'waterfall_id': self.waterfall_id,
            'login_source': 'Login',
            'is_platform_login': 0,
            'pw_encryption_try_count': 1,
            'INTERNAL__latency_qpl_marker_id': 36707139,
            'offline_experiment_group': 'caa_iteration_v6_perf_fb_2',
            'is_from_landing_page': 0,
            'password_text_input_id': 'nmi7ws:95',
            'is_from_empty_password': 0,
            'ar_event_source': 'login_home_page',
            'username_text_input_id': 'nmi7ws:94',
            'layered_homepage_experiment_group': None,
            'device_id': self.device_id,
            'INTERNAL__latency_qpl_instance_id': random.randint(100000000000000, 999999999999999),
            'reg_flow_source': 'login_home_native_integration_point',
            'is_caa_perf_enabled': 1,
            'credential_type': 'password',
            'is_from_password_entry_page': 0,
            'caller': 'gslr',
            'family_device_id': self.device_id,
            'INTERNAL_INFRA_THEME': 'harm_f',
            'is_from_assistive_id': 0,
            'access_flow_version': 'F2_FLOW',
            'is_from_logged_in_switcher': 0
        }

    def _build_payload(self):
        inner_params = json.dumps({
            'client_input_params': self._build_client_input_params(),
            'server_params': self._build_server_params()
        })
        variables = json.dumps({
            'params': {
                'params': inner_params,
                'bloks_versioning_id': self.BLOKS_VERSION,
                'app_id': 'com.bloks.www.bloks.caa.login.async.send_login_request'
            },
            'scale': '2',
            'nt_context': {
                'using_white_navbar': True,
                'styles_id': '964d559c1e2aa0142b5069bc8cb1adea',
                'pixel_ratio': 2,
                'is_push_on': True,
                'debug_tooling_metadata_token': None,
                'is_flipper_enabled': False,
                'theme_params': [],
                'bloks_version': self.BLOKS_VERSION
            }
        })
        return {
            'method': 'post',
            'pretty': 'false',
            'format': 'json',
            'server_timestamps': 'true',
            'locale': 'vi_VN',
            'purpose': 'fetch',
            'fb_api_req_friendly_name': 'FbBloksActionRootQuery-com.bloks.www.bloks.caa.login.async.send_login_request',
            'fb_api_caller_class': 'graphservice',
            'client_doc_id': self.CLIENT_DOC_ID,
            'variables': variables,
            'fb_api_analytics_tags': '["GraphServices"]',
            'client_trace_id': self.client_trace_id,
            'generate_session_cookies': '1'
        }

    def _extract_token(self, text: str) -> Optional[str]:
        match = re.search(r'"access_token"\s*:\s*"([^"]+)"', text)
        if not match:
            match = re.search(r'access_token=([^&"\s]+)', text)
        if not match:
            match = re.search(r'access_token.*?([A-Za-z0-9:_-]{20,})', text)
        if match:
            return match.group(1)
        return None

    def _extract_cookies(self, text: str) -> str:
        try:
            data = json.loads(text)
            cookies = []
            def find_cookies(obj):
                if isinstance(obj, dict):
                    if 'session_cookies' in obj and isinstance(obj['session_cookies'], list):
                        for c in obj['session_cookies']:
                            if 'name' in c and 'value' in c:
                                cookies.append(f"{c['name']}={c['value']}")
                    for v in obj.values():
                        find_cookies(v)
                elif isinstance(obj, list):
                    for item in obj:
                        find_cookies(item)
            find_cookies(data)
            if cookies:
                return '; '.join(cookies)
        except Exception:
            pass
        match = re.search(r'"session_cookies":\s*\[(.*?)\]', text, re.DOTALL)
        if match:
            cookie_part = match.group(1)
            pairs = re.findall(r'"name":"([^"]+)","value":"([^"]+)"', cookie_part)
            if pairs:
                return '; '.join([f"{name}={value}" for name, value in pairs])
        return ""

    def _get_cookies_from_token(self, token: str) -> str:
        url = 'https://api.facebook.com/method/auth.getSessionforApp'
        payload = {
            'access_token': token,
            'format': 'json',
            'new_app_id': '350685531728',
            'generate_session_cookies': '1'
        }
        try:
            resp = self.session.post(url, data=payload, proxies=self.px_dict, timeout=30)
            data = resp.json()
            if 'error' in data:
                return ""
            cookies = data.get('session_cookies', [])
            if cookies:
                return '; '.join(f"{c['name']}={c['value']}" for c in cookies)
            return ""
        except Exception:
            return ""

    def _call_2fa_entrypoint(self, two_step_verification_context: str, machine_id_2fa: str):
        screen_id = f'{uuid.uuid4().hex[:6]}:5'
        inner_params = json.dumps({
            'client_input_params': {
                'device_id': self.device_id,
                'is_whatsapp_installed': 0,
                'machine_id': machine_id_2fa
            },
            'server_params': {
                'family_device_id': self.device_id,
                'device_id': self.device_id,
                'two_step_verification_context': two_step_verification_context,
                'INTERNAL_INFRA_THEME': 'harm_f,default,harm_f',
                'flow_source': 'two_factor_login',
                'INTERNAL_INFRA_screen_id': screen_id
            }
        })
        variables = json.dumps({
            'params': {
                'params': inner_params,
                'bloks_versioning_id': self.BLOKS_VERSION,
                'is_on_load_actions_supported': True,
                'app_id': 'com.bloks.www.two_step_verification.entrypoint'
            },
            'scale': '2',
            'nt_context': {
                'using_white_navbar': True,
                'styles_id': '964d559c1e2aa0142b5069bc8cb1adea',
                'pixel_ratio': 2,
                'is_push_on': True,
                'debug_tooling_metadata_token': None,
                'is_flipper_enabled': False,
                'theme_params': [],
                'bloks_version': self.BLOKS_VERSION
            }
        })
        payload = {
            'method': 'post',
            'pretty': 'false',
            'format': 'json',
            'server_timestamps': 'true',
            'locale': 'vi_VN',
            'purpose': 'fetch',
            'fb_api_req_friendly_name': 'FbBloksAppRootQuery-com.bloks.www.two_step_verification.entrypoint',
            'fb_api_caller_class': 'graphservice',
            'client_doc_id': self.TWO_FA_ENTRYPOINT_DOC_ID,
            'variables': variables,
            'fb_api_analytics_tags': '["GraphServices"]'
        }
        headers = self._build_gql_headers()
        self.session.post(self.GQL_URL, data=payload, headers=headers, proxies=self.px_dict, timeout=20)

    def _handle_2fa(self, two_step_verification_context: str, machine_id_2fa: str) -> dict:
        if not self.twofa_secret:
            return {
                'success': False,
                'api_failed': '2FA_VERIFY',
                'error': 'Tài khoản có bảo mật 2FA nhưng chưa cung cấp mã 2FA Secret'
            }

        try:
            self._call_2fa_entrypoint(two_step_verification_context, machine_id_2fa)

            server_now = self._get_server_now()
            totp = pyotp.TOTP(self.twofa_secret)
            twofactor_code = totp.at(server_now)

            safe_print(f"[2FA] Debug OTP: {twofactor_code}")

            inner_params = json.dumps({
                'client_input_params': {
                    'auth_secure_device_id': '',
                    'machine_id': machine_id_2fa,
                    'code': twofactor_code,
                    'should_trust_device': 1,
                    'family_device_id': self.device_id,
                    'device_id': self.device_id
                },
                'server_params': {
                    'INTERNAL__latency_qpl_marker_id': 36707139,
                    'device_id': self.device_id,
                    'challenge': 'totp',
                    'machine_id': machine_id_2fa,
                    'INTERNAL__latency_qpl_instance_id': random.randint(100000000000000, 999999999999999),
                    'two_step_verification_context': two_step_verification_context,
                    'flow_source': 'two_factor_login'
                }
            })
            variables = json.dumps({
                'params': {
                    'params': inner_params,
                    'bloks_versioning_id': self.BLOKS_VERSION,
                    'app_id': 'com.bloks.www.two_step_verification.verify_code.async'
                },
                'scale': '2',
                'nt_context': {
                    'using_white_navbar': True,
                    'styles_id': '964d559c1e2aa0142b5069bc8cb1adea',
                    'pixel_ratio': 2,
                    'is_push_on': True,
                    'debug_tooling_metadata_token': None,
                    'is_flipper_enabled': False,
                    'theme_params': [],
                    'bloks_version': self.BLOKS_VERSION
                }
            })
            payload_2fa = {
                'method': 'post',
                'pretty': 'false',
                'format': 'json',
                'server_timestamps': 'true',
                'locale': 'vi_VN',
                'purpose': 'fetch',
                'fb_api_req_friendly_name': 'FbBloksActionRootQuery-com.bloks.www.two_step_verification.verify_code.async',
                'fb_api_caller_class': 'graphservice',
                'client_doc_id': self.CLIENT_DOC_ID,
                'variables': variables,
                'fb_api_analytics_tags': '["GraphServices"]',
                'generate_session_cookies': '1'
            }
            headers = self._build_gql_headers()
            resp = self.session.post(self.GQL_URL, data=payload_2fa, headers=headers, proxies=self.px_dict, timeout=25)
            text = resp.text

            token = self._extract_token(text)
            if token:
                return self._build_success_result(token, text)

            bloks_err = None
            try:
                data_2fa = resp.json()
                inner_action = data_2fa.get('data', {}).get('fb_bloks_action', {}).get('root_action', {}).get('action', {}).get('action_bundle', {}).get('bloks_bundle_action', '')
                if inner_action:
                    m = re.search(r'BLOKS_TWO_STEP_VERIFICATION_ENTER_CODE:error_message\\*"\s*,\s*\\*"([^"\\]*(?:\\.[^"\\]*)*)', inner_action)
                    if m:
                        raw_escaped = m.group(1)
                        bloks_err = raw_escaped.encode('utf-8').decode('unicode_escape')
            except Exception:
                pass

            if bloks_err:
                return {'success': False, 'api_failed': '2FA_VERIFY', 'error': bloks_err, 'code_sent': twofactor_code}

            err_match = re.search(r'"error_message":"([^"]*)"', text)
            if err_match:
                return {'success': False, 'api_failed': '2FA_VERIFY', 'error': err_match.group(1), 'code_sent': twofactor_code}

            return {
                'success': False,
                'api_failed': '2FA_VERIFY',
                'error': 'Mã 2FA không chính xác hoặc đã hết hạn',
                'code_sent': twofactor_code
            }

        except Exception as e:
            return {'success': False, 'api_failed': '2FA_VERIFY', 'error': f'Lỗi ngoại lệ 2FA: {str(e)}'}

    def _build_success_result(self, token: str, response_text: str = "") -> dict:
        cookies = self._get_cookies_from_token(token)
        if not cookies:
            if response_text:
                cookies = self._extract_cookies(response_text)
            if not cookies:
                cookie_jar = self.session.cookies
                if cookie_jar:
                    cookies = '; '.join([f"{c.name}={c.value}" for c in cookie_jar])
        return {
            'success': True,
            'access_token': token,
            'cookies': cookies
        }

    def login(self) -> dict:
        try:
            headers = self._build_gql_headers()
            payload = self._build_payload()
            resp = self.session.post(self.GQL_URL, data=payload, headers=headers, proxies=self.px_dict, timeout=30)
            text = resp.text

            token = self._extract_token(text)
            if token:
                return self._build_success_result(token, text)

            if 'two_step_verification_context' in text or 'error_2fa' in text:
                dataJson = json.loads(text)
                inner = dataJson.get('data', {}).get('fb_bloks_action', {}).get('root_action', {}).get('action', {}).get('action_bundle', {}).get('bloks_bundle_action', '')
                ctx_match = re.search(r'two_step_verification_context.*?"([A-Za-z0-9_\-]{100,})', inner)
                mid_match = re.search(r'SaveMachineID[^A-Za-z0-9_-]+([A-Za-z0-9_-]{10,})', text)

                if ctx_match:
                    context = ctx_match.group(1)
                    machine_id_2fa = self.machine_id or (mid_match.group(1) if mid_match else '')
                    return self._handle_2fa(context, machine_id_2fa)
                else:
                    return {
                        'success': False,
                        'api_failed': 'LOGIN_PARSE_2FA_CONTEXT',
                        'error': 'Cần 2FA nhưng không bóc tách được two_step_verification_context',
                        'response_raw': text
                    }

            try:
                data = resp.json()
                errors = data.get('errors', [])
                if errors:
                    return {
                        'success': False,
                        'api_failed': 'LOGIN_GRAPHQL_ERROR',
                        'error': errors[0].get('message', 'Lỗi không xác định'),
                        'response_raw': text
                    }
            except Exception:
                pass

            err_match = re.search(r'"error_message":"([^"]*)"', text)
            if err_match:
                return {'success': False, 'api_failed': 'LOGIN_SEND_REQUEST', 'error': err_match.group(1), 'response_raw': text}

            msg_match = re.search(r'"message":"([^"]*)"', text)
            if msg_match:
                return {'success': False, 'api_failed': 'LOGIN_SEND_REQUEST', 'error': msg_match.group(1), 'response_raw': text}

            return {
                'success': False,
                'api_failed': 'LOGIN_NO_TOKEN',
                'error': 'Đăng nhập không thành công, không nhận được token',
                'response_raw': text
            }

        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'api_failed': 'REQUEST_CONNECTION_ERROR',
                'error': f'Lỗi kết nối mạng/proxy: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'api_failed': 'UNKNOWN_EXCEPTION',
                'error': str(e)
            }


def process_account(index, line, has_2fa, uid, password, twofa, cookie):
    machine_id = extract_datr_from_cookie(cookie)
    try:
        fb = FacebookLogin(uid_phone_mail=uid, password=password, twofa_secret=twofa, machine_id=machine_id, proxy=None)
        result = fb.login()
        if result.get('success'):
            token = result['access_token']
            cookies = result.get('cookies', '')
            if has_2fa:
                out_line = f"{uid}|{password}|{twofa}|{cookies}|{token}"
            else:
                out_line = f"{uid}|{password}|{cookies}|{token}"
            log_account(uid, "✅ Đăng nhập thành công")
            return index, True, [out_line]
        else:
            error = result.get('error', 'Unknown error')
            log_account(uid, f"❌ Thất bại: {error}")
            return index, False, [line]
    except Exception as e:
        log_account(uid, f"❌ Ngoại lệ: {str(e)}")
        return index, False, [line]

def main():
    banner()
    print("\033[1mChọn chế độ nhập:\033[0m")
    print("\033[1m1. Nhập trực tiếp\033[0m")
    print("\033[1m2. Nhập từ file txt\033[0m")
    mode = bold_input("Chọn (1/2): ")

    success_accounts = []
    fail_accounts = []
    all_success_lines = []
    results = []

    if mode == '1':
        print("\033[1m\nNhập dòng dữ liệu:\033[0m")
        print("\033[1mHỗ trợ các định dạng:\033[0m")
        print("  - UID|PASS")
        print("  - UID|PASS|2FA")
        print("  - UID|PASS|COOKIE")
        print("  - UID|PASS|2FA|COOKIE")
        line = bold_input("> ")
        try:
            uid, pwd, twofa, cookie, has_2fa = parse_input_line(line)
        except ValueError as e:
            log_system(f"Lỗi: {e}")
            return

        log_system("Đang xử lý 1 tài khoản...")
        idx, success, lines = process_account(1, line, has_2fa, uid, pwd, twofa, cookie)
        if success:
            success_accounts.append(lines[0])
            all_success_lines.extend(lines)
        else:
            fail_accounts.append(lines[0])

    elif mode == '2':
        file_path = bold_input("Nhập đường dẫn file txt: ")
        if not os.path.exists(file_path):
            log_system(f"Không tìm thấy file: {file_path}")
            return

        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]

        total = len(lines)
        log_system(f"Đang xử lý {total} tài khoản...")

        tasks = []
        for idx, line in enumerate(lines, 1):
            try:
                uid, pwd, twofa, cookie, has_2fa = parse_input_line(line)
            except ValueError as e:
                log_system(f"Lỗi dòng {idx}: {e} - {line}")
                fail_accounts.append(line)
                continue
            tasks.append((idx, line, has_2fa, uid, pwd, twofa, cookie))

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_idx = {}
            for task in tasks:
                idx, line, has_2fa, uid, pwd, twofa, cookie = task
                future = executor.submit(process_account, idx, line, has_2fa, uid, pwd, twofa, cookie)
                future_to_idx[future] = idx

            for future in as_completed(future_to_idx):
                idx, success, lines_result = future.result()
                results.append((idx, success, lines_result))

        results.sort(key=lambda x: x[0])
        for idx, success, lines_result in results:
            if success:
                success_accounts.append(lines_result[0])
                all_success_lines.extend(lines_result)
            else:
                fail_accounts.append(lines_result[0])

    else:
        log_system("Chế độ không hợp lệ")
        return

    success_count = len(success_accounts)
    fail_count = len(fail_accounts)
    log_system(f"Login Thành Công: {success_count} | Login Thất Bại: {fail_count}")

    if all_success_lines:
        with open("Acc_Live.txt", "w", encoding="utf-8") as f:
            for line in all_success_lines:
                f.write(line + "\n")
        log_system(f"Đã lưu {len(all_success_lines)} dòng vào Acc_Live.txt")
    else:
        log_system("Không có Acc nào thành công")

    if fail_accounts:
        with open("Acc_Die.txt", "w", encoding="utf-8") as f:
            for acc in fail_accounts:
                f.write(acc + "\n")
        log_system(f"Đã lưu {fail_count} Acc thất bại vào Acc_Die.txt")
    else:
        log_system("Không có Acc nào thất bại")

if __name__ == '__main__':
    main()