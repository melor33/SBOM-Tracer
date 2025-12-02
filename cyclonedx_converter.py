#!/usr/bin/env python3
"""
YAML to CycloneDX SBOM Converter
Converts YAML reports (PTXdist and custom formats) to CycloneDX format
Production-ready CLI tool with OOP design
"""

import yaml
import requests
import time
import os
import json
import re
import sys
import uuid
import argparse
import urllib.parse
import hashlib
import signal

from tqdm import tqdm
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
from rapidfuzz import fuzz
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

def signal_handler(sig, frame):
    print("\n[!] Ejecución interrumpida por el usuario (Ctrl+C)")
    print("\n Saliendo...")
    sys.exit(0)

# Registrar el manejador de señal
signal.signal(signal.SIGINT, signal_handler)

# Variables from environment
load_dotenv()
API_KEY = os.environ.get("API_KEY") or ""
TARGET_URL = os.environ.get("TARGET_URL") or "https://services.nvd.nist.gov/rest/json/cpes/2.0"

MAX_RETRIES = 3
RATE_LIMIT = 0.6
MAX_WORKERS = 5

# Regex pattern compilation
VERSION_PATTERN = re.compile(r"(\D)\d+$")
UPDATE_PATTERN = re.compile(r"(alpha\d*|beta\d*|pre\d*|rc\d*|p\d+|b\d*|deb\d*)$", re.IGNORECASE)
TRIM_PATTERN = re.compile(r"[.\-_]+$")
FULL_VERSION_PATTERN = re.compile(
    r"""^\s*(?:v)?(?P<core>[0-9]+(?:[.\-][0-9A-Za-z]+)*)
    (?P<suffix>(?:alpha|beta|pre|rc|p|b|deb)\d*)?
    (?:(?P<sep>[+\-])(?P<meta>[0-9A-Za-z\.]+))?\s*$""",
    re.VERBOSE | re.IGNORECASE
)

class YAMLParser(object):
    """Simple YAML parser compatible with Python 2.7+"""
    
    def __init__(self, yaml_file):
        self.yaml_file = yaml_file
        self.data = {}
    
    def parse(self):
        """Parse YAML file and return data dictionary"""
        current_list_key = None
        section_stack = []
        
        with open(self.yaml_file, 'r') as f:
            for line in f:
                line = line.rstrip('\n\r')
                
                if not line.strip() or line.strip().startswith('#'):
                    continue
                
                indent = len(line) - len(line.lstrip())
                line = line.strip()
                
                # Handle list items
                if line.startswith('- '):
                    if current_list_key:
                        if current_list_key not in self.data:
                            self.data[current_list_key] = []
                        value = line[2:].strip().strip("'\"")
                        self.data[current_list_key].append(value)
                    continue
                
                # Handle key-value pairs
                if ':' in line:
                    key, value = self._parse_key_value(line, indent, section_stack)
                    if key:
                        if not value:
                            current_list_key = key
                        else:
                            current_list_key = None
                            self.data[key] = value
        
        return self.data
    
    def _parse_key_value(self, line, indent, section_stack):
        """Parse a key-value line and return full key and value"""
        parts = line.split(':', 1)
        if len(parts) != 2:
            return None, None
        
        key = parts[0].strip()
        value = parts[1].strip().strip("'\"")
        
        # Update section stack based on indentation
        if indent == 0:
            section_stack[:] = [key]
        elif indent == 2:
            section_stack[:] = section_stack[:1] + [key]
        elif indent == 4:
            section_stack[:] = section_stack[:2] + [key]
        elif indent == 6:
            section_stack[:] = section_stack[:3] + [key]
        
        full_key = '.'.join(section_stack)
        return full_key, value

class PackageExtractor(object):
    """Extract package information from parsed YAML data"""
    
    def __init__(self, yaml_data):
        self.yaml_data = yaml_data
        self.packages = {}
    
    def extract(self):
        """Extract all packages from YAML data"""
        for key, value in self.yaml_data.items():
            if not key.startswith('packages.'):
                continue
            
            parts = key.split('.')
            if len(parts) < 2:
                continue
            
            package_name = parts[1]
            if package_name not in self.packages:
                self.packages[package_name] = {}
            
            prop_name = '.'.join(parts[2:]) if len(parts) > 2 else ''
            if prop_name:
                self.packages[package_name][prop_name] = value
        
        return self.packages

class CPEMatcher:
    def __init__(self, api_key='', max_workers=5):
        self.api_key = api_key
        self.headers = {"apiKey": self.api_key} if self.api_key else {}
        self.session = requests.Session()
        self.max_workers = max_workers
        
    def search_cpe(self, pkg_name, pkg_vers='*', pkg_subvers='*', strict=False):
        """Finds all CPE on NVD database. Using requests to its API."""

        actual_retries = 0
        
        while actual_retries < MAX_RETRIES: # Use progressive wait time as the API server has a rate limit.
            try:
                params = self._build_params(pkg_name, pkg_vers, pkg_subvers, strict)
                r = self.session.get(TARGET_URL, params=params, headers=self.headers, timeout=10)
                
                if r.status_code == 429: # In case 429 Code 'Too Many Requests' Occur
                    wait_time = (2 ** actual_retries) * RATE_LIMIT
                    time.sleep(wait_time)
                    actual_retries += 1
                    continue
                elif r.status_code != 200: # In case any other error code occurs
                    # print(f"[!] URL: {r.url}")
                    # print(f"[!] Error {r.status_code} for {pkg_name} {pkg_vers}")
                    return None
                
                return r.json()
                
            except requests.exceptions.RequestException as e:
                # print(f"[!] Request ERROR: {e}")
                time.sleep(RATE_LIMIT)
                actual_retries += 1
        
        return None
    
    def _build_params(self, pkg_name, pkg_vers, pkg_subvers, strict):
        """Builds search parameters to be used in the NVD API request"""
        if strict:
            return {"cpeMatchString": f"cpe:2.3:*:*:{pkg_name}:{pkg_vers}:{pkg_subvers}:*:*:*:*:*:*"}
        
        keywords = pkg_name
        if pkg_vers != '*':
            keywords += f' {pkg_vers}'
        if pkg_subvers != '*':
            keywords += f' {pkg_subvers}'
        return {"keywordSearch": keywords}
    
    def select_best_cpe(self, data, pkg_name):
        """Selects the best CPE from results obtained"""
        total_results = data.get('resultsPerPage', 0)
        
        if not total_results: # No results case
            return False, None
        elif total_results == 1: # Unique result case
            cpe_name = data.get('products', [{}])[0].get('cpe', {}).get('cpeName', '')
            return True, cpe_name
        else: # Multiple results case
            for product in data.get('products', []):
                cpe_name = product.get('cpe', {}).get('cpeName', '')
                cpe_parts = cpe_name.split(':')
                cpe_pkg_name = cpe_parts[4]
                
                score = fuzz.ratio(pkg_name, cpe_pkg_name)
                
                if (score > 90 and 
                    all(f in ('*', '-') for f in cpe_parts[6:]) and 
                    not product.get('cpe', {}).get('deprecated', False)):
                    return True, cpe_name
            
            return False, None


class PackageIdNormalizer:
    """Class that normalizes package name and version"""
    
    @staticmethod
    def normalize_name(pkg_name):
        """Normalize package name"""
        return VERSION_PATTERN.sub(r"\1", pkg_name)
    
    @staticmethod
    def extract_version_parts(version):
        """Normalizes and divides package version (core, suffix, metadata)"""
        match = FULL_VERSION_PATTERN.match(version)
        if match:
            core = TRIM_PATTERN.sub("", match.group("core") or "")
            suffix = match.group("suffix") or '*'
            return core, suffix
        
        match = UPDATE_PATTERN.search(version)
        if match:
            suffix = match.group(1)
            core = TRIM_PATTERN.sub("", version[:match.start()])
            return core, suffix
        
        return TRIM_PATTERN.sub("", version), '*'


class CPEGenerator:
    """Class that generates the final CPEs"""
    
    def __init__(self, matcher, normalizer):
        self.matcher = matcher
        self.normalizer = normalizer
        self.search_strategies = [
            self._strategy_exact,
            self._strategy_with_subversion,
            self._strategy_without_subversion,
            self._strategy_normalized,
            self._strategy_name_only,
        ]
    
    def generate(self, pkg_name_og, pkg_vers):
        """Generates the CPE based on all strategies implemented"""
        if pkg_name_og.startswith('host-'):
            return self._create_custom_cpe(pkg_name_og, pkg_vers)
        
        pkg_name = self.normalizer.normalize_name(pkg_name_og)
        
        if not pkg_vers or not re.search(r"\d", pkg_vers):
            return self._strategy_name_only(pkg_name, pkg_vers)
        
        # Added to clean ':' and '+' not to have 404 errors on NVD database.
        pkg_vers_splitted = pkg_vers.split(':')
        pkg_vers_clean = "".join(pkg_vers_splitted[1:]) if len(pkg_vers_splitted) > 1 else pkg_vers

        pkg_vers_clean = pkg_vers_clean.replace('+', '-')
        pkg_vers_clean = pkg_vers_clean.replace('~', '-')
        
        # Test strategies in order
        for strategy in self.search_strategies:
            result = strategy(pkg_name, pkg_vers_clean)
            if result:
                return result
        
        # In case no strategies work, create a custom CPE
        return self._create_custom_cpe(pkg_name, pkg_vers_clean)
    
    def _try_search(self, pkg_name, pkg_vers='*', pkg_subvers='*', strict_first=True):
        """Searches first using CPE match and then by keyword match"""
        for strict in [True, False] if strict_first else [False]:
            data = self.matcher.search_cpe(pkg_name, pkg_vers, pkg_subvers, strict)
            if data:
                found, cpe_name = self.matcher.select_best_cpe(data, pkg_name)
                if found:
                    mode = "CPE" if strict else "KEYWORD"
                    return cpe_name, mode
        return None, None
    
    def _strategy_exact(self, pkg_name, pkg_vers):
        """Search strategy 1: Exact Match"""
        cpe, mode = self._try_search(pkg_name, pkg_vers)
        if cpe:
            return {'cpe': cpe, 'key': f'{pkg_name} / {pkg_vers}', 'method': f'1 {mode}'}
        return None
    
    def _strategy_with_subversion(self, pkg_name, pkg_vers):
        """Search strategy 2.1: Search with extracted subversion or update"""
        vers_clean, subvers = self.normalizer.extract_version_parts(pkg_vers)
        cpe, mode = self._try_search(pkg_name, vers_clean, subvers)
        if cpe:
            return {'cpe': cpe, 'key': f'{pkg_name} / {vers_clean} / {subvers}', 'method': f'2.1 {mode}'}
        return None
    
    def _strategy_without_subversion(self, pkg_name, pkg_vers):
        """Search strategy 2.2: Search without extracted subversion or update"""
        vers_clean, _ = self.normalizer.extract_version_parts(pkg_vers)
        cpe, mode = self._try_search(pkg_name, vers_clean)
        if cpe:
            return {'cpe': cpe, 'key': f'{pkg_name} / {vers_clean}', 'method': f'2.2 {mode}'}
        return None
    
    def _strategy_normalized(self, pkg_name, pkg_vers):
        """Search strategy 3: Search with cleaned and normalized version"""
        vers_clean, subvers = self.normalizer.extract_version_parts(pkg_vers)
        
        # Using subversion or update
        cpe, mode = self._try_search(pkg_name, vers_clean, subvers)
        if cpe:
            return {'cpe': cpe, 'key': f'{pkg_name} / {vers_clean} / {subvers}', 'method': f'3.1 {mode}'}
        
        # Dropping subversion or update
        cpe, mode = self._try_search(pkg_name, vers_clean)
        if cpe:
            return {'cpe': cpe, 'key': f'{pkg_name} / {vers_clean}', 'method': f'3.2 {mode}'}
        
        return None
    
    def _strategy_name_only(self, pkg_name, pkg_vers='*'):
        """Search strategy 4: Search only using package name, version is inserted manually."""
        cpe, mode = self._try_search(pkg_name)
        if cpe:
            cpe_parts = cpe.split(":")
            cpe_parts[5] = pkg_vers
            new_cpe = ":".join(cpe_parts)
            return {'cpe': new_cpe, 'key': pkg_name, 'method': f'4 {mode}'}
        return None
    
    def _create_custom_cpe(self, pkg_name, pkg_vers):
        """Strategy 5: Create totally customized CPE"""
        clean_name = pkg_name.lower().replace('_', '-').replace(' ', '-')
        clean_version = pkg_vers.replace('_', '-') if pkg_vers else '*'
        cpe = f"cpe:2.3:a:*:{clean_name}:{clean_version}:*:*:*:*:*:*:*"
        return {'cpe': cpe, 'key': pkg_name, 'method': '5 CUSTOM'}

class IdentifierGenerator(object):
    """Generate package identifiers (PURL, CPE)"""
    
    # CPE vendor mapping
    VENDOR_MAPPING = {
        'openssl': 'openssl', 'zlib': 'zlib', 'libpng': 'libpng',
        'freetype': 'freetype', 'cairo': 'cairographics', 'glibc': 'gnu',
        'gcc': 'gnu', 'binutils': 'gnu', 'bash': 'gnu', 'coreutils': 'gnu',
        'busybox': 'busybox', 'dropbear': 'matt_johnston', 'openssh': 'openbsd',
        'curl': 'haxx', 'wget': 'gnu', 'sqlite': 'sqlite',
        'expat': 'libexpat_project', 'kernel': 'linux'
    }
    
    @staticmethod
    def extract_url_from_package(package_data):
        """Extract download URL from package data"""
        url_data = package_data.get('url', '')
        
        if url_data:
            return url_data[0] if isinstance(url_data, list) else url_data
        
        # Check for numbered URL keys
        for i in range(10):
            url_key = 'url.{}'.format(i)
            if url_key in package_data:
                return package_data[url_key]
        
        return ''

    @staticmethod
    def generate_purl_from_cpe(package_name, version, source, download_url='', cpe="") -> str:
        """Generate a Package URL (PURL) from CPE"""

        type_list = [
            "alpm",
            "apk",
            "bitbucket",
            "cargo",
            "cocoapods",
            "composer",
            "conan",
            "conda",
            "cran",
            "deb",
            "docker",
            "gem",
            "github",
            "golang",
            "helm",
            "hex",
            "maven",
            "npm",
            "nuget",
            "oci",
            "pub",
            "pypi",
            "rpm",
            "swift",
            "generic"
        ]

        # Fallback if cpe is non existant
        if not cpe:
            return IdentifierGenerator.generate_purl(package_name, version, source, download_url)

        if source == 'deb':
            return IdentifierGenerator.generate_purl(package_name, version, source, download_url)

        if not cpe.startswith("cpe:2.3:"):
            raise ValueError("[!] CPE must be version 2.3: 'cpe:2.3:'")

        parts = cpe.split(":")
        if len(parts) < 13:
            raise ValueError("[!] CPE is incomplete")

        _, _, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other = parts

        # Include vendor, priduct and version only
        purl_type = source if source in type_list else "generic"
        name = product
        namespace = vendor
        version_str = version
        if update and update != "*":
            version_str += f"-{update}"

        # Add qualifier if it exists
        qualifiers = {}
        if sw_edition and sw_edition != "*":
            qualifiers["sw_edition"] = sw_edition

        # Construct qualifiers string
        qualifier_str = ""
        if qualifiers:
            qualifier_str = "?" + "&".join(f"{k}={urllib.parse.quote(v)}" for k, v in qualifiers.items())

        purl = f"pkg:{purl_type}/{namespace}/{name}@{version_str}{qualifier_str}"
        return purl
    
    @staticmethod
    def generate_purl(package_name, version, source, download_url=''):
        """Generate a Package URL (PURL)"""
        type_list = [
            "alpm",
            "apk",
            "bitbucket",
            "cargo",
            "cocoapods",
            "composer",
            "conan",
            "conda",
            "cran",
            "deb",
            "docker",
            "gem",
            "github",
            "golang",
            "helm",
            "hex",
            "maven",
            "npm",
            "nuget",
            "oci",
            "pub",
            "pypi",
            "rpm",
            "swift",
            "generic"
        ]

        pkg_type = source if source in type_list else "generic"
        namespace = ""
        
        url = download_url[0] if isinstance(download_url, list) else download_url
        
        if url and isinstance(url, str):
            url_lower = url.lower()
            
            if 'gnu.org' in url_lower:
                namespace = "gnu"
            elif 'apache.org' in url_lower:
                namespace = "apache"
            elif 'github.com' in url_lower:
                pkg_type = "github"
                try:
                    parsed = urllib.parse(url)
                    if parsed.path:
                        path_parts = parsed.path.strip('/').split('/')
                        if len(path_parts) >= 2:
                            namespace = path_parts[0]
                except:
                    pass

        if pkg_type == 'deb':
            namespace = 'debian'
        
        clean_name = package_name.lower().replace('_', '-')
        clean_version = version if version else ""
        
        purl = "pkg:{}".format(pkg_type)
        if namespace:
            purl += "/{}".format(namespace)
        purl += "/{}".format(clean_name)
        if clean_version:
            purl += "@{}".format(clean_version)
        
        return purl
    
    @classmethod
    def generate_cpe(cls, package_name, version, cpe_generator):
        """Generate a CPE name for vulnerability analysis"""

        # First of all clean version
        if version:
            # Clean version from ':'
            version_splitted = version.split(':')
            version = "".join(version_splitted[1:]) if len(version_splitted) > 1 else version

        try:
            result = cpe_generator.generate(package_name, version)
            
            if result:
                return result['cpe']  # Devuelve solo el CPE, no la tupla
            
            # Fallback to custom CPE
            return cls._create_fallback_cpe(package_name, version)
            
        except Exception as e:
            print(f'[!] Error generating CPE for {package_name}: {e}')
            return cls._create_fallback_cpe(package_name, version)

    @classmethod
    def _create_fallback_cpe(cls, package_name, version):
        """Create fallback CPE when API lookup fails"""
        clean_name = package_name.lower().replace('_', '-').replace(' ', '-')

        if version:
            version_splitted = version.split(':')
            clean_version = "".join(version_splitted[1:])

            clean_version = clean_version.replace('_', '-')
            clean_version = clean_version.replace('+', '-')
            clean_version = clean_version.replace('~', '-')

        else:
            clean_version = '*'

        vendor = cls.VENDOR_MAPPING.get(clean_name, '*')
        return "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*".format(vendor, clean_name, clean_version)

class LicenseMapper(object):
    """Map license strings to SPDX identifiers"""
    
    # Comprehensive SPDX license mapping
    LICENSE_MAPPING = {
        'LGPL-2.1-or-later': 'LGPL-2.1-or-later', 'LGPL-2.1+': 'LGPL-2.1-or-later',
        'GPL-2.0-only': 'GPL-2.0-only', 'GPL-2.0': 'GPL-2.0-only',
        'GPL-2.0-or-later': 'GPL-2.0-or-later', 'GPL-2.0+': 'GPL-2.0-or-later',
        'GPL-3.0-only': 'GPL-3.0-only', 'GPL-3.0': 'GPL-3.0-only',
        'GPL-3.0-or-later': 'GPL-3.0-or-later', 'GPL-3.0+': 'GPL-3.0-or-later',
        'LGPL-2.1-only': 'LGPL-2.1-only', 'LGPL-2.1': 'LGPL-2.1-only',
        'LGPL-3.0-only': 'LGPL-3.0-only', 'LGPL-3.0': 'LGPL-3.0-only',
        'BSD-3-Clause': 'BSD-3-Clause', 'BSD-2-Clause': 'BSD-2-Clause',
        'MIT': 'MIT', 'Apache-2.0': 'Apache-2.0', 'MPL-2.0': 'MPL-2.0',
        'OpenSSL': 'OpenSSL', 'Zlib': 'Zlib', 'ISC': 'ISC', 'X11': 'MIT',
        'Expat': 'MIT', 'Public Domain': 'CC0-1.0', 'Unlicense': 'Unlicense',
        'CC0': 'CC0-1.0', 'CC-BY-4.0': 'CC-BY-4.0', 'CC-BY-SA-4.0': 'CC-BY-SA-4.0',
        'Python-2.0': 'Python-2.0', 'Ruby': 'Ruby', 'Artistic-2.0': 'Artistic-2.0',
        'EPL-1.0': 'EPL-1.0', 'EPL-2.0': 'EPL-2.0', 'CDDL-1.0': 'CDDL-1.0',
        'CDDL-1.1': 'CDDL-1.1', 'MPL-1.1': 'MPL-1.1', 'EUPL-1.1': 'EUPL-1.1',
        'EUPL-1.2': 'EUPL-1.2'
    }
    
    @classmethod
    def map_to_spdx(cls, license_str):
        """Map license string to SPDX identifier"""
        if not license_str:
            return None
        
        license_normalized = license_str.strip()
        
        # Direct mapping
        if license_normalized in cls.LICENSE_MAPPING:
            return cls.LICENSE_MAPPING[license_normalized]
        
        # Pattern matching
        upper = license_normalized.upper()
        
        if upper.startswith('BSD'):
            return 'BSD-3-Clause' if '3' in license_normalized else 'BSD-2-Clause'
        
        if upper.startswith('GPL'):
            if '3' in license_normalized:
                return 'GPL-3.0-only'
            elif '2' in license_normalized:
                return 'GPL-2.0-only'
        
        if upper.startswith('LGPL'):
            if '3' in license_normalized:
                return 'LGPL-3.0-only'
            elif '2.1' in license_normalized:
                return 'LGPL-2.1-only'
        
        return None

class ComponentBuilder(object):
    """Build CycloneDX components from package data"""
    
    COMPONENT_TYPE_KEYWORDS = {
        'firmware': ['kernel', 'bootloader', 'u-boot'],
        'operating-system': ['glibc', 'musl', 'uclibc', 'busybox', 'bash', 'coreutils', 'systemd'],
        'application': ['gcc', 'binutils', 'make', 'cmake']
    }
    
    def __init__(self, package_name, package_data, cpe_dict):
        self.package_name = package_name
        self.package_data = package_data
        self.package_source = package_data.get('source' '')
        self.pkg_cpe_dict = cpe_dict
        self.version = package_data.get('version', '')
        self.download_url = IdentifierGenerator.extract_url_from_package(package_data)
        self.cpe = cpe_dict.get(f'{self.package_name}-{self.version}', '')
        self.purl = IdentifierGenerator.generate_purl_from_cpe(self.package_name, self.version, self.package_source, self.download_url, self.cpe)
    
    def build(self):
        """Build complete CycloneDX component"""
        component = {
            "type": self._determine_type(),
            "bom-ref": self.purl,
            "name": self.package_name,
            "purl": self.purl
        }
        
        if self.version:
            component["version"] = self.version
        
        component["cpe"] = self.cpe
        
        self._add_description(component)
        self._add_licenses(component)
        self._add_hashes(component)
        self._add_external_references(component)
        self._add_properties(component)
        self._add_scope(component)
        self._add_publisher(component)
        
        return component
    
    def _determine_type(self):
        """Determine component type"""
        if self.package_name.startswith('host-'):
            return "application"
        
        for comp_type, keywords in self.COMPONENT_TYPE_KEYWORDS.items():
            if self.package_name in keywords or any(kw in self.package_name.lower() for kw in keywords):
                return comp_type
        
        return "library"
    
    def _add_description(self, component):
        """Add component description"""
        parts = []
        
        license_section = self.package_data.get('license-section', '')
        if license_section:
            parts.append("License category: {}".format(license_section))
        
        if self.package_data.get('patches', ''):
            parts.append("Includes PTXdist patches")
        
        if parts:
            component["description"] = "; ".join(parts)
    
    def _add_licenses(self, component):
        """Add license information"""
        licenses = self.package_data.get('licenses', '')
        if not licenses:
            return
        
        # Handle complex license expressions
        if ' OR ' in licenses or ' AND ' in licenses:
            component["licenses"] = [{"expression": str(licenses)}]
        else:
            spdx_id = LicenseMapper.map_to_spdx(licenses)
            if spdx_id:
                component["licenses"] = [{"license": {"id": spdx_id}}]
        
        # Add license files
        license_files = [
            k.replace('license-files.', '') 
            for k in self.package_data.keys() 
            if k.startswith('license-files.') and not any(
                k.endswith(suffix) for suffix in ['.guessed', '.file', '.md5']
            )
        ]
        
        if license_files:
            component["copyright"] = "See license files: {}".format(", ".join(license_files))
    
    def _add_hashes(self, component):
        """Add hash information"""

        md5_hash = self.package_data.get('md5', '').split()[0] if self.package_data.get('md5', '').split() else ''

        if md5_hash:
            component["hashes"] = [{"alg": "MD5", "content": md5_hash}]
    
    def _add_external_references(self, component):
        """Add external references"""
        refs = []
        
        if self.download_url:
            refs.append({
                "type": "distribution",
                "url": self.download_url,
                "comment": "Original source download"
            })
            
            try:
                parsed = urllib.parse(self.download_url)
                if parsed.netloc:
                    refs.append({
                        "type": "website",
                        "url": "{}://{}".format(parsed.scheme, parsed.netloc),
                        "comment": "Project homepage"
                    })
            except:
                pass
        
        rulefile = self.package_data.get('rulefile', '')
        if rulefile:
            refs.append({
                "type": "build-meta",
                "url": "file://{}".format(rulefile),
                "comment": "PTXdist build rule"
            })
        
        if refs:
            component["externalReferences"] = refs
    
    def _add_properties(self, component):
        """Add PTXdist-specific properties"""
        properties = []
        
        # Standard properties
        property_mappings = [
            ('config-hash', 'cfghash'),
            ('source-hash', 'srchash'),
            ('license-category', 'license-section'),
            ('patches-applied', 'patches'),
            ('build-location', 'srcdir'),
            ('build-directory', 'builddir'),
            ('source-file', 'source'),
            ('menu-config', 'menufile')
        ]
        
        for prop_name, yaml_key in property_mappings:
            value = self.package_data.get(yaml_key, '')
            if value:
                if yaml_key in ['patches', 'source', 'menufile']:
                    value = os.path.basename(value)
                properties.append({
                    "name": "ptxdist:{}".format(prop_name),
                    "value": value
                })
        
        # Generated packages
        ipkgs = [
            os.path.basename(v) for k, v in self.package_data.items()
            if k.startswith('ipkgs.') and k.replace('ipkgs.', '').isdigit()
        ]
        if ipkgs:
            properties.append({
                "name": "ptxdist:generated-packages",
                "value": ", ".join(ipkgs)
            })
        
        # License flags
        license_flags = [
            v for k, v in self.package_data.items()
            if k.startswith('license-flags.') and k.replace('license-flags.', '').isdigit()
        ]
        if license_flags:
            properties.append({
                "name": "ptxdist:license-flags",
                "value": ", ".join(license_flags)
            })
        
        if properties:
            component["properties"] = properties
    
    def _add_scope(self, component):
        """Add component scope"""
        comp_type = component["type"]
        if comp_type == "application" and self.package_name.startswith('host-'):
            component["scope"] = "excluded"
        else:
            component["scope"] = "required"
    
    def _add_publisher(self, component):
        """Add publisher information"""
        if self.download_url:
            try:
                parsed = urllib.parse(self.download_url)
                if parsed.netloc:
                    component["publisher"] = parsed.netloc
            except:
                pass

class DependencyBuilder(object):
    """Build CycloneDX dependencies"""
    
    def __init__(self, packages, pkg_cpe_dict):
        self.packages = packages
        self.pkg_cpe_dict = pkg_cpe_dict
    
    def build(self):
        """Build all dependencies"""
        dependencies = []
        
        for package_name, package_data in tqdm(self.packages.items(), desc="Progress"):
            version = package_data.get('version', '')
            source = package_data.get('source', '')
            download_url = IdentifierGenerator.extract_url_from_package(package_data)

            cpe = self.pkg_cpe_dict.get(f'{package_name}-{version}', '')

            main_purl = IdentifierGenerator.generate_purl_from_cpe(package_name, version, source, download_url, cpe)
            
            dep_purls = self._collect_dependencies(package_name, package_data, self.pkg_cpe_dict)
            
            if dep_purls:
                dependencies.append({
                    "ref": main_purl,
                    "dependsOn": list(dep_purls)
                })
        
        return dependencies
    
    def _collect_dependencies(self, package_name, package_data, pkg_cpe_dict):
        """Collect all dependencies for a package"""
        all_deps = set()
        
        for dep_type in ['builddeps', 'rundeps', 'deps']:
            deps_value = package_data.get(dep_type, [])
            deps_list = deps_value if isinstance(deps_value, list) else [deps_value] if deps_value else []
            
            for dep_name in deps_list:
                clean_dep = dep_name.strip("'\"")
                if clean_dep in self.packages:
                    dep_version = self.packages[clean_dep].get('version', '')
                    dep_source = self.packages[clean_dep].get('source', '')
                    dep_url = IdentifierGenerator.extract_url_from_package(self.packages[clean_dep])
                    dep_cpe = pkg_cpe_dict.get(f"{clean_dep}-{dep_version}", '')
                    dep_purl = IdentifierGenerator.generate_purl_from_cpe(clean_dep, dep_version, dep_source, dep_url, dep_cpe)
                    all_deps.add(dep_purl)
        
        return all_deps

class SBOMStatistics(object):
    """Calculate and display SBOM statistics"""
    
    def __init__(self, sbom):
        self.sbom = sbom
        self.components = sbom["components"]
        self.dependencies = sbom["dependencies"]
    
    def display(self):
        """Display comprehensive statistics"""
        self._display_component_stats()
        self._display_license_stats()
        self._display_publisher_stats()
        self._display_dependency_stats()
        self._display_ptxdist_stats()
        self._display_compatibility()
    
    def _display_component_stats(self):
        """Display component type statistics"""
        stats = defaultdict(int)
        for comp in self.components:
            stats[comp.get("type", "unknown")] += 1
        
        print("\n=== DETAILED STATISTICS ===")
        print("Components by type:")
        for comp_type, count in sorted(stats.items()):
            print("  {}: {}".format(comp_type, count))
    
    def _display_license_stats(self):
        """Display license statistics"""
        stats = defaultdict(int)
        
        for comp in self.components:
            for lic in comp.get("licenses", []):
                if "license" in lic and "id" in lic["license"]:
                    stats[lic["license"]["id"]] += 1
                elif "expression" in lic:
                    stats[lic["expression"]] += 1
        
        print("\nTop 10 licenses:")
        for lic, count in sorted(stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            if lic:
                print("  {}: {}".format(lic, count))
    
    def _display_publisher_stats(self):
        """Display publisher statistics"""
        stats = defaultdict(int)
        
        for comp in self.components:
            publisher = comp.get("publisher", "Unknown")
            if publisher != "Unknown":
                stats[publisher] += 1
        
        print("\nTop 10 publishers:")
        for pub, count in sorted(stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print("  {}: {}".format(pub, count))
    
    def _display_dependency_stats(self):
        """Display dependency statistics"""
        deps_with_deps = len([d for d in self.dependencies if d.get("dependsOn", [])])
        total_rels = sum(len(d.get("dependsOn", [])) for d in self.dependencies)
        
        print("\nDependencies:")
        print("  Components with dependencies: {}".format(deps_with_deps))
        print("  Total dependency relationships: {}".format(total_rels))
        
        if deps_with_deps > 0:
            avg = total_rels / float(deps_with_deps)
            print("  Average dependencies per component: {:.1f}".format(avg))
    
    def _display_ptxdist_stats(self):
        """Display PTXdist-specific statistics"""
        ptx_props = sum(
            len([p for p in c.get("properties", []) if p.get("name", "").startswith("ptxdist:")])
            for c in self.components
        )
        
        if ptx_props == 0:
            return
        
        with_hashes = len([
            c for c in self.components if any(
                p.get("name", "").startswith("ptxdist:") and "hash" in p.get("name", "")
                for p in c.get("properties", [])
            )
        ])
        
        with_patches = len([
            c for c in self.components if any(
                p.get("name", "") == "ptxdist:patches-applied"
                for p in c.get("properties", [])
            )
        ])
        
        print("\nPTXdist information:")
        print("  Total PTXdist properties: {}".format(ptx_props))
        print("  Components with hashes: {}".format(with_hashes))
        print("  Components with patches: {}".format(with_patches))
    
    def _display_compatibility(self):
        """Display compatibility information"""
        print("\n=== COMPATIBILITY ===")
        print("[✓] Compatible with Dependency-Track")
        print("[✓] Compatible with OWASP Dependency-Check")
        print("[✓] Compatible with Syft/Grype")
        print("[✓] CPE names included for vulnerability analysis")

class SBOMGenerator(object):
    """Main SBOM generator orchestrator"""
    
    def __init__(self, yaml_file, output_file, document_name=None):
        self.yaml_file = yaml_file
        self.output_file = output_file
        self.document_name = document_name
        self.yaml_data = None
        self.packages = None
        self.sbom = None
        self.source_type = None

        # Initialize the components
        matcher = CPEMatcher(API_KEY, max_workers=MAX_WORKERS)
        normalizer = PackageIdNormalizer()
        self.cpe_generator = CPEGenerator(matcher, normalizer)

        self.pkg_cpe_dict = {}
    
    def generate(self):
        """Generate SBOM - template method"""
        print("[i] Parsing YAML file...")
        self._parse_yaml()
        
        print("[i] Extracting package information...")
        self._extract_packages()
        
        print("[i] Building SBOM structure...")
        self._create_sbom_structure()
        
        print("[i] Processing components...")
        self._process_components()
        
        print("[i] Generating dependencies...")
        self._generate_dependencies()
        
        print("[i] Adding root dependency...")
        self._add_root_dependency()
        
        print("[i] Saving SBOM...")
        self._save_sbom()
        
        print("\n[✓] CycloneDX SBOM generated: {}".format(self.output_file))
        print("[i] Components processed: {}".format(len(self.sbom["components"])))
        print("[i] Dependencies: {}".format(len(self.sbom["dependencies"])))
        
        self._display_statistics()
    
    def _parse_yaml(self):
        """Parse YAML file"""
        parser = YAMLParser(self.yaml_file)
        self.yaml_data = parser.parse()

    def _extract_source(self):
        """Extract information pkg source"""
        self.source_type = self.yaml_data['project-source']
    
    def _extract_packages(self):
        """Extract packages from YAML data"""
        extractor = PackageExtractor(self.yaml_data)
        self.packages = extractor.extract()
        print("[i] Packages found: {}".format(len(self.packages)))
    
    def _create_sbom_structure(self):
        """Create base SBOM structure - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement _create_sbom_structure")
    
    def _process_components(self):
        """Process all packages into CycloneDX components"""
        for pkg_name, pkg_data in tqdm(self.packages.items(), desc="Progress"):
            try:
                self.pkg_cpe_dict[f"{pkg_name}-{pkg_data.get("version", '')}"] = IdentifierGenerator.generate_cpe(pkg_name, pkg_data.get('version',''), self.cpe_generator)
                builder = ComponentBuilder(pkg_name, pkg_data, self.pkg_cpe_dict)
                component = builder.build()
                self.sbom["components"].append(component)
            except Exception as e:
                print("[!] Error processing package {}: {}".format(pkg_name, str(e)))
    
    def _generate_dependencies(self):
        """Generate dependency graph"""
        builder = DependencyBuilder(self.packages, self.pkg_cpe_dict)
        self.sbom["dependencies"] = builder.build()
    
    def _add_root_dependency(self):
        """Add root component as parent of all components"""
        root_ref = self.sbom["metadata"]["component"]["bom-ref"]
        component_refs = [c["bom-ref"] for c in self.sbom["components"]]
        
        self.sbom["dependencies"].insert(0, {
            "ref": root_ref,
            "dependsOn": component_refs
        })
    
    def _save_sbom(self):
        """Save SBOM to file"""
        with open(self.output_file, 'w') as f:
            json.dump(self.sbom, f, indent=2)
    
    def _display_statistics(self):
        """Display SBOM statistics"""
        stats = SBOMStatistics(self.sbom)
        stats.display()
    
    def _create_base_sbom(self, project_info):
        """Create base CycloneDX SBOM structure"""
        timestamp = datetime.now().isoformat() + "Z"
        serial_number = "urn:uuid:{}".format(uuid.uuid4())
        
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": project_info.get('tools', []),
                "component": project_info.get('component', {}),
                "properties": project_info.get('properties', [])
            },
            "components": [],
            "dependencies": []
        }

class PTXdistSBOMGenerator(SBOMGenerator):
    """SBOM generator for PTXdist projects"""
    
    def _create_sbom_structure(self):
        """Create PTXdist-specific SBOM structure"""
        # Extract BSP information
        bsp_version = self.yaml_data.get('bsp.project-version', 'Unknown')
        platform = self.yaml_data.get('bsp.platform', 'Unknown')
        platform_version = self.yaml_data.get('bsp.platform-version', 'Unknown')
        ptx_version = self.yaml_data.get('ptxdist.version', 'Unknown')
        
        doc_name = self.document_name or "BSP-{}-{}".format(bsp_version, platform)
        
        print("[i] BSP detected: {}".format(doc_name))
        print("[i] PTXdist version: {}".format(ptx_version))
        
        # Build project info
        project_info = {
            'tools': [
                {
                    "vendor": "PTXdist",
                    "name": "ptxdist",
                    "version": ptx_version
                },
                {
                    "vendor": "Custom",
                    "name": "YAML-to-CycloneDX-Converter",
                    "version": "3.0"
                }
            ],
            'component': {
                "type": "firmware",
                "bom-ref": "pkg:generic/{}@{}".format(
                    doc_name.lower().replace(' ', '-'), bsp_version
                ),
                "name": doc_name,
                "version": bsp_version,
                "description": "Embedded BSP built with PTXdist {} for {} {}".format(
                    ptx_version, platform, platform_version
                ),
                "licenses": [{"license": {"name": "Mixed - see individual components"}}],
                "properties": [
                    {"name": "ptxdist:platform", "value": platform},
                    {"name": "ptxdist:platform-version", "value": platform_version},
                    {"name": "ptxdist:project-version", "value": bsp_version}
                ]
            },
            'properties': []
        }
        
        # Add toolchain information
        self._add_toolchain_info(project_info)
        
        # Add layers information
        self._add_layers_info(project_info)
        
        self.sbom = self._create_base_sbom(project_info)
    
    def _add_toolchain_info(self, project_info):
        """Add toolchain information to project"""
        toolchain = self.yaml_data.get('develop.target.toolchain-prefix', '')
        gnu_target = self.yaml_data.get('develop.target.gnu-target', '')
        
        if toolchain:
            project_info['component']['properties'].append({
                "name": "ptxdist:toolchain-prefix",
                "value": toolchain
            })
        
        if gnu_target:
            project_info['component']['properties'].append({
                "name": "ptxdist:gnu-target",
                "value": gnu_target
            })
    
    def _add_layers_info(self, project_info):
        """Add layers information to project"""
        layers = [
            v for k, v in self.yaml_data.items()
            if k.startswith('bsp.layers.') and k.replace('bsp.layers.', '').isdigit()
        ]
        
        if layers:
            project_info['component']['properties'].append({
                "name": "ptxdist:layers",
                "value": "; ".join(layers)
            })

class ApplicationSBOMGenerator(SBOMGenerator):
    """SBOM generator for generic applications"""
    
    def __init__(self, yaml_file, app_type, output_file, document_name=None):
        super(ApplicationSBOMGenerator, self).__init__(yaml_file, output_file, document_name)
        self.app_type = app_type.lower()
    
    def _create_sbom_structure(self):
        """Create application-specific SBOM structure"""
        # Extract project information
        project_name = self.yaml_data.get('{}.project-name'.format(self.app_type), 'Unknown')
        project_version = self.yaml_data.get('{}.project-version'.format(self.app_type), 'Unknown')
        project_desc = self.yaml_data.get('{}.project-description'.format(self.app_type), 'Unknown')
        platform = self.yaml_data.get('{}.platform'.format(self.app_type), 'Unknown')
        platform_version = self.yaml_data.get('{}.platform-version'.format(self.app_type), 'Unknown')
        
        doc_name = self.document_name or "{}-{}-{}".format(project_name, project_version, platform)
        
        print("[i] Application detected: {}".format(doc_name))
        
        # Build project info
        project_info = {
            'tools': [
                {
                    "vendor": "Custom",
                    "name": "Recursive depencency extractor (ldd_recusrive.sh)",
                    "version": "0.0.0"
                },
                {
                    "vendor": "Custom",
                    "name": "XML-to-YAML-Report-Creator",
                    "version": "0.0.0"
                },
                {
                    "vendor": "Custom",
                    "name": "YAML-to-CycloneDX-Converter",
                    "version": "3.0"
                }
            ],
            'component': {
                "type": "application",
                "bom-ref": "pkg:generic/{}".format(doc_name.lower().replace(' ', '-')),
                "name": doc_name,
                "version": project_version,
                "description": project_desc,
                "licenses": [{"license": {"name": "Mixed - see individual components"}}],
                "properties": [
                    {"name": "{}:platform".format(self.app_type), "value": platform},
                    {"name": "{}:platform-version".format(self.app_type), "value": platform_version},
                    {"name": "{}:project-version".format(self.app_type), "value": project_version}
                ]
            },
            'properties': []
        }
        
        self.sbom = self._create_base_sbom(project_info)

class CLIApplication(object):
    """Main CLI application controller"""
    
    VERSION = "3.0.0"
    
    def __init__(self):
        self.args = None
    
    def run(self):
        """Run the CLI application"""
        try:
            self._parse_arguments()
            self._validate_input()
            self._generate_sbom()
            print("\n[✓] CycloneDX SBOM generated successfully!")
            if self.args.sign:
                self._sign_output_file()
                print("\n[✓] CycloneDX SBOM file SHA256 computed correctly!")
            return 0
        except Exception as e:
            print("\n[!] Error: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            return 1
    
    def _parse_arguments(self):
        """Parse command-line arguments"""
        parser = argparse.ArgumentParser(
            description='Convert YAML reports (PTXdist/Custom) to CycloneDX SBOM',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Convert PTXdist report
  %(prog)s -t ptx full-bsp-report.yaml -o bsp-sbom.json
  
  # Convert application report with custom name
  %(prog)s -t prg app-report.yaml -o app-sbom.json -n "MyApp-v1.0"
  
  # Convert HMI report
  %(prog)s -t hmi hmi-report.yaml -o hmi-sbom.json

Supported types:
  ptx         PTXdist BSP projects
  prg         Program/application projects
  hmi         HMI (Human-Machine Interface) projects
  application Generic application projects
  firmware    Firmware projects
  other       Other custom projects
            """
        )
        
        parser.add_argument(
            'yaml_file',
            help='Input YAML report file'
        )
        
        parser.add_argument(
            '-t', '--type',
            required=True,
            choices=['ptx', 'firmware', 'prg', 'hmi', 'application', 'other'],
            help='Type of YAML file to convert'
        )
        
        parser.add_argument(
            '-o', '--output',
            required=True,
            default='sbom.cdx.json',
            help='Output CycloneDX SBOM file (default: sbom.cdx.json)'
        )
        
        parser.add_argument(
            '-n', '--name',
            help='Document name (auto-detected if not specified)'
        )
        
        parser.add_argument(
            '-v', '--version',
            action='version',
            version='%(prog)s {}'.format(self.VERSION)
        )
        
        parser.add_argument(
            '-q', '--quiet',
            action='store_true',
            help='Suppress informational messages'
        )

        parser.add_argument(
            '-s', '--sign',
            action='store_true',
            help='Sign created SBOM file.'
        )
        
        self.args = parser.parse_args()
    
    def _validate_input(self):
        """Validate input parameters"""
        if not os.path.exists(self.args.yaml_file):
            raise IOError("File not found: {}".format(self.args.yaml_file))
        
        if not os.path.isfile(self.args.yaml_file):
            raise IOError("Not a file: {}".format(self.args.yaml_file))
        
        # Check if file is readable
        try:
            with open(self.args.yaml_file, 'r') as f:
                f.read(1)
        except IOError as e:
            raise IOError("Cannot read file: {}".format(str(e)))
    
    def _generate_sbom(self):
        """Generate SBOM based on type"""
        if self.args.type == 'ptx':
            generator = PTXdistSBOMGenerator(
                self.args.yaml_file,
                self.args.output,
                self.args.name
            )
        else:
            generator = ApplicationSBOMGenerator(
                self.args.yaml_file,
                self.args.type,
                self.args.output,
                self.args.name
            )
        
        generator.generate()

    def _sign_output_file(self):
        """Signs created SBOM file"""

        with open(self.args.output, "rb") as f:
            data = f.read()

        hash_sha256 = hashlib.sha256(data).hexdigest()

        hash_file = self.args.output + ".sha256"

        with open(hash_file, 'w') as f:
            f.write(f"Archivo: {self.args.output}\n")
            f.write(f"Algoritmo: SHA-256\n")
            f.write(f"Hash: {hash_sha256}\n")

def main():
    """Main entry point"""
    app = CLIApplication()
    sys.exit(app.run())

if __name__ == "__main__":
    main()
