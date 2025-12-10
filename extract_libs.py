#!/usr/bin/env python3
"""
Dependency Analyzer - Analiza dependencias de componentes desde archivos XML

Este script procesa archivos XML generados por ldd_recursive.sh y analiza
las dependencias entre componentes, permitiendo exportar los resultados
en múltiples formatos (JSON, YAML, texto).
"""

import xml.etree.ElementTree as ET
from collections import defaultdict
from rapidfuzz import process, fuzz
import json
import yaml
import argparse
import sys
import os
import re
import signal

from abc import ABC, abstractmethod
from typing import Dict, Any, Callable, Optional, List, Set
from lxml import etree
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()
DEFAULT_XML_SCHEMA = os.environ.get("XML_SCHEMA") or ''
DEFAULT_LIBS_DIR = os.environ.get("LIBS_DIR") or ''
DEFAULT_PTX_REPORT = os.environ.get("PTX_REPORT") or ''

DEFAULT_THRESHOLD = 80.0

VERSION = '0.0.0'

def print_banner():
    """Imprime el banner del programa"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║              Extraer paquetes desde listado de librerías (XML)           ║
║                              Versión {VERSION}                               ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_examples():
    """Imprime ejemplos de uso del programa"""
    examples = '''
    USE EXAMPLES:
    ═══════════════════════════════════════════════════════════════
    # Procesamiento de archivos XML (generados por ./ldd_recursive.sh)
    %(prog)s xml file.xml                                    # Análisis básico en terminal
    %(prog)s xml file.xml -j output.json                     # Exportar solo JSON
    %(prog)s xml file.xml -t report.txt                      # Exportar solo reporte texto
    %(prog)s xml file.xml -y deps.yaml                       # Exportar solo YAML
    %(prog)s xml file.xml -j deps.json -t deps.txt           # Exportar múltiples formatos
    %(prog)s xml file.xml --no-console                       # Sin salida en terminal
    %(prog)s xml file.xml -s                                 # Solo resumen
    %(prog)s xml file.xml -m                                 # Crear mapeo lib->pkg
    %(prog)s xml file.xml --lib-lists /path/to/dir           # Usar directorios con mapeos
    %(prog)s xml file.xml --bsp-report base_report.yaml      # Usar reporte BSP del sistema base
    
    # Procesamiento de archivos DPKG
    %(prog)s dpkg dpkg_status --dpkg-name "Sistema" --dpkg-vers "1.0"  # Análisis DPKG
    %(prog)s dpkg dpkg_status -j output.json                           # Exportar a JSON
    %(prog)s dpkg dpkg_status -y deps.yaml                             # Exportar a YAML
        '''
    print(examples)

# ============================================================================
# MAPPING SYSTEM
# ============================================================================

class MappingLoader:
    """
    Clase genérica para cargar mapeos desde diferentes fuentes.
    """
    
    @staticmethod
    def _load_from_source(source: str, 
                        loader_func,  # json.load o yaml.safe_load
                        pattern: str,  # "*.json" o "*.yaml"
                        mapping_extractor) -> Dict[str, str]:
        """Método genérico para cargar desde archivos o directorios."""
        mapping = {}
        path = Path(source)

        if not path.exists():
            print(f"[!] Warning: Source not found '{source}'", file=sys.stderr)
            return mapping

        files_to_process = []
        if path.is_dir():
            files_to_process = list(path.glob(pattern))
        elif path.is_file():
            files_to_process = [path]
        
        for file in files_to_process:
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = loader_func(f)
                    file_mapping = mapping_extractor(data)
                    mapping.update(file_mapping)
            except Exception as e:
                print(f"[!] Error loading {file}: {e}", file=sys.stderr)
        
        return mapping

    @staticmethod
    def from_json(source: str, mapping_extractor: Callable[[Dict], Dict[str, str]]) -> Dict[str, str]:
        """
        Cargar datos para mapeos desde archivos JSON.
        """

        return MappingLoader._load_from_source(source, json.load, "*.json", mapping_extractor)
    
    @staticmethod
    def from_yaml(source: str, mapping_extractor: Callable[[Dict], Dict[str, str]]) -> Dict[str, str]:
        """
        Cargar datos para mapeos desde archivos YAML.
        """
        return MappingLoader._load_from_source(source, yaml.safe_load, "*.yaml", mapping_extractor)


class FuzzyMapper:
    """
    Clase para realizar búsquedas en mapeos con coincidencia exacta o aproximada.
    """
    
    def __init__(self, mapping: Dict[str, str], threshold: float = DEFAULT_THRESHOLD):
        self.mapping = mapping
        self.threshold = threshold
    
    def find_by_key(self, key: str, default: str = 'unknown') -> str:
        """
        Busca un valor por clave con coincidencia exacta o aproximada.
        """
        if not key or key == 'unknown':
            return default
        
        if key in self.mapping:
            return self.mapping[key]
        
        if not self.mapping: 
            return default
        
        key_norm = key.lower().strip()
        mapping_norm = {k.lower().strip(): v for k, v in self.mapping.items()}
        
        result = process.extractOne(key_norm, mapping_norm, scorer=fuzz.ratio)
        
        if result:
            best_match, score = result[0], result[1]
            if float(score) >= self.threshold:
                return self.mapping[best_match]
        
        return default
    
    def find_by_value(self, value: str, default: str = 'unknown') -> str:
        """
        Busca una clave por valor con coincidencia exacta o aproximada.
        """
        if not value or value == 'unknown':
            return default
        
        if value in self.mapping.values():
            return next((k for k, v in self.mapping.items() if v == value), default)
        
        if not self.mapping:
            return default
        
        result = process.extractOne(value, self.mapping.values(), scorer=fuzz.ratio)
        
        if result:
            best_match, score = result[0], result[1]
            if float(score) >= self.threshold:
                return next((k for k, v in self.mapping.items() if v == best_match), default)
        
        return default
    
    def find_all_by_keys(self, keys: List[str]) -> Dict[str, str]:
        return {key: self.find_by_key(key) for key in keys}
    
    def find_all_by_values(self, values: List[str]) -> Dict[str, str]:
        return {self.find_by_value(value): value for value in values}
    
    def update_mapping(self, new_mapping: Dict[str, str]):
        self.mapping.update(new_mapping)


def create_libs_to_packages_mapping(directory: str) -> Dict[str, str]:
    """
    Crea mapeo de bibliotecas (filename.so) a directorio de paquetes (dirnames) desde archivos JSON.
    """
    def extract_mapping(data):
        mapping = {}
        for pkg in data.get("packages", []):
            pkg_name = pkg.get("package")
            if not pkg_name:
                continue
            for lib in pkg.get("libraries", []):
                if lib:
                    mapping[lib] = pkg_name
        return mapping
    
    return MappingLoader.from_json(directory, extract_mapping)


def create_pkgdirname_to_pkg_mapping(yaml_path: str) -> Dict[str, str]:
    """
    Crea mapeo de nombres de directorio de paquetes a nombres de paquetes.
    """
    def extract_mapping(data):
        mapping = {}
        packages_dict = data.get('packages', {})
        
        for key, value in packages_dict.items():
            pkgdir = value.get("pkgdir")
            if pkgdir:
                new_key = os.path.basename(pkgdir)
            else:
                name = value.get("name")
                version = value.get("version")
                new_key = f"{name}-{version}" if version else name
            
            mapping[new_key] = key
        
        return mapping
    
    return MappingLoader.from_yaml(yaml_path, extract_mapping)

class BaseExporter(ABC):
    
    def __init__(self, components_dict: Dict[str, Any]):
        self.components_dict = components_dict
    
    @abstractmethod
    def export(self, output_file: str) -> Any:
        pass
    
    def _get_sorted_components(self):
        return sorted(self.components_dict.items())


class JSONExporter(BaseExporter):
    """
    Exporta componentes y dependencias a formato JSON.
    """
    
    def export(self, output_file: str = 'dependencies.json') -> Dict[str, Any]:
        json_data = {
            "total_components": len(self.components_dict),
            "components": []
        }
        
        for key, data in self._get_sorted_components():
            component_data = {
                "name": data['name'],
                "type": data['type'],
                'level': data['level'],
                "version": data['version'],
                "filename": data['filename'],
                "id": key,
                "pkg_id": data['pkg_id'],
                "pkgdir_id": data['pkgdir_id'],
                "dependencies_count": len(data['dependencies']),
                "dependencies": sorted(data['dependencies'])
            }
            
            json_data['components'].append(component_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        return json_data


class YAMLExporter(BaseExporter):
    """
    Exporta componentes y dependencias a formato YAML (PtxDist Report format).
    """
    def __init__(self, components_dict: Dict[str, Any], ptx_report_path: str = DEFAULT_PTX_REPORT, source_type: str = ''):
        super().__init__(components_dict)
        self.ptx_report_path = ptx_report_path
        self._load_ptx_data()

        self.source_type = 'deb' if source_type == 'dpkg' else 'generic'
    
    def _load_ptx_data(self):
        if not Path(self.ptx_report_path).exists():
            print(f"[!] Advertencia: Archivo PTX no encontrado '{self.ptx_report_path}'", file=sys.stderr)
            self.ptx_yaml_data = {'bsp': {'platform': 'unknown', 'platform-version': 'unknown'}, 'packages': {}}
            return
        
        with open(self.ptx_report_path, 'r', encoding='utf-8') as f:
            self.ptx_yaml_data = yaml.safe_load(f)
    
    def _get_app_info(self, data: Dict) -> tuple:
        """
        Extrae información de la aplicación.
        """
        app_name = data.get('name', 'unknown').strip().upper()
        app_vers = data.get('version', 'unknown')
        
        if app_name.startswith(("FPP", "TSP", "TFP", "VTP", "RTP")):
            return "prg", f"Machine control application {app_name}-v{app_vers}"
        elif app_name.startswith(("FPV", "TSV", "TFV", "VTV", "RTV")):
            return "hmi", f"Machine visualization application {app_name}-v{app_vers}"
        elif "BSP" in app_name or 'DPKG' in app_name or 'LINUX' in app_name or 'DEBIAN' in app_name:
            return "firmware", f"Machine custom firmware or BSP {app_name}-v{app_vers}"
        else:
            return "application", f"Machine custom application {app_name}-v{app_vers}"
    
    def _build_base_structure(self, app_data: Dict, app_type: str, app_description: str) -> Dict:
        """
        Construye la estructura base del YAML.
        """
        app_name = app_data.get('name', 'unknown').strip().upper()
        app_vers = app_data.get('version', 'unknown')
        
        return {
            "python_script": {
                "version": sys.version,
                "path": os.getcwd(),
            },
            app_type: {
                "project-name": app_name,
                "project-version": app_vers,
                "project-description": app_description,
                "project-source": self.source_type, 
                "platform": self.ptx_yaml_data.get('bsp', {}).get('platform', 'unknown'),
                "platform-version": self.ptx_yaml_data.get('bsp', {}).get('platform-version', 'unknown')
            },
            "packages": {}
        }
    
    def _add_package_from_dependency(self, yaml_data: Dict, dep_data: Dict):
        """
        Añade un paquete al YAML desde una dependencia.
        """
        pkg_id = dep_data.get('pkg_id', '')
        pkg_src = dep_data.get('pkg_src', '')
        pkg_md5 = dep_data.get('pkg_md5', '')
        pkg_sha1 = dep_data.get('pkg_sha1', '')
        pkg_sha256 = dep_data.get('pkg_sha256', '')
        pkg_sha512 = dep_data.get('pkg_sha512', '')
        
        if not pkg_id or pkg_id == 'unknown':
            pkgdir_id = dep_data.get('pkgdir_id', '')
            if not pkgdir_id or pkgdir_id == 'unknown':
                return
            
            match = re.match(r'^(.+?)-(\d+[\.:].*?)$', pkgdir_id)

            if match:
                pkg_name, pkg_vrs = match.groups()
            else:
                pkg_name, pkg_vrs = pkgdir_id, 'unknown'
            
            if pkg_name not in yaml_data['packages']:
                yaml_data['packages'][pkg_name] = {
                    "name": pkg_name,
                    "version": pkg_vrs,
                    "source": pkg_src,
                    "md5": pkg_md5,
                    "sha1": pkg_sha1,
                    "sha256": pkg_sha256,
                    "sha512": pkg_sha512,
                    "deps": []
                }

        else:
            if pkg_id not in yaml_data['packages']:
                packages = self.ptx_yaml_data.get("packages", {})
                if pkg_id in packages:
                    subfields = ["name", "version", "url", "md5", "licensed"]
                    yaml_data["packages"][pkg_id] = {
                        k: v for k, v in packages[pkg_id].items() 
                        if k in subfields
                    }
                    yaml_data["packages"][pkg_id]["deps"] = []


    def _process_application_dependencies(self) -> Dict:
        """
        Procesa las dependencias de la aplicaión principal y las añade al YAML.
        """
                
        yaml_data = {}
        
        # Find principal or base application that contains the packages.
        for key, data in self._get_sorted_components():
            if data.get('level', '') == 'root':
                app_type, app_description = self._get_app_info(data)
                yaml_data = self._build_base_structure(data, app_type, app_description)
                
                # Procesar las dependencias de la aplicación.
                for dep in data.get('dependencies', []):
                    for key_dep, data_dep in self._get_sorted_components():
                        if key_dep == dep:
                            self._add_package_from_dependency(yaml_data, data_dep)
                            break
                break
        
        # Si no hay aplicación principal crea una estructura default.
        if not yaml_data:
            bsp = self.ptx_yaml_data.get('bsp', {})
            yaml_data = {
                'unknown': {
                    "project-version": 'unknown',
                    "platform": bsp.get('platform', 'unknown'),
                    "platform-version": bsp.get('platform-version', 'unknown'),
                },
                "packages": {}
            }

        return yaml_data
    
    def _process_library_dependencies(self, yaml_data: Dict):
        """
        Procesa las dependencias de cada paquete de la aplicación y las añade al YAML
        """
        for key, data in self._get_sorted_components():
            
            if data.get("type", "") == "library":
                # Obtain package name
                pkg_id = data.get('pkg_id', '')
                if not pkg_id or pkg_id == 'unknown':
                    pkgdir_id = data.get('pkgdir_id', '')
                    if not pkgdir_id or pkgdir_id == 'unknown':
                        continue

                    match = re.match(r'^(.+?)-(\d+[\.:].*?)$', pkgdir_id)
                    
                    if match:
                        pkg_name, pkg_vrs = match.groups()
                    else:
                        pkg_name, pkg_vrs = pkgdir_id, 'unknown'

                else:
                    pkg_name = pkg_id
            else:
                pkg_name = data.get('name', '')           
            
            if pkg_name not in yaml_data['packages']:
                continue
            
            # Collect all package dependencies.
            pkg_deps = set()
            for lib_dep in data.get('dependencies', []):
                for key_deps, data_deps in self._get_sorted_components():
                    if lib_dep == key_deps:

                        if data_deps.get("type", "") == "library":
                            dep_pkg_id = data_deps.get('pkg_id', '')
                            if not dep_pkg_id or dep_pkg_id == 'unknown':
                                pkg_dep_dir = data_deps.get('pkgdir_id', '')
                                match = re.match(r'^(.*?)-([0-9].*)$', pkg_dep_dir)
                                if match:
                                    pkg_dep_name, _ = match.groups()
                                else:
                                    pkg_dep_name= pkg_dep_dir
                            else:
                                pkg_dep_name = dep_pkg_id

                        else:
                            pkg_dep_name = data_deps.get("name", "")

                        if pkg_dep_name and pkg_dep_name != 'unknown' and pkg_dep_name != pkg_name:
                            pkg_deps.add(pkg_dep_name)
                        break
            
            yaml_data['packages'][pkg_name]["deps"] = list(pkg_deps.union(yaml_data['packages'][pkg_name]["deps"]))
    
    def export(self, output_file: str = 'dependencies.yaml') -> Dict[str, Any]:
        """
        Exportar los datos a un fichero YAML tipo PTXdist Report.
        """

        # Procesar las dependencias principales de la aplicación
        yaml_data = self._process_application_dependencies()
        
        # Process Procesar dependencias de cada paquete dentro de la aplicación principal
        self._process_library_dependencies(yaml_data)
        
        # Guardar archivo
        with open(output_file, "w", encoding='utf-8') as f:
            yaml.dump(yaml_data, f, sort_keys=False, allow_unicode=True)
        
        return yaml_data


class TextExporter(BaseExporter):
    """
    Exporta análisis completo a formato texto.
    """
    
    def print_components_summary(self, file_handle):
        """Imprime resumen de componentes únicos."""
        print("=" * 80, file=file_handle)
        print("UNIQUE COMPONENTS FOUND", file=file_handle)
        print("=" * 80, file=file_handle)
        print(f"\nTotal unique components found: {len(self.components_dict)}\n", 
              file=file_handle)
        
        for i, (key, data) in enumerate(self._get_sorted_components(), 1):
            print(f"{i}. {data['name']} (v{data['version']})", file=file_handle)
            print(f"   File: {data['filename']}", file=file_handle)
            print(f"   Type: {data['type']}", file=file_handle)
            print(f"   Internal ID: {key}", file=file_handle)
            print(f"   Package DName ID: {data['pkgdir_id']}", file=file_handle)
            print(f"   Package ID: {data['pkg_id']}", file=file_handle)
            print(f"   Number of Dependencies: {len(data['dependencies'])}", 
                  file=file_handle)
            print(file=file_handle)
    
    def print_dependencies_detail(self, file_handle):
        """Imprime detalles de dependencias por componente."""
        print("=" * 80, file=file_handle)
        print("DEPENDENCIES PER COMPONENT", file=file_handle)
        print("=" * 80, file=file_handle)
        
        for key, data in self._get_sorted_components():
            print(f"\n{data['name']} (v{data['version']})", file=file_handle)
            print(f"File: {data['filename']}", file=file_handle)
            print("-" * 80, file=file_handle)
            
            if data['dependencies']:
                print("Dependencias:", file=file_handle)
                for dep in sorted(data['dependencies']):
                    print(f"  → {dep}", file=file_handle)
            else:
                print("No dependencies", file=file_handle)
            print(file=file_handle)
    
    def export(self, output_file: str = 'dependency_analysis.txt') -> None:
        """
        Exporta a archivo de texto.
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            self.print_components_summary(f)
            self.print_dependencies_detail(f)


class ExporterFactory:
    """
    Factory para crear exporters según el tipo solicitado.
    """
    
    @staticmethod
    def create_exporter(export_type: str, 
                       components_dict: Dict[str, Any],
                       **kwargs) -> BaseExporter:
        """
        Crea un exporter del tipo especificado.
        """
        exporters = {
            'json': JSONExporter,
            'yaml': YAMLExporter,
            'text': TextExporter
        }
        
        exporter_class = exporters.get(export_type.lower())
        if not exporter_class:
            raise ValueError(f"Tipo de exporter no soportado: {export_type}")
        
        if export_type.lower() == 'yaml':
            ptx_report_path = kwargs.get('ptx_report_path', DEFAULT_PTX_REPORT)
            return exporter_class(components_dict, ptx_report_path)
        
        return exporter_class(components_dict)


# ============================================================================
# COMPATIBILITY WRAPPERS
# ============================================================================

def export_to_json(components_dict, output_file='dependencies.json'):
    """Wrapper de compatibilidad para export_to_json."""
    exporter = JSONExporter(components_dict)
    return exporter.export(output_file)


def export_to_yaml(components_dict, output_file='dependencies.yaml', source_type=''):
    """Wrapper de compatibilidad para export_to_yaml."""
    exporter = YAMLExporter(components_dict, DEFAULT_PTX_REPORT, source_type)
    return exporter.export(output_file)


def export_to_text(components_dict, output_file='dependency_analysis.txt'):
    """Wrapper de compatibilidad para export_to_text."""
    exporter = TextExporter(components_dict)
    exporter.export(output_file)


def print_components_summary(components_dict):
    """Wrapper de compatibilidad para print_components_summary."""
    exporter = TextExporter(components_dict)
    exporter.print_components_summary(sys.stdout)


def print_dependencies_detail(components_dict):
    """Wrapper de compatibilidad para print_dependencies_detail."""
    exporter = TextExporter(components_dict)
    exporter.print_dependencies_detail(sys.stdout)


# ============================================================================
# COMPONENT PARSER
# ============================================================================

@dataclass
class Component:
    """
    Representa un componente con sus propiedades y dependencias.
    """
    name: str
    version: str
    type: str
    filename: str
    arch: str = 'unknown'
    pkgdir_id: str = 'unknown'
    pkg_id: str = 'unknown'
    pkg_src: str = 'unknown'
    level: str = 'unknown'
    md5: str = ''
    sha1: str = ''
    sha256: str = ''
    sha512: str = ''
    dependencies: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el componente a diccionario."""
        return {
            'name': self.name,
            'version': self.version,
            'type': self.type,
            'level': self.level,
            'filename': self.filename,
            'pkgdir_id': self.pkgdir_id,
            'pkg_id': self.pkg_id,
            'pkg_src': self.pkg_src,
            'pkg_md5': self.md5,
            'pkg_sha1': self.sha1,
            'pkg_sha256': self.sha256,
            'pkg_sha512': self.sha512,
            'arch': self.arch,
            'dependencies': self.dependencies
        }
    
    @property
    def key(self) -> str:
        """Retorna la clave única del componente."""
        return f"{self.name}-v{self.version}"

class DPKGComponentParser:
    """
    Parser para analizar componentes DPKG/status y sus dependencias.
    """

    def __init__(self, libs_mapper=None, pkgs_mapper=None):
        """
        Inicializa el parser.
        """
        self.libs_mapper = libs_mapper
        self.pkgs_mapper = pkgs_mapper
        self.components = {}

    def parse_from_string(self, txt_content: str, dpkg_name: str, dpkg_vers: str) -> Dict[str, Dict[str, Any]]:
        """
        Parsear cadena de texto extraido de DPKG.
        """
        # Inicializar dicts
        sources_provides_dict = {}
        provides_dict = {}
        depends_dict = {}

        # Primeramente dividimos el string en bloques.
        blocks = txt_content.strip().split('\n\n')
        
        for block in blocks:
            lines = block.splitlines()

            block_name = 'unknown'
            block_source = ''
            block_md5 = ''
            block_sha1 = ''
            block_sha256 = ''
            block_sha512 = ''
            block_type = 'unknown'
            block_mantainer = 'unknown'
            block_version = 'unknown'
            block_deps = []
            block_provides = []

            for line in lines:
                if line.startswith(" ") or ":" not in line or not line.strip(): # Checkear que la linea contenga un campo.
                    continue
                
                line_splitted = []
                line_splitted = line.split(':')

                key = line_splitted[0]
                val = ":".join(line_splitted[1:])

                if key == "Package":
                    block_name = val.strip()

                if key == "Source":
                    block_source = val.strip()
                    block_source = "".join(re.sub(r"\s*\(.*?\)", "", block_source)).strip()

                if key == "Section":
                    if val.strip().startswith("kernel"):
                        block_type = "operating_system"
                    else:
                        block_type = "package"

                if key == "MD5sum":
                    block_md5 = val.strip()

                if key == "SHA1":
                    block_sha1 = val.strip()

                if key == "SHA256":
                    block_sha256 = val.strip()

                if key == "SHA512":
                    block_sha512 = val.strip()

                elif key == "Maintainer":
                    block_mantainer  = val.strip()

                elif key == "Version":
                    block_version = val.strip()

                elif key == "Depends":
                    for val_clean in val.split(","):
                        dep_clean = "".join(re.sub(r"\s*\(.*?\)", "", val_clean)).strip()
                        block_deps.append(dep_clean)

                elif key == "Provides":
                    for val_clean in val.split(","):
                        dep_clean = "".join(re.sub(r"\s*\(.*?\)", "", val_clean)).strip()
                        block_provides.append(dep_clean)

            block_provides.append(block_name)

            if block_source:
                source_component = self._create_component(
                    name=block_source,
                    version=block_version if block_version else 'unknown',
                    comp_lvl='dep',
                    source='deb',
                    md5='',
                    sha1='',
                    sha256='',
                    sha512='',
                    comp_type=block_type if block_type else 'unknown',
                    filename=None
                )

                source_component_key = source_component.key
        
                # Si el componente no existe, añadirlo
                if source_component_key not in self.components:
                    self.components[source_component_key] = source_component.to_dict()

                sources_provides_dict.setdefault(source_component_key, [])
                sources_provides_dict[source_component_key] = list(set(sources_provides_dict[source_component_key] + block_provides + [block_source]))

                depends_dict.setdefault(source_component_key, [])
                depends_dict[source_component_key] = list(set(depends_dict[source_component_key] + [block_name]))

            # Crear componente
            component = self._create_component(
                name=block_name,
                version=block_version if block_version else 'unknown',
                comp_lvl='dep',
                source='deb',
                md5=block_md5 if block_md5 else '',
                sha1=block_sha1 if block_sha1 else '',
                sha256=block_sha256 if block_sha256 else '',
                sha512=block_sha512 if block_sha512 else '',
                comp_type=block_type if block_type else 'unknown',
                filename=None
            )

            component_key = component.key
        
            # Si el componente no existe, añadirlo
            if component_key not in self.components:
                self.components[component_key] = component.to_dict()

            provides_dict.setdefault(component_key, [])
            provides_dict[component_key] = list(set(provides_dict[component_key] + block_provides))

            depends_dict.setdefault(component_key, [])
            depends_dict[component_key] = list(set(depends_dict[component_key] + block_deps))


        # Parsear dependencias
        for comp_key, comp_val in self.components.items():
            
            # print(f"Component KEY: {comp_key}")
            
            key_dependencies = depends_dict.get(comp_key, [])

            # print(f"Key DEPS: {key_dependencies}")

            for dep in key_dependencies:

                # print(f"Clean: {dep}")

                alts = [x.strip() for x in dep.split("|")]

                # print(f"Dependency: {alts}")

                for alt in alts:
                    found = False
                    # print(f"Alternative: {alt}")

                    # # Sources provide (introduces source package instead of original package)
                    # for sprov_key, sprov_vallist in sources_provides_dict.items():
                    #     # print(f"Source Provides list: {sprov_vallist}")
                    #     if alt in sprov_vallist and comp_key != sprov_key:
                    #         # print(f"Sources Provides Key: {sprov_key}")
                    #         self.components[comp_key]['dependencies'].add(sprov_key)
                    #         found = True
                    #         break

                    if found:
                        break

                    for prov_key, prov_vallist in provides_dict.items():
                        # print(f"Provides list: {prov_vallist}")
                        if alt in prov_vallist:
                            # print(f"Provides Key: {prov_key}")
                            self.components[comp_key]['dependencies'].add(prov_key)
                            found = True
                            break

                    if found:
                        break

        # print()

        pkg_ids = set(self.components.keys())

        # Crear componente
        component = self._create_component(
            name=dpkg_name,
            version=dpkg_vers if dpkg_vers else 'unknown',
            comp_lvl='root',
            comp_type='firmware',
            md5='',
            sha1='',
            sha256='',
            sha512='',
            source='generic',
            filename=None
        )

        component_key = component.key
    
        # Si el componente no existe, añadirlo
        if component_key not in self.components:
            self.components[component_key] = component.to_dict()

        self.components[component_key]['dependencies'].update(pkg_ids)

        return self.components


    def _create_component(self, 
                         name: str, 
                         version: str, 
                         comp_type: str, 
                         comp_lvl: str,
                         source: str,
                         md5: Optional[str],
                         sha1: Optional[str],
                         sha256: Optional[str],
                         sha512: Optional[str],
                         filename: Optional[str]) -> Component:
        """
        Crea un objeto Component con mapeos aplicados.
        """
        # Normalizar valores
        comp_version = version if version != 'unknown' else 'unknown'
        comp_filename = filename if filename else 'unknown'
        
        # Aplicar mapeos si están disponibles
        pkgdir_id = 'unknown'
        pkg_id = 'unknown'
        
        if self.libs_mapper and comp_filename != 'unknown':
            pkgdir_id = self.libs_mapper.find_by_key(comp_filename)
        
        if self.pkgs_mapper and pkgdir_id != 'unknown':
            pkg_id = self.pkgs_mapper.find_by_key(pkgdir_id)

        return Component(
            name=name,
            version=comp_version,
            type=comp_type,
            level=comp_lvl,
            filename=comp_filename,
            pkg_src=source,
            pkg_id=pkg_id, # if pkg_id and pkg_id != 'unknown' else name,
            md5=md5 if md5 else '',
            sha1=sha1 if sha1 else '',
            sha256=sha256 if sha256 else '',
            sha512=sha512 if sha512 else '',
            pkgdir_id=pkgdir_id if pkgdir_id and pkgdir_id != 'unknown' else f"{name}-{version}"
        )
    
    def get_components(self) -> Dict[str, Dict[str, Any]]:
        """Retorna todos los componentes parseados."""
        return self.components
    
    def get_component(self, component_key: str) -> Optional[Dict[str, Any]]:
        """Obtiene un componente específico por su clave."""
        return self.components.get(component_key)
    
    def get_component_count(self) -> int:
        """Retorna el número total de componentes."""
        return len(self.components)
    
    def clear(self):
        """Limpia todos los componentes parseados."""
        self.components = {}
    

class XMLComponentParser:
    """
    Parser para analizar componentes XML y sus dependencias.
    """
    
    def __init__(self, libs_mapper=None, pkgs_mapper=None):
        """
        Inicializa el parser.
        """
        self.libs_mapper = libs_mapper
        self.pkgs_mapper = pkgs_mapper
        self.components = {}
        self._parse_depth = 0
    
    def parse_from_string(self, xml_content: str) -> Dict[str, Dict[str, Any]]:
        """
        Parsea contenido XML desde una cadena.
        """
        root = ET.fromstring(xml_content)
        self._parse_component_element(root)
        return self.components
    
    def _parse_component_element(self, element: ET.Element, depth: int = 0) -> Optional[str]:
        """
        Parsea un elemento de componente XML recursivamente.
        """
        # Extraer información básica
        name_elem = element.find('name')
        version_elem = element.find('version')
        filename_elem = element.find('filename')
        comp_type = element.get('type')

        if not depth:
            comp_level = 'root'
        else:
            comp_level = 'dep'
        
        # Validar elementos obligatorios
        if name_elem is None or version_elem is None or name_elem.text is None:
            return None
        
        # Crear componente
        component = self._create_component(
            name=name_elem.text,
            version=version_elem.text if version_elem.text else 'unknown',
            comp_lvl=comp_level,
            source='generic',
            comp_type=comp_type if comp_type else 'unknown',
            filename=filename_elem.text if filename_elem is not None else None
        )
        
        component_key = component.key
        
        # Si el componente no existe, añadirlo
        if component_key not in self.components:
            self.components[component_key] = component.to_dict()
        
        # Parsear dependencias
        dependencies_elem = element.find('dependencies')
        if dependencies_elem is not None:
            for dep_elem in dependencies_elem.findall('component'):
                dep_key = self._parse_dependency(dep_elem, depth)
                if dep_key:
                    self.components[component_key]['dependencies'].add(dep_key)
        
        return component_key
    
    def _create_component(self, 
                         name: str, 
                         version: str, 
                         comp_type: str, 
                         source: str,
                         comp_lvl: str,
                         filename: Optional[str]) -> Component:
        """
        Crea un objeto Component con mapeos aplicados.
        """
        # Normalizar valores
        comp_version = version if version != 'unknown' else 'unknown'
        comp_filename = filename if filename else 'unknown'
        
        # Aplicar mapeos si están disponibles
        pkgdir_id = 'unknown'
        pkg_id = 'unknown'
        
        if self.libs_mapper and comp_filename != 'unknown':
            pkgdir_id = self.libs_mapper.find_by_key(comp_filename)
        
        if self.pkgs_mapper and pkgdir_id != 'unknown':
            pkg_id = self.pkgs_mapper.find_by_key(pkgdir_id)
        
        return Component(
            name=name,
            version=comp_version,
            type=comp_type,
            level=comp_lvl,
            filename=comp_filename,
            pkg_src=source,
            pkgdir_id=pkgdir_id if pkgdir_id and pkgdir_id != 'unknown' else f"{name}-{version}",
            pkg_id=pkg_id
        )
    
    def _parse_dependency(self, dep_element: ET.Element, parent_depth: int) -> Optional[str]:
        """
        Parsea un elemento de dependencia.
        """

        dep_name_elem = dep_element.find('name')
        dep_version_elem = dep_element.find('version')
        
        if dep_name_elem is None or dep_version_elem is None or dep_name_elem.text is None:
            return None
        
        dep_version = dep_version_elem.text if dep_version_elem.text else 'unknown'
        dep_key = f"{dep_name_elem.text}-v{dep_version}"
        
        # Parsear recursivamente la dependencia completa
        self._parse_component_element(dep_element, depth=parent_depth + 1)
        
        return dep_key
    
    def get_components(self) -> Dict[str, Dict[str, Any]]:
        """Retorna todos los componentes parseados."""
        return self.components
    
    def get_component(self, component_key: str) -> Optional[Dict[str, Any]]:
        """Obtiene un componente específico por su clave."""
        return self.components.get(component_key)
    
    def get_component_count(self) -> int:
        """Retorna el número total de componentes."""
        return len(self.components)
    
    def clear(self):
        """Limpia todos los componentes parseados."""
        self.components = {}
        self._parse_depth = 0

# ============================================================================
#  BASE ANALYZER CLASS
# ============================================================================

class BaseAnalyzer:
    """
    Base para analizador de ficheros.
    """

    def __init__(self, 
                 libs_mapping_source: Optional[str] = None,
                 pkgs_mapping_source: Optional[str] = None,
                 mapping_threshold: float = DEFAULT_THRESHOLD):
        
        self.parser = None
        self.libs_mapper = None
        self.pkgs_mapper = None
        self.mapping_threshold = mapping_threshold
        
        # Configurar mappers si se proporcionan fuentes para extraer la información.
        if libs_mapping_source or pkgs_mapping_source:
            self._setup_mappers(libs_mapping_source, pkgs_mapping_source)
    
    def _setup_mappers(self, libs_source: Optional[str], pkgs_source: Optional[str]):
        """
        Setup de mapeos que se utilizarán en el proceso.
        """

        if libs_source:
            libs_mapping = create_libs_to_packages_mapping(libs_source)
            if libs_mapping:
                self.libs_mapper = FuzzyMapper(libs_mapping, threshold=self.mapping_threshold)
                print(f"[i] Mapeo de bibliotecas cargado: {len(libs_mapping)} entradas")
        
        if pkgs_source:
            pkgs_mapping = create_pkgdirname_to_pkg_mapping(pkgs_source)
            if pkgs_mapping:
                self.pkgs_mapper = FuzzyMapper(pkgs_mapping, threshold=self.mapping_threshold)
                print(f"[i] Mapeo de paquetes cargado: {len(pkgs_mapping)} entradas")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del análisis.
        """
        if not self.parser:
            return {}
        
        components = self.parser.get_components()
        total = len(components)
        by_type = {}
        total_deps = 0
        
        for comp in components.values():
            comp_type = comp.get('type', 'unknown')
            by_type[comp_type] = by_type.get(comp_type, 0) + 1
            total_deps += len(comp.get('dependencies', set()))
        
        return {
            'total_components': total,
            'by_type': by_type,
            'total_dependencies': total_deps,
            'avg_dependencies': total_deps / total if total > 0 else 0
        }

# ============================================================================
# DPKG STATUS ANALYZER
# ============================================================================

class DPKGAnalyzer(BaseAnalyzer):
    """
    Analizador de ficheros de componentes DPKG (/var/lib/dpkg/status).
    """

    def load_file(self, filepath: str):

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"[!] El archivo {filepath} no existe...")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        self.content = content

    def analyze_from_string(self, dpkg_name: str = 'ROOT', dpkg_vers: str = 'unknown') -> Dict[str, Dict[str, Any]]:
        """
        Analiza contenido XML desde una cadena.
        """
        self.parser = DPKGComponentParser(
            libs_mapper=self.libs_mapper,
            pkgs_mapper=self.pkgs_mapper
        )
        return self.parser.parse_from_string(self.content, dpkg_name, dpkg_vers)
    

# ============================================================================
# XML ANALYZER
# ============================================================================

class XMLAnalyzer(BaseAnalyzer):
    """
    Analizador de ficheros de componentes XML(./ldd_recursive.sh).
    """
    
    def __init__(self, 
                 libs_mapping_source: Optional[str] = None,
                 pkgs_mapping_source: Optional[str] = None,
                 mapping_threshold: float = DEFAULT_THRESHOLD):
        super().__init__(libs_mapping_source, pkgs_mapping_source, mapping_threshold)

        self.xsd_schema_path = None

    def set_xml_schema(self, xsd_schema_path: str):
        """
        Establece el esquema que se va a utilizar y validar al leer los XML
        """

        if not os.path.exists(xsd_schema_path):
            raise FileNotFoundError(f"[!] El archivo {xsd_schema_path} no existe")
                
        self.xsd_schema_path = xsd_schema_path

    def load_file(self, filepath: str):

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"[!] El archivo {filepath} no existe")
        
        print(f"\t - Evaluando formato de XML... ")

        xml_doc = etree.parse(filepath)
        schema_doc = etree.parse(self.xsd_schema_path)
        schema = etree.XMLSchema(schema_doc) 

        schema.assertValid(xml_doc)
        
        with open(filepath, 'r', encoding='utf-8') as f:
            xml_content = f.read()

        self.xml_content = xml_content
    
    def analyze_from_string(self) -> Dict[str, Dict[str, Any]]:
        """
        Analiza contenido XML desde una cadena.
        """
        self.parser = XMLComponentParser(
            libs_mapper=self.libs_mapper,
            pkgs_mapper=self.pkgs_mapper
        )
        return self.parser.parse_from_string(self.xml_content)

# ============================================================================
# PROGRAMA PRINCIPAL
# ============================================================================

def main():
    """
    Función principal para utilizar la herramienta mediante CLI.
    """
    parser = argparse.ArgumentParser(
        description='Analizador de dependencias desde archivos',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Para ver ejemplos de uso: python3 %(prog)s --examples'
    )

    parser.add_argument('--no-console', 
                        action='store_true',
                        help='No mostrar salida en consola')

    parser.add_argument('-s', '--summary-only', 
                        action='store_true',
                        help='Mostrar solo resumen (sin dependencias detalladas)')
    
    parser.add_argument('--examples', 
                        action='store_true',
                        help='Muestra ejemplos de uso del programa')

    parser.add_argument('-v', '--version', 
                        action='version',
                        version='%(prog)s 1.0')

    # Subparsers para diferentes tipos de archivo
    subparsers = parser.add_subparsers(
        dest='command', 
        required=True,  # Cambiado a True para hacer obligatorio el subcomando
        help='Tipo de archivo a procesar'
    )

    # Subcomando para XML
    xml_parser = subparsers.add_parser(
        'xml', 
        help='Procesar fichero XML (creado por ./ldd_recursive.sh)',
        description='Analiza dependencias desde archivos XML generados por ldd_recursive.sh'
    )

    xml_parser.add_argument(
        'input_file',
        help='Archivo XML de entrada con componentes y dependencias'
    )

    xml_parser.add_argument('-m', '--create-mapping',
                        action='store_true',
                        help='Crear y usar mapeo de librería a paquete')

    xml_parser.add_argument('--lib-lists',
                        metavar='DIR',
                        help='Directorios que contienen mapeos de paquetes y librerías')

    xml_parser.add_argument('--bsp-report',
                        metavar='FILE',
                        help='Reporte BSP del sistema base en formato YAML')

    xml_parser.add_argument('-j', '--json', 
                        metavar='FILE',
                        help='Exportar resultados intermedios a archivo JSON')

    xml_parser.add_argument('-t', '--text', 
                        metavar='FILE',
                        help='Exportar reporte de resultados a archivo de texto')

    xml_parser.add_argument('-y', '--yaml',
                        metavar='FILE',
                        help='Exportar resultados finales a archivo YAML')

    # Subcomando para DPKG
    dpkg_parser = subparsers.add_parser(
        'dpkg', 
        help='Procesar datos extraídos desde dpkg/status',
        description='Analiza dependencias desde archivos de estado de DPKG'
    )

    dpkg_parser.add_argument(
        'input_file',
        help='Archivo dpkg/status de entrada'
    )

    dpkg_parser.add_argument('--dpkg-name',
                        metavar='NAME',
                        help='Nombre del sistema al que pertenece el archivo DPKG')

    dpkg_parser.add_argument('--dpkg-vers',
                        metavar='VERSION',
                        help='Versión del sistema al que pertenece el archivo DPKG')

    dpkg_parser.add_argument('-j', '--json', 
                        metavar='FILE',
                        help='Exportar resultados intermedios a archivo JSON')

    dpkg_parser.add_argument('-t', '--text', 
                        metavar='FILE',
                        help='Exportar reporte de resultados a archivo de texto')

    dpkg_parser.add_argument('-y', '--yaml',
                        metavar='FILE',
                        help='Exportar resultados finales a archivo YAML')

    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        return 0

    args = parser.parse_args()

    if args.examples:
        print_examples()
        return 0
    
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"[!] Error: No se pudo encontrar el archivo '{args.input_file}'", file=sys.stderr)
        sys.exit(1)
    
    try:

        if args.command == 'xml':
            if args.create_mapping or args.output or args.yaml:

                if not args.lib_lists:
                    print('[i] No se ha proporcionado directorio de librerias, Saliendo...')
                    sys.exit(1)

                if not args.bsp_report:
                    print('[i] No se ha proporcionado report del sistema base (BSP), Saliendo...')
                    sys.exit(1)

                analyzer = XMLAnalyzer(
                    libs_mapping_source=args.lib_lists,
                    pkgs_mapping_source=args.bsp_report
                )
            else:
                analyzer = XMLAnalyzer()

            if DEFAULT_XML_SCHEMA:
                analyzer.set_xml_schema(DEFAULT_XML_SCHEMA)

            print(f"[i] Leyendo archivo '{args.input_file}'...")

            analyzer.load_file(input_path)
            
            print("[i] Analizando dependencias...")
            
            components = analyzer.analyze_from_string()
            
            print(f"[✓] Se encontraron {len(components)} componentes únicos\n")

        elif args.command == 'dpkg':
            analyzer = DPKGAnalyzer()

            print(f"[i] Leyendo archivo '{args.input_file}'...")

            analyzer.load_file(input_path)
            
            print("[i] Analizando dependencias...")

            if not args.dpkg_name and not args.dpkg_vers:
                components = analyzer.analyze_from_string()
            else:
                components = analyzer.analyze_from_string(args.dpkg_name, args.dpkg_vers)
            
            print(f"[✓] Se encontraron {len(components)} componentes únicos\n")
        
    except ET.ParseError as e:
        print(f"[!] Error al parsear XML: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not args.no_console:
        print_components_summary(components)
        if not args.summary_only:
            print_dependencies_detail(components)
    
    export_count = 0
    
    if args.yaml:
        try:
            export_to_yaml(components, args.yaml, args.command)
            print(f"[✓] Datos exportados a '{args.yaml}'")
            export_count += 1
        except Exception as e:
            print(f"[!] Error al exportar YAML: {e}", file=sys.stderr)
            sys.exit(1)

    if args.json:
        try:
            export_to_json(components, args.json)
            print(f"[✓] Datos exportados a '{args.json}'")
            export_count += 1
        except Exception as e:
            print(f"[!] Error al exportar JSON: {e}", file=sys.stderr)
            sys.exit(1)
    
    if args.text:
        try:
            export_to_text(components, args.text)
            print(f"[✓] Análisis exportado a '{args.text}'")
            export_count += 1
        except Exception as e:
            print(f"[!] Error al exportar archivo de texto: {e}", file=sys.stderr)
            sys.exit(1)
    
    if export_count == 0 and not args.no_console:
        print("\n[i] Consejo: Usa -j para exportar JSON o -t para exportar reporte de texto")
        print("   Ejemplo: python script.py archivo.xml -j salida.json")


if __name__ == "__main__":

    def manejar_ctrl_c(signum, frame):
        print("\n[!] Capturado Ctrl+C. Saliendo del programa...")
        sys.exit(0)

    # Asociamos el manejador a la señal SIGINT
    signal.signal(signal.SIGINT, manejar_ctrl_c)

    main()
