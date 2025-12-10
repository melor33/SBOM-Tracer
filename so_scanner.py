#!/usr/bin/env python3
"""
Escáner de librerías .so del sistema
Mapea todas las librerías compartidas a sus paquetes correspondientes
"""

import os
import sys
import subprocess
import json
import signal
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Información del programa
VERSION = "1.0.0"
AUTHOR = "Tu Nombre"

def def_handler(signum, frame):
    print("\n[!] Saliendo...")
    exit(1)

signal.signal(signal.SIGINT, def_handler)

def print_banner():
    """Imprime el banner del programa"""
    banner = f"""
╔═══════════════════════════════════════════════════════════════╗
║              Escáner de Librerías .so del Sistema             ║
║                        Versión {VERSION}                          ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_examples():
    """Imprime ejemplos de uso del programa"""
    examples = """
EJEMPLOS DE USO:
═══════════════════════════════════════════════════════════════

1. Escaneo básico con salida en pantalla:
   $ ./so_scanner.py

2. Escaneo con salida formateada a archivos JSON:
   $ ./so_scanner.py -o libraries.json --pretty

3. Escaneo con modo verbose para ver el progreso:
   $ ./so_scanner.py -v -o libraries.json

4. Escaneo con modo ultra-verbose (depuración detallada):
   $ ./so_scanner.py -vV -o libraries.json

5. Ajustar número de workers (hilos paralelos):
   $ ./so_scanner.py -v -w 16 -o libraries.json

6. Escaneo rápido con máximo paralelismo:
   $ ./so_scanner.py -v -w 64 --pretty -o libraries.json

7. Escaneo en modo debug con pocos workers:
   $ ./so_scanner.py -vV -w 4 -o libraries.json

8. Ver esta ayuda:
   $ ./so_scanner.py --help
   $ ./so_scanner.py --examples

SALIDA:
═══════════════════════════════════════════════════════════════
El programa genera 3 archivos JSON (o 3 secciones en stdout):

• installed_<nombre>.json  → Librerías de paquetes instalados
• suggested_<nombre>.json  → Librerías de paquetes sugeridos
• unknown_<nombre>.json    → Librerías sin paquete conocido

FORMATO JSON:
═══════════════════════════════════════════════════════════════
{
  "package": "libc6",
  "libraries": [
    "libc.so.6",
    "libm.so.6"
  ]
}

REQUISITOS:
═══════════════════════════════════════════════════════════════
• Sistema Debian/Ubuntu (requiere dpkg)
• apt-file (instalado automáticamente si no está presente)
"""
    print(examples)

class SOScanner:
    def __init__(self, verbose=False, debug=False, workers=None):
        self.verbose = verbose
        self.ultra_verbose = debug
        self.workers = workers or min(32, (os.cpu_count() or 1) * 4)
        self.search_paths = [
            '/lib',
            '/lib64',
            '/usr/lib',
            '/usr/lib64',
            '/usr/local/lib',
            '/usr/local/lib64',
        ]
        self.lock = Lock()
        self.processed_count = 0

        self._log_info(f"Actualizando apt-file...")
        subprocess.run(['apt-file', 'update'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _log(self, message):
        """Imprime mensajes generales"""
        print(message)

    def _log_info(self, message):
        """Imprime mensajes si verbose está activado"""
        if self.verbose:
            print(f"[INFO] {message}")

    def _log_debug(self, message):
        """Imprime mensajes de depuración si ultra_verbose está activado"""
        if self.ultra_verbose:
            print(f"[DEBUG] {message}")
    
    def find_so_files(self) -> Set[str]:
        """Encuentra todos los archivos .so en el sistema"""
        so_files = set()
        
        for search_path in self.search_paths:
            if not os.path.exists(search_path):
                continue
            
            self._log_info(f"Escaneando {search_path}...")
            
            try:
                for root, dirs, files in os.walk(search_path):
                    for file in files:
                        # Buscar archivos .so o .so.X.Y.Z
                        if '.so' in file:
                            full_path = os.path.join(root, file)
                            so_files.add(full_path)
            except PermissionError:
                self._log_info(f"Permiso denegado en {search_path}")
                continue
        
        self._log_info(f"Encontrados {len(so_files)} archivos .so")
        return so_files
    
    def get_package_for_file(self, filepath: str) -> str:
        """Usa dpkg -S para obtener el paquete de un archivo"""
        try:
            result = subprocess.run(
                ['dpkg', '-S', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # dpkg -S devuelve: "paquete: /ruta/archivo"
                output = result.stdout.strip()
                if ':' in output:
                    package = output.split(':')[0]
                    return package
            
            return None
            
        except subprocess.TimeoutExpired:
            self._log_debug(f"Timeout al consultar {filepath}")
            return None
        except FileNotFoundError:
            print("[!] Error: dpkg no encontrado. Este script requiere un sistema Debian/Ubuntu.")
            return None
        except Exception as e:
            self._log_debug(f"Error al consultar {filepath}: {e}")
            return None

    def get_suggested_package_from_filename(self, filepath: str) -> str:
        """Usa apt-file search para determinar el paquete al que habría pertenecido"""
        try:
            res = subprocess.run(
                ['apt-file', 'search', filepath],
                capture_output=True,
                text=True,
                timeout=50
            )

            if res.returncode == 0:
                output = res.stdout.strip()
                if output:
                    # apt-file search devuelve múltiples líneas, tomar la primera
                    first_line = output.splitlines()[0]
                    if ':' in first_line:
                        package = first_line.split(':')[0]
                        return package
                    
            return None
        
        except subprocess.TimeoutExpired:
            self._log_debug(f"Timeout al buscar paquete sugerido para {filepath}")
            return None
        except FileNotFoundError:
            self._log_debug("[!] apt-file no encontrado. No se pueden sugerir paquetes para archivos no instalados.")
            return None
        except Exception as e:
            self._log_debug(f"Error al buscar paquete sugerido para {filepath}: {e}")
            return None

    def process_single_file(self, so_file: str, total: int) -> Dict:
        """Procesa un solo archivo .so y devuelve su clasificación"""
        result = {
            'category': None,
            'package': None,
            'lib_name': os.path.basename(so_file)
        }
        
        # Incrementar contador con lock
        with self.lock:
            self.processed_count += 1
            current = self.processed_count
            tqmd_percentage = (current / total) * 100
            tqmd_bar = ('#' * int(tqmd_percentage // 2)).ljust(50)
            print(f"\r[{tqmd_bar}] {current}/{total} ({tqmd_percentage:.2f}%)", end='', flush=True)

        # Si es enlace simbólico, intentar resolver
        if os.path.islink(so_file):
            try:
                self._log_debug(f"Resolviendo enlace simbólico: {so_file}")
                target_path = os.path.realpath(so_file)
                
                package = self.get_package_for_file(target_path)
                self._log_debug(f"{so_file} (enlace) -> {package if package else 'No encontrado'}")
                if package:
                    result['category'] = 'installed'
                    result['package'] = package
                    return result

            except Exception as e:
                self._log_debug(f"Error al resolver enlace {so_file}: {e}")
        
        # Intentar obtener paquete instalado
        package = self.get_package_for_file(so_file)
        self._log_debug(f"{so_file} -> {package if package else 'No encontrado'}")
        if package:
            result['category'] = 'installed'
            result['package'] = package
            return result
        
        # Si es enlace simbólico, intentar obtener paquete sugerido del target
        if os.path.islink(so_file):
            try:
                self._log_debug(f"Resolviendo enlace simbólico: {so_file}")
                target_path = os.path.realpath(so_file)
                
                package = self.get_suggested_package_from_filename(target_path)
                self._log_debug(f"{so_file} (enlace) (sugerido) -> {package if package else 'No encontrado'}")
                if package:
                    result['category'] = 'suggested'
                    result['package'] = package
                    return result

            except Exception as e:
                self._log_debug(f"Error al resolver enlace {so_file}: {e}")

        # Intentar obtener paquete sugerido
        package = self.get_suggested_package_from_filename(so_file)
        self._log_debug(f"{so_file} (sugerido) -> {package if package else 'No encontrado'}")
        if package:
            result['category'] = 'suggested'
            result['package'] = package
            return result
        
        # Si no se encuentra, marcar como unknown
        result['category'] = 'unknown'
        return result
    
    def map_libraries_to_packages(self, so_files: Set[str]) -> Dict[str, Dict[str, List[str]]]:
        """Mapea librerías a paquetes usando threading"""
        package_libs = {
            "installed": defaultdict(list),
            "suggested": defaultdict(list),
            "unknown": []
        }
        
        total = len(so_files)
        self.processed_count = 0
        
        self._log_info(f"Procesando {total} archivos con {self.workers} workers...")
        
        # Usar ThreadPoolExecutor para procesar archivos en paralelo
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            # Enviar todas las tareas
            futures = {
                executor.submit(self.process_single_file, so_file, total): so_file 
                for so_file in so_files
            }
            
            # Recoger resultados conforme se completan
            for future in as_completed(futures):
                try:
                    result = future.result()
                    
                    if result['category'] == 'unknown':
                        package_libs['unknown'].append(result['lib_name'])
                    else:
                        package_libs[result['category']][result['package']].append(result['lib_name'])
                        
                except Exception as e:
                    so_file = futures[future]
                    self._log_debug(f"Error procesando {so_file}: {e}")
        
        return package_libs
    
    def format_output(self, package_libs: Dict[str, Dict[str, List[str]]]) -> Dict:
        """Formatea la salida al formato JSON solicitado"""
        result = {}

        for category in package_libs.keys():
            self._log_info(f"Preparando salida para categoría: {category}")
            result[category] = []
            
            if category == 'unknown':
                # Para unknown, simplemente devolver la lista de nombres
                result[category] = sorted(list(set(package_libs[category])))
            else:
                # Para installed y suggested, crear la estructura de paquetes
                for package, libraries in sorted(package_libs[category].items()):
                    entry = {
                        "package": package,
                        "libraries": sorted(list(set(libraries)))  # Eliminar duplicados y ordenar
                    }
                    result[category].append(entry)

        return result
    
    def scan(self) -> Dict:
        """Ejecuta el escaneo completo"""
        self._log("[i] Iniciando escaneo del sistema...")
        
        # 1. Encontrar todos los archivos .so
        so_files = self.find_so_files()
        
        if not so_files:
            self._log("[!] No se encontraron archivos .so")
            return {}
        
        # 2. Mapear a paquetes
        self._log("[i] Mapeando librerías a paquetes...")
        package_libs = self.map_libraries_to_packages(so_files)
        
        # 3. Formatear salida
        result = self.format_output(package_libs)
        
        total_packages = sum(len(result[cat]) if cat != 'unknown' else 0 for cat in result.keys())
        self._log(f"\n[✓] Escaneo completado. {total_packages} paquetes encontrados.")
        return result


def main():
    parser = argparse.ArgumentParser(
        prog='so_scanner.py',
        description='Escáner de librerías .so del sistema - Mapea librerías compartidas a paquetes',
        epilog='Para ver ejemplos de uso detallados, ejecuta: %(prog)s --examples',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        metavar='ARCHIVO',
        help='Nombre base para archivos de salida JSON. Se generarán 3 archivos: installed_<ARCHIVO>, suggested_<ARCHIVO>, unknown_<ARCHIVO> (por defecto: salida a stdout)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose - Muestra información de progreso y estadísticas'
    )
    
    parser.add_argument(
        "-vV", "--ultra-verbose",
        action='store_true',
        help='Modo ultra-verbose - Muestra información detallada de depuración para cada archivo procesado'
    )
    
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Formatea el JSON con indentación para mejor legibilidad'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        metavar='N',
        default=None,
        help='Número de workers (hilos) para procesamiento paralelo. Por defecto: CPU_COUNT × 4 (típicamente 32)'
    )
    
    parser.add_argument(
        '--examples',
        action='store_true',
        help='Muestra ejemplos de uso del programa'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )
    
    # Si no hay argumentos, mostrar ayuda
    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        return 0
    
    args = parser.parse_args()
    
    # Si se solicitan ejemplos, mostrarlos y salir
    if args.examples:
        print_examples()
        return 0
    
    # Verificar que estamos en un sistema con dpkg
    if not os.path.exists('/usr/bin/dpkg') and not os.path.exists('/bin/dpkg'):
        print("[!] Error: Este script requiere dpkg (sistema Debian/Ubuntu)")
        return 1
    
    # Mostrar banner en modo verbose
    if args.verbose or args.ultra_verbose:
        print_banner()
    
    # Crear scanner y ejecutar
    scanner = SOScanner(verbose=args.verbose, debug=args.ultra_verbose, workers=args.workers)
    result = scanner.scan()
    
    # Formatear JSON
    indent = 2 if args.pretty else None

    for category in result.keys():
        if category != 'unknown':
            json_output = json.dumps(sorted(result[category], key=lambda x: x['package']), indent=indent, ensure_ascii=False)
        else:
            json_output = json.dumps(sorted(result[category]), indent=indent, ensure_ascii=False)
    
        # Guardar o imprimir
        if args.output:
            filename = f"{category}_{args.output}"
            with open(filename, 'w') as f:
                f.write(json_output)
            print(f"[✓] Resultados guardados en el fichero {filename}")
        else:
            print(f"\n{'='*60}")
            print(f"  {category.upper()}")
            print('='*60)
            print(json_output)
    
    return 0


if __name__ == '__main__':
    exit(main())