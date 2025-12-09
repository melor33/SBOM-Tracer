# SBOM Tracer

Proyecto compuesto por múltiples scripts para crear listados de software SBOM con formato CycloneDX JSON.

Se puede utilizar para extraer librerías de aplicaciones en entornos linux para listar todos los paquetes que conforman la aplicación con un listado SBOM en formato CycloneDX JSON. O en su defecto para convertir reportes en formato YAML a listados SBOM en formato CycloneDX JSON.

## Requerimientos

Para utilizar los siguientes scripts de forma correcta, se necesitan los siguientes ficheros de datos y establecer las variables de entorno, únicamente si es necesario el mapeo de librerías a paquetes, muy importante para el procesamiento de archivos XML extraidos con el script de bash `ldd_recursive.sh`.

- Fichero donde se especifiquen el contenido de librerías de cada paquete en formato JSON ([Ver ejemplo de esquema aqui](#inventario-de-paqueteslibrerías-en-json)).

- Archivo del report completo del BSP o firware en la que se evaluarán las aplicaciones, en formato YAML y esquema utilizado por PTXDist.

## Instalación

Se recomienda utilizar un entorno virtual para aislar dependencias y o tener que ejecutar todas los paquetes de pip en el sistema.

### 1. Instalación mediante script

Dar permisos de ejecución al script de setup.

```bash
chmod +x ./setup.sh
```

Ejecutar el script de setup

```bash
./setup.sh
```

### 2. Instalación manual

#### Crear un entorno virtual de python:

```bash
python3 -m venv venv
```

#### Activar el entorno virtual:

**Linux / macOS**

```bash
source venv/bin/activate
```

**Windows**

```bash
venv\Scripts\activate
```

#### Instalar dependencias

Todas las dependencias necesarias están listadas en `requirements.txt`.

```bash
pip install -r requirements.txt
```

## Extraer paquetes desde listado de librerías (XML)

### Configuración del script

Antes de ejecutar el script se deben establecer las variables de entorno que se utilizarán por defecto en el script. Esto es, se utilizarán como directorios default para el caso en el que no se introduzcan los argumento `--lib-lists` y `--bsp-report`

Estos hacen referencia  primeramente al directorio donde se ubican las listas con los mapeos de nombres de librerías (.so) a paquetes.

```bash
export LIBS_DIR="/"
```

Y también el report completo del firmware o BSP extraído del sistema (linux) donde se ejecutará la aplicación, en el caso de que sea posible y se tenga acceso al fichero.

```bash
export PTX_REPORT="/"
```

### Uso del script

El script lista todos los paquetes que existen entre todas las librerías en el fichero XML y lo procesa para tener la información mas accesible y legible. Además, también se puede obtener un archivo en formato YAML basado en los report creados por PTXDist para poder obtener el SBOM final. 

El script requiere de diversos argumentos para su ejecución.

Ejemplo **XML**:

```bash
python3 extract_libs.py xml <ldd_resultfile.xml> --lib-lists /path/to/dir --bsp-report base_report.yaml -j <complist.json> -t <report.txt> -y <report.yaml>
```

Ejemplo **DPKG**:

```bash
python3 cyclonedx_converter.py dpkg <dpkg_status.txt> --dpkg-name NAME --dpkg-vers VERSION -j <complist.json> -t <report.txt> -y <report.yaml>
```

Se puede obtener toda la información para la ejecución del script mediante:

```bash
python3 extract_libs.py -h
```

```bash
Uso:python3 extract_libs.py [-h] [--no-console] [-s] [-v] {xml,dpkg} ...

Analizador de dependencias desde archivos

Argumentos posicionales:
  {xml,dpkg}          Tipo de archivo a procesar
    xml               Procesar fichero XML (creado por ./ldd_recursive.sh)
    dpkg              Procesar datos extraídos desde dpkg/status

Opciones:
  -h, --help          Visualizar el mensaje de ayuda
  --no-console        No mostrar salida en consola
  -s, --summary-only  Mostrar solo resumen (sin dependencias detalladas)
  -v, --version       Visualizar versión del programa

    Ejemplos de uso:
    # Procesamiento de archivos XML (generados por ./ldd_recursive.sh)
    extract_libs.py xml file.xml                                    # Análisis básico en terminal
    extract_libs.py xml file.xml -j output.json                     # Exportar solo JSON
    extract_libs.py xml file.xml -t report.txt                      # Exportar solo reporte texto
    extract_libs.py xml file.xml -y deps.yaml                       # Exportar solo YAML
    extract_libs.py xml file.xml -j deps.json -t deps.txt           # Exportar múltiples formatos
    extract_libs.py xml file.xml --no-console                       # Sin salida en terminal
    extract_libs.py xml file.xml -s                                 # Solo resumen
    extract_libs.py xml file.xml -m                                 # Crear mapeo lib->pkg
    extract_libs.py xml file.xml --lib-lists /path/to/dir           # Usar directorios con mapeos
    extract_libs.py xml file.xml --bsp-report base_report.yaml      # Usar reporte BSP del sistema base
    
    # Procesamiento de archivos DPKG
    extract_libs.py dpkg dpkg_status --dpkg-name "Sistema" --dpkg-vers "1.0"  # Análisis DPKG
    extract_libs.py dpkg dpkg_status -t report.txt                      # Exportar a TXT
    extract_libs.py dpkg dpkg_status -j output.json                           # Exportar a JSON
    extract_libs.py dpkg dpkg_status -y deps.yaml                             # Exportar a YAML

```

## Convertir report (YAML) a CycloneDX SBOM

### Configuración del script

El script requiere de la configuración para el acceso a la base de datos de NVD(NIST) donde se alojan los datos de todos los CVE y CPE del gobierno de los Estados Unidos.

Esto se debe de hacer mendiante las variables de entorno, configurando el endpoint donde se ubica la API de la base de datos y la API key, en el caso de que esté disponible. 

La API key sirve para tener un rate limit ampliado, el cuál está limitado por las reglas de firewall de NIST. Con una API key se obtiene una rate limit de 50 requests por 30 segundos frente a los 5 requests por 30 segundos (sin API key). Se puede obtener en la siguiente url [Request an API Key](https://nvd.nist.gov/developers/request-an-api-key).


```bash
export API_KEY="tu_api_key"
export TARGET_URL="https://services.nvd.nist.gov/rest/json/cpes/2.0"
```

### Uso del script

El script convierte ficheros de reporte de PTXDist originales o customizados (creados con [extract_libs.py](#extraer-paquetes-desde-listado-de-librerías-xml)) en formato YAML a ficheros de listado de materiales de software (SBOM) en formato CycloneDX JSON.

El script requiere de diversos argumentos para su ejecución.

Ejemplo:

```bash
python3 cyclonedx_converter.py -t ptx full-bsp-report.yaml -o bsp-sbom.json
```

Se puede obtener toda la información para la ejecución del script mediante:

```bash
python3 cyclonedx_converter.py -h
```

```bash
Usage: cyclonedx_converter.py [-h] -t {ptx,firmware,prg,hmi,application,other} -o OUTPUT [-n NAME] [-v] [-q] [-s] yaml_file

Convert YAML reports (PTXdist/Custom) to CycloneDX SBOM

Positional arguments:
  yaml_file             Input YAML report file

Options:
  -h, --help            show this help message and exit
  -t {ptx,firmware,prg,hmi,application,other}, --type {ptx,firmware,prg,hmi,application,other}
                        Type of YAML file to convert
  -o OUTPUT, --output OUTPUT
                        Output CycloneDX SBOM file (default: sbom.cdx.json)
  -n NAME, --name NAME  Document name (auto-detected if not specified)
  -v, --version         show program's version number and exit
  -q, --quiet           Suppress informational messages
  -s, --sign            Sign created SBOM file.

Examples:
  # Convert PTXdist report
  cyclonedx_converter.py -t ptx full-bsp-report.yaml -o bsp-sbom.json
  
  # Convert application report with custom name
  cyclonedx_converter.py -t prg app-report.yaml -o app-sbom.json -n "MyApp-v1.0"
  
  # Convert HMI report
  cyclonedx_converter.py -t hmi hmi-report.yaml -o hmi-sbom.json

Supported types:
  ptx         PTXdist BSP projects
  prg         Program/application projects
  hmi         HMI (Human-Machine Interface) projects
  application Generic application projects
  firmware    Firmware projects
  other       Other custom projects

```

## Estructura del Proyecto

```
SBOM_CREATION/
│
├─ config/
├─ data/
|
├─ cyclonedx_converter.py
├─ extract_libs.py
|
├─ ldd_recursive.sh
│
├─ requirements.txt
├─ README.md
└─ setup.sh
```

## Uso de Library Finder

Para utilizar el siguiente script, solamente se necesita copiar el script de BASH al sistema en el que este se debe de funcionar y ejecutarlo mediante terminal.

Dar permisos de ejecución al script.

```bash
chmod +x ./ldd_recursive.sh
```

Ejecutar el script, introduciendo el path a la aplicación, el nombre de la aplicación y un directorio donde se guardará los ficheros de salida.

```bash
./ldd_recursive.sh /ruta/a/ejecutable <elf_name> /directorio/output
```

## Esquemas utilizados en el script

### Inventario de paquetes/librerías en JSON

Esquema del listado de librerías que contiene cada paquete en formato JSON.

```json
{
  "packages": [
    {
      "package": "gcclibs-12.2.1",
      "libraries": [
        "libstdc++.so.6",
        "libgcc_s.so.1",
        "libgomp.so.1",
        "libatomic.so.1",
        "libquadmath.so.0"
      ]
    },
    {
      "package": "glibc-2.36",
      "libraries": [
        "libc.so.6",
        "libm.so.6",
        "libpthread.so.0",
        "libdl.so.2",
        "libutil.so.1",
        "libanl.so.1",
        "librt.so.1",
        "libcrypt.so.1",
        "libresolv.so.2",
        "libnsl.so.1",
        "libnss_files.so.2",
        "libnss_dns.so.2",
        "libnss_hesiod.so.2",
        "libnss_compat.so.2",
        "libnss_nisplus.so.2",
        "libnss_nis.so.2"
      ]
    },
    { "package": "binutils-2.39",
     "libraries": [] }
  ]
}
```

Se puede ver el esquema completo en [`complist_schema.json`](./config/complist_schema.json)

### Lista de dependencias (librerías) en XML

Esquema del archivo xml creado por el script ./ldd_recursive.sh que busca las librerías.

Ejemplo:

```xml
<component type="application">
  <filename></filename>
  <name>FPP</name>
  <version>25220_02</version>
  <path></path>
  <hashes>
    <hash alg="MD5">352f001edb679dc648af117a84030274</hash>
  </hashes>
  <dependencies>
    <component type="library">
      <filename>libm.so.6</filename>
      <name>libm</name>
      <version>6</version>
      <path>/lib/libm.so.6</path>
      <hashes>
        <hash alg="MD5">56854374fe834cf12d082ecfc409e7c8</hash>
      </hashes>
      <externalReferences>
        <reference>
          <filename>libm.so.6</filename>
          <url>/lib/libm.so.6</url>
          <comment>Symbolic Link</comment>
        </reference>
      </externalReferences>
      <dependencies>
        <component type="library">
          <filename>libc.so.6</filename>
          <name>libc</name>
          <version>6</version>
          <path>/lib/libc.so.6</path>
          <hashes>
            <hash alg="MD5">dba2ef9eff0cfb1ef57150da1aa49a49</hash>
          </hashes>
          <externalReferences>
            <reference>
              <filename>libc.so.6</filename>
              <url>/lib/libc.so.6</url>
              <comment>Symbolic Link</comment>
            </reference>
          </externalReferences>
          <dependencies>
          </dependencies>
        </component>
      </dependencies>
    </component>
    ...
  </dependencies>
</component>
```

Se puede ver el esquema completo en [`libs_schema.xsd`](./config/libs_schema.xsd)

### Esquema CyclondeDX@1.5 formato JSON

El esquema completo utilizado se puede ver en [`bom-1.5.schema.json`](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.5.schema.json)
