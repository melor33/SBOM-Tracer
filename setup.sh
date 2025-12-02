#!/bin/bash

# Crear entorno virtual si no existe
if [ ! -d \"venv\" ]; then
    python3 -m venv venv
fi

# Activar entorno virtual
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Crear directorios
mkdir -p data/ config/lib_lists config/report config/schema

#
echo \"[i] Entorno de ejecución listo.\"
