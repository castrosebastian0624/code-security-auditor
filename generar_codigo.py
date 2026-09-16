"""
================================================================================
 GENERADOR DE CÓDIGOS DE ACCESO — herramienta interna, NO se despliega
================================================================================
Este script se corre LOCALMENTE en tu computadora (no en Streamlit Cloud).
Sirve para crear un código de acceso nuevo cada vez que vayas a contactar a
un prospecto, sin tener que escribir el SQL a mano en Neon.

Cómo usarlo:
    python generar_codigo.py

Te va a preguntar el nombre del prospecto y cuántos usos gratis darle
(por defecto 2), y te muestra el código ya listo para copiar y pegar en tu
mensaje de LinkedIn/WhatsApp.
================================================================================
"""

import os
import re
import random
import string
from dotenv import load_dotenv
import psycopg2

load_dotenv()
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    print("❌ No se encontró DATABASE_URL en tu archivo .env. Revisa que exista esa línea.")
    exit(1)


def slug_desde_nombre(nombre: str) -> str:
    """Convierte 'Juan Pérez - CTO StartupX' en algo como 'JUANPEREZ'."""
    solo_letras = re.sub(r"[^a-zA-Z]", "", nombre)
    return solo_letras.upper()[:10] or "PROSPECTO"


def generar_codigo_unico(nombre: str) -> str:
    slug = slug_desde_nombre(nombre)
    sufijo = "".join(random.choices(string.digits, k=4))
    return f"DEMO-{slug}{sufijo}"


def crear_codigo(nombre_prospecto: str, usos: int) -> str:
    codigo = generar_codigo_unico(nombre_prospecto)
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO codigos_acceso (codigo, prospecto_nombre, usos_permitidos) "
                "VALUES (%s, %s, %s)",
                (codigo, nombre_prospecto, usos),
            )
        conn.commit()
    finally:
        conn.close()
    return codigo


if __name__ == "__main__":
    print("=" * 60)
    print("  GENERADOR DE CÓDIGOS DE ACCESO — Auditor de Código")
    print("=" * 60)

    nombre = input("\nNombre del prospecto (ej: 'Juan Pérez - CTO StartupX'): ").strip()
    if not nombre:
        print("❌ Necesitas escribir un nombre.")
        exit(1)

    usos_input = input("¿Cuántas auditorías gratis darle? [Enter = 2]: ").strip()
    usos = int(usos_input) if usos_input else 2

    try:
        codigo = crear_codigo(nombre, usos)
        print("\n✅ ¡Código creado con éxito!")
        print(f"\n   Código:    {codigo}")
        print(f"   Prospecto: {nombre}")
        print(f"   Usos:      {usos}")
        print("\nCópialo y pégalo en tu mensaje de LinkedIn/WhatsApp.")
    except psycopg2.errors.UniqueViolation:
        print("\n⚠️ Ese código ya existe (raro, pero puede pasar). Corre el script de nuevo.")
    except Exception as e:
        print(f"\n❌ Error al crear el código: {e}")