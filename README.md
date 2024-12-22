# Sistema de Detección de Intrusos en Entornos Domésticos para Trabajos Empresariales

## Descripción
Con el incremento del 13% en la presencia de malware en entornos empresariales tras la pandemia del COVID-19, este proyecto desarrolla un sistema de detección de intrusos diseñado para redes domésticas utilizadas en trabajos empresariales. El sistema combina un módulo de captura de paquetes de red y un módulo de análisis basado en algoritmos de aprendizaje automático, logrando identificar patrones anómalos en el tráfico de red. Utilizando un algoritmo Support Vector Machine, se alcanzó una precisión del 82% en la detección de intrusiones.

## Instrucciones de Instalación

### Requisitos Previos
- Python 3.8 o superior.
- Sistema operativo compatible con Pyshark (Linux o Windows con Wireshark instalado).

### Pasos para la Instalación
1. Clonar el repositorio:
   ```bash
   git clone <url_del_repositorio>
   cd <nombre_del_repositorio>
   ```
2. Configurar el módulo 1 (`src/Modulo1.py`):
   - Indicar el nombre del archivo donde se guardarán los datos capturados.
   - Especificar la cantidad de paquetes a capturar.
   - Seleccionar la interfaz de red a utilizar (e.g., Wi-Fi, Ethernet).

3. Configurar el módulo 2 (`src/Modulo2.ipynb`):
   - En la quinta celda, definir el tipo de archivo a analizar (capturado o archivo de pruebas).

### Ejecución de la Aplicación
Para ejecutar el sistema, sigue los pasos:
1. Inicia la captura de paquetes con el módulo correspondiente:
   ```bash
   python src/Modulo1.py
   ```
2. Analiza los datos utilizando el módulo de análisis:
   ```bash
   jupyter notebook src/Modulo2.ipynb
   ```
3. Revisa los resultados generados en la carpeta `src/`.

### Ejecución de Tests
- Los scripts han sido diseñados para capturar tráfico en tiempo real. Asegúrate de contar con permisos administrativos y una interfaz de red activa para pruebas.

## Demo
En la carpeta `/demo/` se encuentra un video que muestra el sistema en acción. Accede a él para ver cómo funciona el proyecto en un entorno controlado.

## Informe Final
El informe final del proyecto está disponible en la carpeta `/docs/` bajo el nombre `Informe.pdf`. Este documento detalla el desarrollo, los resultados y las conclusiones del trabajo.

## Estructura del Repositorio
- `/src/`: Contiene los scripts principales y los archivos necesarios para ejecutar el sistema.
- `/demo/`: Incluye el video demostrativo del proyecto.
- `/docs/`: Contiene el informe final del proyecto.

## Autor
Proyecto desarrollado como parte del trabajo de graduación de Diego José Franco Pacay, dentro de la Universidad Del Valle de Guatemala.

