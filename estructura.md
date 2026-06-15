# Especificación Técnica de Arquitectura Backend: SparkGate

## 1. Visión General del Sistema

SparkGate es un sistema de mitigación de gestión insegura de contraseñas. Este backend actúa como una API RESTful intermediaria entre la extensión de Chrome (Frontend), los servicios de validación de brechas de seguridad (Have I Been Pwned - HIBP), la base de datos (Supabase), y el motor de Inteligencia Artificial (Llama 3.2 vía Ollama).  

## 2. Stack Tecnológico
```
    Lenguaje: Python 3.10+  

    Framework Web: FastAPI (para alto rendimiento asíncrono y autogeneración de OpenAPI).  

    Validación y Serialización: Pydantic V2.  

    Cliente HTTP Asíncrono: httpx (para peticiones no bloqueantes a HIBP y Ollama).  

    Base de Datos y Autenticación: supabase (Python Client).  

    Motor LLM: Llama 3.2 (comunicación mediante API REST local de Ollama).  
```

## 3. Estructura de Directorios Requerida

El proyecto debe adherirse estrictamente a la siguiente estructura modular:  

```bash
sparkgate-api/
├── app/
│   ├── init.py
│   ├── main.py                 # Instancia de FastAPI y configuración CORS
│   ├── api/
│   │   ├── dependencies.py     # Funciones inyectables (ej. extraer/validar JWT de Supabase)
│   │   └── routes/
│   │       ├── auth.py         # Endpoints de login/registro (proxy a Supabase)
│   │       ├── passwords.py    # Endpoints principales de evaluación y generación
│   │       └── health.py       # GET /health para monitoreo de servicios
│   ├── core/
│   │   ├── config.py           # Clase Settings(BaseSettings) para variables de entorno
│   │   └── exceptions.py       # Manejadores de excepciones HTTP personalizados
│   ├── schemas/
│   │   ├── passwords.py        # Modelos Pydantic para Request/Response de contraseñas
│   │   └── common.py           # Modelos compartidos (ej. respuestas de error genéricas)
│   └── services/
│       ├── ai_engine.py        # Lógica de prompts y comunicación con API de Ollama
│       ├── hibp_client.py      # Lógica K-Anonymity (SHA-1 parcial) contra HIBP
│       └── db_client.py        # Abstracción de operaciones con Supabase
├── .env.example                # Plantilla de variables de entorno
├── .gitignore
├── requirements.txt            # Dependencias
└── README.md  
```

## 4. Modelos de Datos (Schemas Pydantic)

Deben definirse en app/schemas/passwords.py:  
```bash
from pydantic import BaseModel, Field  

class PasswordEvaluateRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Contraseña en texto plano a evaluar")
    context: str | None = Field(default=None, description="Contexto opcional (ej. 'banco', 'red social')")  

class PasswordEvaluateResponse(BaseModel):
    is_compromised: bool
    pwned_count: int
    ai_score: int = Field(..., ge=0, le=100)
    ai_feedback: str
    ai_suggestions: list[str]  

class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=12, le=64)
    context: str | None = None
    complexity_level: str = Field(default="high") # high, medium, memorable  

class PasswordGenerateResponse(BaseModel):
    generated_password: str
    explanation: str # Explicación de la IA sobre por qué es segura  
```
## 5. Especificación de Endpoints (Capa de Presentación)

### 5.1. POST /api/v1/passwords/evaluate

    Propósito: Evalúa la seguridad de una contraseña.  

    Flujo:

        Llama a hibp_client.check_password(pwd).  

        Pasa la contraseña y el resultado de HIBP a ai_engine.evaluate_security(pwd, is_pwned).  

        Retorna el resultado combinado.  

### 5.2. POST /api/v1/passwords/generate

    Propósito: Genera una contraseña segura adaptada al contexto del usuario.  

    Flujo:

        Construye el prompt con los parámetros (longitud, contexto, complejidad).  

        Llama a ai_engine.generate_password(...).  

        Opcional: valida la contraseña generada contra HIBP antes de retornarla.  

### 5.3. GET /api/v1/health

    Propósito: Verificar el estado de las dependencias (Ollama corriendo, Supabase accesible).  

## 6. Lógica de Servicios (Capa de Negocio)

    hibp_client.py:

        Obligatorio: Utilizar el modelo de K-Anonymity. Nunca enviar la contraseña en texto plano. Hashear localmente con SHA-1, enviar los primeros 5 caracteres a la API [https://api.pwnedpasswords.com/range/](https://api.pwnedpasswords.com/range/), y comparar los sufijos localmente.  

    ai_engine.py:      

        Debe comunicarse con Ollama a través de llamadas HTTP asíncronas (httpx.AsyncClient) hacia http://localhost:11434/api/generate.  

        Se deben diseñar System Prompts estrictos para evitar alucinaciones, exigiendo respuestas en formato JSON estructurado.  

    main.py (CORS):

        Configurar CORSMiddleware para permitir peticiones desde orígenes específicos (importante para extensiones de Chrome que usan esquemas chrome-extension://).  

## 7. Instrucciones Estrictas para la Generación de Código (Prompt System Rules)
  

Al momento de programar esto, el modelo de IA debe respetar las siguientes reglas:  

    Tipado Estricto: Usar type hints en todas las funciones y dependencias de FastAPI.  

    Asincronismo: Todas las llamadas a red (HIBP, Ollama, Supabase) deben usar async def y librerías asíncronas (httpx, versiones async de clientes DB) para no bloquear el Event Loop.  

    Inyección de Dependencias: Usar el sistema de dependencias de FastAPI (Depends()) para manejar las sesiones de Supabase y las conexiones HTTP.  

    Manejo de Errores: Evitar bloques try/except silenciosos. Usar HTTPException con códigos de estado adecuados (400, 401, 500, 502, 503) para que la extensión de Chrome pueda reaccionar adecuadamente.  

    Seguridad: No exponer tokens, variables de entorno ni la lógica de HIBP en respuestas de error detalladas.[cite: 2]