FROM python:3.11-slim

WORKDIR /app

# Copiar requirements primeiro
COPY requirements.txt .

# Instalar dependências Python sem dependências do sistema
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY src/ ./src/

# Expor porta
EXPOSE 3000

# Variáveis de ambiente
ENV FLASK_APP=src/main.py
ENV FLASK_ENV=production

# Health check simples
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:3000/health')" || exit 1

# Comando para iniciar a aplicação
CMD ["python", "src/main.py"]

