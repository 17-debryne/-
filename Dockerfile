# 在项目根执行: docker compose build && docker compose up -d
FROM python:3.12-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MASP_HOST=0.0.0.0 \
    MASP_PORT=8765

COPY pyproject.toml README.txt /app/
COPY mcp_agent_safe_protecter /app/mcp_agent_safe_protecter/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e .

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request;p=os.environ.get('MASP_PORT','8765');urllib.request.urlopen(f'http://127.0.0.1:{p}/health',timeout=3)"

CMD ["python", "-m", "mcp_agent_safe_protecter.run_http"]
