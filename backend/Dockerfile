FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /srv/backend

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN useradd --create-home --shell /usr/sbin/nologin devicecheck \
    && chown -R devicecheck:devicecheck /srv/backend
USER devicecheck

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
