FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 80

# Écoute sur le port 80 (HTTP standard) pour que le scanner puisse analyser
# la cible via "http://demo-target" sans avoir à préciser de port.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]
