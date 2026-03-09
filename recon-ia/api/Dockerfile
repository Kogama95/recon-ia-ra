FROM python:3.9
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y nmap masscan && rm -rf /var/lib/apt/lists/*
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
ENV FLASK_APP=main.py
CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]