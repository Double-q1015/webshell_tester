FROM python:3.9-slim

# install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# set working directory
WORKDIR /app

# install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# create health check file
RUN echo "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef health():\n    return 'healthy'\n\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', port=5000)" > app.py

# health check
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# expose port
EXPOSE 5000

# start flask application
CMD ["python", "app.py"] 