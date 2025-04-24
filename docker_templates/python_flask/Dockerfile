FROM python:3.9-slim

# 安装必要工具
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 安装Python依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 创建健康检查文件
RUN echo "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef health():\n    return 'healthy'\n\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', port=5000)" > app.py

# 健康检查
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# 暴露端口
EXPOSE 5000

# 启动Flask应用
CMD ["python", "app.py"] 