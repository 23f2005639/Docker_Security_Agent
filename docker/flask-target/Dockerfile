FROM python:3.8

RUN pip install flask requests

COPY app.py /app/app.py
WORKDIR /app

CMD ["python", "app.py"]
