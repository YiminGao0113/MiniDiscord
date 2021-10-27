FROM python:3.6


COPY  requirements.txt /requirements.txt
RUN pip install -r requirements.txt
WORKDIR /app
COPY . /app
EXPOSE 5000
CMD ["python", "./app.py"]