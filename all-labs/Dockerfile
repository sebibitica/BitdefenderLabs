FROM python:3.10

WORKDIR /app/src
COPY requirements.txt /app/src/requirements.txt
RUN pip install -r requirements.txt
COPY . /app/src

CMD python server.py