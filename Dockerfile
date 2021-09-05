FROM python:3.8
WORKDIR backend
COPY . .
RUN pip install -r req.txt
EXPOSE 5000
CMD ["python", "app.py"]