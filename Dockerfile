# Dockerfile.api
# Stage 1: Build
FROM python:3.9-slim as build

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copy the .env file
COPY .env .env

COPY . .

# Stage 2: Production
FROM python:3.9-slim

WORKDIR /app

COPY --from=build /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /app /app

EXPOSE 4500

CMD ["gunicorn", "--bind", "0.0.0.0:4500", "app:app"]
