FROM python:3.10-slim

WORKDIR /app

# Copy all files and set ownership to user 1000 (Hugging Face Spaces runs as user 1000)
COPY --chown=1000:1000 . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create uploads directory if not present and ensure permissions
RUN mkdir -p uploads && chown -R 1000:1000 /app

# Switch to non-root user
USER 1000

# Expose the default port for Hugging Face Spaces
EXPOSE 7860

# Run gunicorn binding to port 7860
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "app:app"]
