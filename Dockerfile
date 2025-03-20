# Use the official Python image
FROM python:3.13-rc-slim

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Create the static directory to hold the background image
#RUN mkdir -p /app/static

# Install Python dependencies
RUN pip install -r requirements.txt

# Expose the port Gunicorn will run on
EXPOSE 5000

# Run the Flask app with Gunicorn
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]
