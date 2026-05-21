# Deployment Guide

## Local Deployment

Cyber Sentinel X can be run locally with Python 3.8+ and pip. Install the required packages and launch the Streamlit app:

```bash
pip install -r requirements.txt
streamlit run app.py
```

The application will start on `http://localhost:8501`. Use the web interface to upload logs, generate demo data and explore the features.

## Streamlit Cloud

To deploy the app on Streamlit Cloud:

1. Push the repository to GitHub (it is already structured for deployment).
2. Sign in to [Streamlit Cloud](https://streamlit.io/cloud) and click **New app**.
3. Connect your GitHub account and choose the repository and branch containing Cyber Sentinel X.
4. Set the **Main file path** to `app.py`.
5. Configure a secret for any API keys if necessary (Cyber Sentinel X does not require external keys by default).
6. Deploy the app. Streamlit Cloud will automatically install dependencies from `requirements.txt` and run the application.

## Hugging Face Spaces (Alternative)

Cyber Sentinel X can also be deployed to [Hugging Face Spaces](https://huggingface.co/spaces) using the Streamlit SDK. The process is similar:

1. Create a new Space and select **Streamlit** as the SDK.
2. Provide the GitHub repository URL or upload the project files.
3. Ensure the `requirements.txt` file is present.
4. Launch the Space; Hugging Face will build the environment and run the app.

## Render or Other PaaS Platforms

The project can be containerised and deployed on platforms like Render, Heroku or AWS. Create a Dockerfile that installs the dependencies and runs `streamlit run app.py`. Push the Dockerfile and configure the platform to expose port 8501.