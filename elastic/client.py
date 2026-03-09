"""
ELASTICSEARCH CLIENT
=====================
This file creates a connection to Elasticsearch.

Think of Elasticsearch like a very smart database that:
1. Stores JSON documents (our cloud resources and findings)
2. Searches them extremely fast using both keywords AND meaning (vectors)
3. Can run analytics queries (like SQL but for JSON)

We use it as the "long-term memory" of our security copilot.
"""

from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv

load_dotenv()

def get_es_client():
    """
    Creates and returns an Elasticsearch client.
    The client is how Python talks to the ES database.
    """
    client = Elasticsearch(
        os.getenv("ES_HOST"),
        api_key=os.getenv("ES_API_KEY"),
        verify_certs=True
    )

    # Test connection
    if client.ping():
        print("✅ Connected to Elasticsearch!")
    else:
        print("❌ Could not connect to Elasticsearch!")

    return client

# Singleton — one client shared across the app
es = get_es_client()