"""Test both connections before running bootstrap."""
import os
from dotenv import load_dotenv
load_dotenv()

# Test Elasticsearch
print("Testing Elasticsearch...")
from elasticsearch import Elasticsearch
es = Elasticsearch(os.getenv("ES_HOST"), api_key=os.getenv("ES_API_KEY"))
if es.ping():
    print("✅ Elasticsearch connected!")
    info = es.info()
    print(f"   Cluster: {info['cluster_name']}")
else:
    print("❌ Elasticsearch failed — check ES_HOST and ES_API_KEY")

# Test AWS Nova
print("\nTesting AWS Bedrock (Nova)...")
import boto3, json

try:
    bedrock = boto3.client(
        service_name="bedrock-runtime",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    response = bedrock.invoke_model(
        modelId="amazon.nova-lite-v1:0",
        body=json.dumps({
            "messages": [{"role": "user", "content": [{"text": "Say hello in 5 words."}]}],
            "inferenceConfig": {"maxTokens": 50}
        })
    )
    body = json.loads(response["body"].read())
    reply = body["output"]["message"]["content"][0]["text"]
    print(f"✅ Nova connected! Response: '{reply}'")
except Exception as e:
    print(f"❌ Nova failed: {e}")