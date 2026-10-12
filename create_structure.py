import os

dirs = [
    "frontend/src/components",
    "frontend/src/pages",
    "frontend/src/dashboards",
    "frontend/src/incidents",
    "frontend/src/threat-intelligence",
    "frontend/src/api",
    "backend/app/api",
    "backend/app/services",
    "backend/app/models",
    "backend/app/database",
    "backend/app/schemas",
    "ml/data/raw",
    "ml/data/processed",
    "ml/preprocessing",
    "ml/anomaly_detection",
    "ml/classification",
    "ml/graph_learning",
    "ml/explainability",
    "ml/training",
    "ml/evaluation",
    "ml/saved_models",
    "intelligence/mitre",
    "intelligence/threat_feeds",
    "intelligence/rag",
    "intelligence/agent",
    "network/packet_capture",
    "network/flow_extraction",
    "network/parsers",
    "tests",
]

files = [
    "docker-compose.yml",
    ".env.example",
    "README.md",
    "frontend/package.json",
    "backend/requirements.txt",
    "backend/app/main.py",
    "backend/app/api/traffic.py",
    "backend/app/api/detection.py",
    "backend/app/api/incidents.py",
    "backend/app/api/intelligence.py",
    "backend/app/api/investigation.py",
    "backend/app/services/traffic_service.py",
    "backend/app/services/detection_service.py",
    "backend/app/services/threat_service.py",
    "backend/app/services/investigation_service.py",
    "backend/app/models/incident.py",
    "backend/app/models/network_flow.py",
    "backend/app/models/intelligence.py",
    "ml/preprocessing/clean_data.py",
    "ml/preprocessing/feature_engineering.py",
    "ml/preprocessing/feature_schema.py",
    "ml/anomaly_detection/autoencoder.py",
    "ml/anomaly_detection/isolation_forest.py",
    "ml/anomaly_detection/ensemble.py",
    "ml/classification/random_forest.py",
    "ml/classification/xgboost_model.py",
    "ml/classification/transformer.py",
    "ml/graph_learning/gnn_model.py",
    "ml/explainability/shap_explainer.py",
    "intelligence/rag/embeddings.py",
    "intelligence/rag/retrieval.py",
    "intelligence/rag/ingestion.py",
    "intelligence/agent/tools.py",
    "intelligence/agent/workflow.py",
    "intelligence/agent/report_generator.py",
]

for d in dirs:
    os.makedirs(d, exist_ok=True)

for f in files:
    d = os.path.dirname(f)
    if d:
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(f):
        with open(f, "w", encoding="utf-8") as fp:
            pass

print("Structure created successfully.")
