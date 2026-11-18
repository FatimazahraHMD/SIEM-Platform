from elasticsearch import Elasticsearch
from config import ELASTIC_HOST, ELASTIC_USER, ELASTIC_PASSWORD

def connect():
    es = Elasticsearch(ELASTIC_HOST, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD))
    if es.ping():
        print("[OK] Connexion à Elasticsearch réussie.")
        return es
    print("[ERREUR] Impossible de se connecter à Elasticsearch.")
    return None
