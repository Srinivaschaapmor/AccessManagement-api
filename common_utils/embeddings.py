from langchain_community.embeddings import SentenceTransformerEmbeddings

def default_embeddings():
    return SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
    
def openai_embeddings():
    pass
