# Lab 17 – RAG Pipeline and Vector Index Comparison

## Folder contents

- `lab_01_rag_pipeline.py` – Lab 17.1 document chunking, mock embeddings,
  MongoDB storage, brute-force retrieval, prompt construction and in-process
  conversation history.
- `lab_02_hnsw_vs_ivf.py` – Lab 17.2 offline NumPy demonstration comparing
  an IVF-style index and a simplified single-layer NSW/HNSW-like graph against
  exact brute-force search.
- `config/connection.py` – shared MongoDB connection helpers.
- `requirements.txt` – Python dependencies.

## Requirements

- Python 3.10 or newer recommended.
- Docker Desktop running the Lab 16 MongoDB container, published on host
  port `27222`, OR another MongoDB server whose URI you provide.
- Run commands from this project folder.

## Setup on Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If your MongoDB server is the Lab 16 Docker container, its connection URI
defaults to `mongodb://127.0.0.1:27222`. Otherwise set the URI before running:

```powershell
$env:MONGO_URI = "mongodb://127.0.0.1:27017"
```

Check the Lab 16 MongoDB container is running:

```powershell
docker ps --filter "name=lab16-mongodb"
```

## Run Lab 17.1

```powershell
python lab_01_rag_pipeline.py
```

The script resets only `nosql_labs.rag_documents`, chunks the included
NoSQL documents, stores embeddings and retrieves relevant chunks.

Important scope note: the supplied Lab 17.1 implementation uses deterministic
mock embeddings and a mock LLM response so it can run without API keys. It
does not call Voyage AI, does not create an Atlas Vector Search index, and
does not call a real LLM. Retrieval is local brute-force cosine similarity.
Conversation history in this version is held in process memory, not persisted
to the `conversations` MongoDB collection. The `find()` projection was
corrected in this packaged copy so retrieval reads the stored documents.

## Run Lab 17.2

```powershell
python lab_02_hnsw_vs_ivf.py
```

This experiment is offline and does not need MongoDB. It creates synthetic
unit-normalized vectors, computes exact ground truth, and compares an IVF
implementation with a simplified single-layer NSW graph.

Important scope note: this is an educational approximation, not MongoDB
Atlas's actual HNSW or IVF implementation. Its dataset settings are 3,000
vectors of 64 dimensions and 20 queries (as configured in the script), rather
than the 5,000 x 384 / 100-query Atlas benchmark described in the lab brief.
The script reports measured results from your machine; do not replace them
with the illustrative numbers in the lab handout.

## Safety / data note

Lab 17.1 drops and recreates only the `nosql_labs.rag_documents` collection
each time it starts. It does not drop other databases or collections.
