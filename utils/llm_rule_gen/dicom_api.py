import os
import tempfile
import uvicorn
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Import langchain components with new import pattern
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.vectorstores import FAISS
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_community.document_loaders import (
    PyPDFLoader,
    TextLoader,
    Docx2txtLoader,
)
# Add a SimpleMarkdownLoader class to avoid unstructured dependency
from langchain_core.documents import Document

# Simple markdown loader that doesn't require unstructured
class SimpleMarkdownLoader:
    def __init__(self, file_path):
        self.file_path = file_path

    def load(self):
        with open(self.file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # Create a single document with the entire content
        return [Document(page_content=content, metadata={"source": self.file_path})]

# Load environment variables from .env file
load_dotenv()

# Get the OpenAI API key from environment variables
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable is not set. Please set it in the .env file.")

# Get the model name from environment variables or use default
model_name = os.getenv("OPENAI_MODEL", "gpt-4-1106-preview")

# File handling configurations
ACCEPTED_FILETYPES = {
    ".pdf": PyPDFLoader,
    ".txt": TextLoader,
    ".md": SimpleMarkdownLoader,
    ".docx": Docx2txtLoader,
}

# Create FastAPI app
app = FastAPI(
    title="DICOM Documentation Assistant API",
    description="An API for answering questions about DICOM protocols based on uploaded documentation",
    version="1.0.0",
)

# Add CORS middleware to allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
retriever = None
conversation_chain = None
chat_history = []
processed_files_info = []

# Pydantic models for API requests and responses
class QuestionRequest(BaseModel):
    question: str

class QuestionResponse(BaseModel):
    answer: str
    source_files: Optional[List[str]] = None

class ProcessingResponse(BaseModel):
    status: str
    message: str
    processed_files: List[Dict[str, Any]]

@app.get("/")
async def root():
    """Root endpoint, provides basic information about the API."""
    return {
        "name": "DICOM Documentation Assistant API",
        "description": "API for answering questions about DICOM protocols based on uploaded documentation",
        "endpoints": {
            "/upload": "POST - Upload DICOM documentation files",
            "/ask": "POST - Ask a question about DICOM protocols",
            "/status": "GET - Check the status of the API and uploaded documents",
            "/reset": "POST - Reset the API and clear all uploaded documents"
        }
    }

@app.post("/upload", response_model=ProcessingResponse)
async def upload_files(files: List[UploadFile] = File(...)):
    """Upload DICOM documentation files to be processed and used for answering questions."""
    global retriever, conversation_chain, processed_files_info

    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    # Clear any previous uploaded files
    processed_files_info = []

    # Initialize document processing variables
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=100
    )
    docs = []

    # Process each file
    for file in files:
        file_content = await file.read()
        file_extension = os.path.splitext(file.filename)[1].lower()

        if file_extension not in ACCEPTED_FILETYPES:
            processed_files_info.append({
                "filename": file.filename,
                "status": "error",
                "message": f"Unsupported file type: {file_extension}"
            })
            continue

        try:
            # Create a temporary file
            with tempfile.NamedTemporaryFile(suffix=file.filename, delete=False) as temp_file:
                temp_file.write(file_content)
                temp_file.flush()
                temp_file_path = temp_file.name

            try:
                # Get the appropriate loader for the file type
                loader = ACCEPTED_FILETYPES[file_extension](temp_file_path)
                loaded_docs = loader.load()

                # Split into chunks and add to docs collection
                split_docs = text_splitter.split_documents(loaded_docs)
                docs.extend(split_docs)

                processed_files_info.append({
                    "filename": file.filename,
                    "status": "success",
                    "chunks": len(split_docs)
                })
            finally:
                # Make sure to clean up the temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)

        except Exception as e:
            processed_files_info.append({
                "filename": file.filename,
                "status": "error",
                "message": str(e)
            })

    # If no files were successfully processed
    successful_files = [f for f in processed_files_info if f["status"] == "success"]
    if not successful_files:
        return ProcessingResponse(
            status="error",
            message="No files were successfully processed",
            processed_files=processed_files_info
        )

    # Create vector store and retriever
    try:
        embeddings = OpenAIEmbeddings()
        vector_store = FAISS.from_documents(docs, embeddings)
        retriever = vector_store.as_retriever(search_kwargs={"k": 4})

        # Create the LLM
        llm = ChatOpenAI(model_name=model_name, temperature=0)

        # Create a template for QA system with chat history
        template = """
        You are an assistant specialized in answering questions about DICOM (Digital Imaging and Communications in Medicine) protocols.
        Use the following context to answer the question. If the answer cannot be found in the context, say "I don't have information about that in the provided documentation."

        Context: {context}

        Chat History: {chat_history}

        Question: {question}

        Answer:
        """

        # Create the prompt from the template
        prompt = ChatPromptTemplate.from_template(template)

        # Define the RAG chain
        conversation_chain = (
            {"context": retriever,
             "question": RunnablePassthrough(),
             "chat_history": lambda _: str(chat_history)}
            | prompt
            | llm
            | StrOutputParser()
        )

        return ProcessingResponse(
            status="success",
            message=f"Successfully processed {len(successful_files)} files with {len(docs)} text chunks",
            processed_files=processed_files_info
        )
    except Exception as e:
        return ProcessingResponse(
            status="error",
            message=f"Error setting up QA system: {str(e)}",
            processed_files=processed_files_info
        )

@app.post("/ask", response_model=QuestionResponse)
async def ask_question(request: QuestionRequest):
    """Ask a question about DICOM protocols based on the uploaded documentation."""
    global retriever, conversation_chain, chat_history

    if not conversation_chain:
        raise HTTPException(
            status_code=400,
            detail="No documents have been processed. Please upload documentation files first."
        )

    # Add user message to chat history
    chat_history.append(f"User: {request.question}")

    try:
        # Get answer using the conversation chain
        answer = await conversation_chain.ainvoke(request.question)

        # Add assistant response to chat history
        chat_history.append(f"Assistant: {answer}")

        # Get source files if we can identify them
        source_files = []
        if retriever and hasattr(retriever, "vectorstore"):
            # This attempt to get sources might not work depending on the specific retriever implementation
            try:
                docs = retriever.get_relevant_documents(request.question)
                source_files = list(set([doc.metadata.get("source", "Unknown") for doc in docs if "source" in doc.metadata]))
            except:
                pass

        return QuestionResponse(
            answer=answer,
            source_files=source_files if source_files else None
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating response: {str(e)}"
        )

@app.get("/status")
async def get_status():
    """Get the current status of the API and information about uploaded documents."""
    global processed_files_info, retriever

    return {
        "status": "ready" if retriever else "not_ready",
        "processed_files": processed_files_info,
        "chat_history_length": len(chat_history) // 2  # Divide by 2 because each QA pair is 2 entries
    }

@app.post("/reset")
async def reset_api():
    """Reset the API by clearing all uploaded documents and chat history."""
    global retriever, conversation_chain, chat_history, processed_files_info

    retriever = None
    conversation_chain = None
    chat_history = []
    processed_files_info = []

    return {"status": "success", "message": "API reset successfully"}

if __name__ == "__main__":
    uvicorn.run("dicom_api:app", host="0.0.0.0", port=8080, reload=True)