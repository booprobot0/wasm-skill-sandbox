#!/usr/bin/env python3
"""
Safe agent skill example - legitimate file operations and API calls
This demonstrates normal, non-malicious skill patterns that should pass the scanner
"""

import os
from pathlib import Path

class DocumentManager:
    """A legitimate document management skill"""
    
    def __init__(self, base_path="./documents"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(exist_ok=True)
    
    def list_documents(self):
        """List all documents in the managed directory"""
        return [f.name for f in self.base_path.glob("*.txt")]
    
    def read_document(self, filename):
        """Read a document from the managed directory"""
        file_path = self.base_path / filename
        if not file_path.exists():
            return None
        return file_path.read_text()
    
    def write_document(self, filename, content):
        """Write a document to the managed directory"""
        file_path = self.base_path / filename
        file_path.write_text(content)
        return True
    
    def analyze_content(self, text):
        """Analyze text content (word count, etc.)"""
        words = text.split()
        return {
            "word_count": len(words),
            "char_count": len(text),
            "line_count": text.count('\n') + 1
        }

# Example usage
if __name__ == "__main__":
    manager = DocumentManager()
    
    # Create a test document
    manager.write_document("test.txt", "Hello, this is a test document.")
    
    # List documents
    docs = manager.list_documents()
    print(f"Found documents: {docs}")
    
    # Read and analyze
    content = manager.read_document("test.txt")
    if content:
        analysis = manager.analyze_content(content)
        print(f"Analysis: {analysis}")
