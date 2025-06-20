import socket
import os
import json
import argparse
import threading
import logging
from cryptography.fernet import Fernet
import shutil
import hashlib
import functools
from tqdm import tqdm

# --- Configuration ---
CHUNK_SIZE = 4 * 1024 * 1024  # 4MB per chunk
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
CHUNKS_DIR = "prepared_chunks"

# --- Helper Functions ---
def sha256_file(filepath):
    """Calculates the SHA256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_key():
    """Generates a new encryption key."""
    return Fernet.generate_key()

def get_cipher(key):
    """Creates a cipher object from a key."""
    return Fernet(key)

# --- Core Logic ---
def prepare_file(file_path):
    """
    Splits a large file into smaller, encrypted chunks for transfer.
    Generates a unique encryption key for this file transfer.
    Returns (file_id, key) on success, (None, None) on failure.
    """
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return None, None

    file_name = os.path.basename(file_path)
    os.makedirs(CHUNKS_DIR, exist_ok=True)
    output_dir = os.path.join(CHUNKS_DIR, f"{file_name}_chunks")
    file_id = os.path.basename(output_dir)

    if os.path.exists(output_dir):
        logging.warning(f"Chunks directory '{output_dir}' already exists. Removing and regenerating.")
        shutil.rmtree(output_dir)

    os.makedirs(output_dir, exist_ok=True)

    key = generate_key()
    cipher = get_cipher(key)
    key_path = os.path.join(output_dir, 'key.txt')
    with open(key_path, 'wb') as f:
        f.write(key)

    logging.info(f"Generated new one-time key for '{file_name}'.")

    total_size = os.path.getsize(file_path)
    chunk_count = (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE

    logging.info(f"Calculating SHA256 checksum for {file_name}...")
    checksum = sha256_file(file_path)
    logging.info(f"Checksum: {checksum}")

    metadata = {
        "original_filename": file_name,
        "total_size": total_size,
        "chunk_size": CHUNK_SIZE,
        "total_chunks": chunk_count,
        "sha256_checksum": checksum
    }

    with open(os.path.join(output_dir, 'metadata.json'), 'w') as f:
        json.dump(metadata, f)

    logging.info(f"Preparing and encrypting '{file_name}' into {chunk_count} chunks...")

    try:
        with open(file_path, 'rb') as f_in:
            for i in tqdm(range(chunk_count), desc="Preparing & Encrypting File", unit="chunk", ncols=100):
                chunk_data = f_in.read(CHUNK_SIZE)
                encrypted_data = cipher.encrypt(chunk_data)
                chunk_filename = os.path.join(output_dir, f'chunk_{i}')
                with open(chunk_filename, 'wb') as f_out:
                    f_out.write(encrypted_data)
        logging.info("File preparation and encryption complete.")
        return file_id, key
    except Exception as e:
        logging.error(f"An error occurred during file preparation: {e}")
        shutil.rmtree(output_dir)
        return None, None

def handle_client(conn, addr, file_id, server_key_bytes):
    """Handles a single client connection."""
    logging.info(f"New connection from {addr}")

    try:
        while True:
            # Receive request (max 4KB for request)
            request_data = conn.recv(4096)
            if not request_data:
                break

            request = json.loads(request_data.decode('utf-8'))

            action = request.get('action')
            key_str = request.get('key')

            # --- Authentication and Initialization ---
            if not key_str or key_str.encode('utf-8') != server_key_bytes:
                conn.sendall(json.dumps({"status": "error", "message": "Authentication failed: Invalid key"}).encode('utf-8'))
                break # Terminate connection on auth failure

            # Cipher object is no longer needed for on-the-fly encryption.

            chunk_dir_path = os.path.join(CHUNKS_DIR, file_id)

            # --- Action Handling ---
            if action == 'get_metadata':
                metadata_path = os.path.join(chunk_dir_path, 'metadata.json')
                if not os.path.exists(metadata_path):
                    conn.sendall(json.dumps({"status": "error", "message": "File metadata not found on server."}).encode('utf-8'))
                    continue
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                conn.sendall(json.dumps({"status": "ok", "metadata": metadata}).encode('utf-8'))

            elif action == 'get_chunk':
                chunk_num = request.get('chunk_num')
                chunk_path = os.path.join(chunk_dir_path, f'chunk_{chunk_num}')

                if not os.path.exists(chunk_path):
                    conn.sendall(json.dumps({"status": "error", "message": f"Chunk {chunk_num} not found"}).encode('utf-8'))
                    continue

                with open(chunk_path, 'rb') as f:
                    encrypted_data = f.read()

                # Data is already encrypted.

                # Send header first: 4 bytes for length of encrypted data
                conn.sendall(len(encrypted_data).to_bytes(4, 'big'))
                # Send encrypted data
                conn.sendall(encrypted_data)
                # logging.info(f"Sent chunk {chunk_num} of {file_id} to {addr}") # This is too noisy for high performance

    except (ConnectionResetError, BrokenPipeError):
        logging.warning(f"Client {addr} disconnected unexpectedly.")
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON received from {addr}.")
    except Exception as e:
        logging.error(f"An error occurred with client {addr}: {e}")
    finally:
        logging.info(f"Closing connection for {addr}")
        conn.close()

def start_server(host, port, filepath):
    """Prepares the file and starts the file transfer server."""
    file_id, key = prepare_file(filepath)
    if not file_id:
        logging.error(f"Could not prepare file {filepath}. Aborting server start.")
        return

    print("--- Server Ready to Share ---")
    print(f"File: {os.path.basename(filepath)}")
    print(f"ONE-TIME-KEY: {key.decode('utf-8')}")
    print("\nProvide the client with the ONE-TIME-KEY.")
    print("-----------------------------")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        logging.info(f"Server listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            
            def handler_wrapper(c, a):
                handle_client(c, a, file_id=file_id, server_key_bytes=key)

            client_thread = threading.Thread(target=handler_wrapper, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()
            
    except OSError as e:
        logging.error(f"Failed to bind to {host}:{port}. Error: {e}")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        server_socket.close()
        logging.info("Server shut down.")


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="High-performance, secure file transfer server.")
    parser.add_argument('filepath', type=str, help='The path to the large file to prepare and serve.')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the server to.')
    parser.add_argument('--port', type=int, default=9999, help='Port to listen on.')

    args = parser.parse_args()

    os.makedirs(CHUNKS_DIR, exist_ok=True)
    logging.info(f"Storing prepared chunks in '{CHUNKS_DIR}' directory.")
    start_server(args.host, args.port, args.filepath)
