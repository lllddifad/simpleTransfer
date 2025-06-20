import socket
import os
import json
import argparse
import logging
import concurrent.futures
from cryptography.fernet import Fernet
from tqdm import tqdm
import shutil
import hashlib
import queue

# --- Configuration ---
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
DOWNLOAD_DIR = "downloads"
TEMP_DIR_SUFFIX = "_temp_chunks"

# --- Helper Functions ---
def sha256_file(filepath):
    """Calculates the SHA256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_cipher(key):
    """Creates a cipher object from a key."""
    return Fernet(key)

def receive_all(sock, length):
    """Helper to receive a specific number of bytes from a socket."""
    data = bytearray()
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

# --- Core Logic ---
def chunk_worker(server_ip, port, key, temp_dir, log_path, chunk_queue, pbar):
    """
    Worker thread that connects to the server and downloads chunks from the queue.
    Each worker manages its own persistent connection.
    """
    cipher = get_cipher(key.encode('utf-8'))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, port))
            while True:
                try:
                    chunk_num = chunk_queue.get_nowait()
                except queue.Empty:
                    break  # No more chunks

                try:
                    # Send request for the chunk
                    request = {
                        "action": "get_chunk",
                        "key": key,
                        "chunk_num": chunk_num
                    }
                    sock.sendall(json.dumps(request).encode('utf-8'))

                    # Receive header (4 bytes for length)
                    header = receive_all(sock, 4)
                    if not header:
                        raise ConnectionError("Failed to receive chunk header from server.")

                    encrypted_data_len = int.from_bytes(header, 'big')

                    # Receive encrypted data
                    encrypted_data = receive_all(sock, encrypted_data_len)
                    if not encrypted_data:
                        raise ConnectionError("Failed to receive encrypted chunk data from server.")

                    # Decrypt and save
                    decrypted_data = cipher.decrypt(bytes(encrypted_data))

                    chunk_path = os.path.join(temp_dir, f'chunk_{chunk_num}')
                    with open(chunk_path, 'wb') as f:
                        f.write(decrypted_data)

                    # Log the successful download
                    with open(log_path, 'a') as f_log:
                        f_log.write(f"{chunk_num}\n")

                    pbar.update(1)
                except Exception as e:
                    logging.error(f"Failed to process chunk {chunk_num}: {e}. Leaving for retry on next run.")
                finally:
                    chunk_queue.task_done()
    except Exception as e:
        logging.error(f"A worker thread failed to connect or run: {e}")

def download_file(server_ip, port, key, max_workers=10):
    """Main function to download a file from the server."""
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    
    logging.info(f"Requesting metadata from server...")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, port))
            
            # Request metadata
            request = {
                "action": "get_metadata",
                "key": key
            }
            sock.sendall(json.dumps(request).encode('utf-8'))
            
            response_data = sock.recv(4096) # Assuming metadata response is < 4KB
            if not response_data:
                raise ConnectionError("Failed to get metadata from server.")

            response = json.loads(response_data.decode('utf-8'))

            if response.get('status') != 'ok':
                raise Exception(f"Server error on metadata request: {response.get('message')}")

        metadata = response['metadata']
        original_filename = metadata['original_filename']
        total_chunks = metadata['total_chunks']
        total_size = metadata['total_size']
        server_checksum = metadata['sha256_checksum']
        
        logging.info(f"Starting download of '{original_filename}' ({total_chunks} chunks).")
        logging.info(f"Expected SHA256: {server_checksum}")

        temp_dir = os.path.join(DOWNLOAD_DIR, f"{original_filename}{TEMP_DIR_SUFFIX}")
        os.makedirs(temp_dir, exist_ok=True)
        log_path = os.path.join(temp_dir, 'download.log')

        # --- Resume Logic ---
        existing_chunks = set()
        logging.info(f"Checking for download log at {log_path}...")
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line: # Avoid empty lines
                        try:
                            existing_chunks.add(int(line))
                        except ValueError:
                            logging.warning(f"Found invalid entry in log file: '{line}'. Ignoring.")
        except FileNotFoundError:
            logging.info("Log file not found. Starting a fresh download.")

        if existing_chunks:
            logging.info(f"Found {len(existing_chunks)} completed chunks in log. Resuming download.")

        chunks_to_download = [i for i in range(total_chunks) if i not in existing_chunks]

        if not chunks_to_download:
            logging.info("All chunks already present according to log.")
        else:
            logging.info(f"Requesting {len(chunks_to_download)} missing chunks using {max_workers} workers.")
            
            chunk_queue = queue.Queue()
            for i in chunks_to_download:
                chunk_queue.put(i)

            with tqdm(total=len(chunks_to_download), desc="Downloading Chunks") as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for _ in range(max_workers):
                        executor.submit(chunk_worker, server_ip, port, key, temp_dir, log_path, chunk_queue, pbar)
                    
                    chunk_queue.join() # Blocks until all tasks in the queue are processed

        # --- Verification after download attempt ---
        final_downloaded_chunks = set()
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line: final_downloaded_chunks.add(int(line))
        except FileNotFoundError:
            pass # No log file means no chunks were downloaded

        if len(final_downloaded_chunks) != total_chunks:
            logging.error("Download incomplete. Some chunks failed to download. Please run the client again to retry.")
            return

        # Reassemble the file
        output_path = os.path.join(DOWNLOAD_DIR, original_filename)
        reassemble_chunks(temp_dir, output_path, total_chunks, total_size)

        # Verify checksum
        logging.info("Verifying file integrity...")
        client_checksum = sha256_file(output_path)
        logging.info(f"Client SHA256: {client_checksum}")

        if client_checksum == server_checksum:
            logging.info("Checksum verification successful! File is intact.")
        else:
            logging.error("CHECKSUM MISMATCH! The downloaded file may be corrupted.")

    except Exception as e:
        logging.error(f"An error occurred during download: {e}")
    finally:
        # Optional: clean up temp dir even on failure
        if os.path.exists(temp_dir):
            # shutil.rmtree(temp_dir)
            pass # Keep for debugging for now


def reassemble_chunks(temp_dir, output_path, total_chunks, total_size):
    """Reassembles the downloaded chunks into the final file."""
    logging.info(f"Reassembling file: {output_path}")
    try:
        with open(output_path, 'wb') as f_out:
            for i in range(total_chunks):
                chunk_path = os.path.join(temp_dir, f'chunk_{i}')
                if not os.path.exists(chunk_path):
                    raise FileNotFoundError(f"Missing chunk {i} for reassembly.")
                with open(chunk_path, 'rb') as f_in:
                    f_out.write(f_in.read())
        
        # Verify file size
        if os.path.getsize(output_path) == total_size:
            logging.info("File reassembled successfully and size is verified.")
            # Clean up temporary chunk directory
            shutil.rmtree(temp_dir)
            logging.info(f"Removed temporary directory: {temp_dir}")
        else:
            logging.error("Reassembled file size does not match expected size!")

    except Exception as e:
        logging.error(f"An error occurred during reassembly: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="High-performance, secure file transfer client.")
    parser.add_argument('host', type=str, help='The server IP address.')
    parser.add_argument('port', type=int, help='The server port.')
    parser.add_argument('key', type=str, help='The one-time key for decryption.')
    parser.add_argument('--workers', type=int, default=10, help='Number of parallel download threads.')

    args = parser.parse_args()

    download_file(args.host, args.port, args.key, max_workers=args.workers)
