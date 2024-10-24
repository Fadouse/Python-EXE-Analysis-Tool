import pefile
import requests
import json
import sys
import os
import argparse
import logging
import re
import time
from datetime import datetime

# Ollama API endpoint (Assume Ollama is running locally)
OLLAMA_API_URL = "http://localhost:11434/api/generate"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Analysis Guidelines in English with instruction to respond in Chinese and include credibility analysis
ANALYSIS_GUIDELINES = (
    "I have extracted the following information from a Portable Executable (PE) file:\n"
    "String Pool:\n"
    "{}\n"
    "Import Address Table (IAT):\n"
    "{}\n"
    "Import Information:\n"
    "{}\n"
    "Static Information:\n"
    "{}\n"
    "Please analyze this information and determine if this PE file might be malicious. "
    "If so, provide a high-level analysis of its potential purpose.\n\n"
    "Analysis Guidelines:\n"
    "1. Carefully examine the provided information to avoid misclassification.\n"
    "2. If the information is insufficient, clearly state this and request more specific data.\n"
    "3. When determining 'malicious' or 'non-malicious', provide detailed reasons and observations.\n"
    "4. Point out and explain any suspicious characteristics, even if uncertain.\n"
    "5. In your summary, include a credibility analysis with percentages for the following malware types:\n"
    "   - General Malware: xx%\n"
    "   - Ransomware: xx%\n"
    "   - Backdoor: xx%\n"
    "   - Remote Control: xx%\n"
    "6. Maintain objectivity in your analysis, avoid definitive conclusions, and provide evidence-based reasonable inferences.\n"
    "Please respond in Chinese."
)

MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

def extract_strings(pe):
    """
    Extracts printable ASCII and Unicode strings from all sections of the PE file.
    """
    strings = set()
    try:
        for section in pe.sections:
            section_data = section.get_data()
            # Extract ASCII strings
            ascii_strings = re.findall(b'[\x20-\x7E]{4,}', section_data)
            for s in ascii_strings:
                try:
                    decoded = s.decode('utf-8')
                    strings.add(decoded)
                except UnicodeDecodeError:
                    continue
            # Extract Unicode strings
            unicode_strings = re.findall(b'(?:[\x20-\x7E]\x00){4,}', section_data)
            for s in unicode_strings:
                try:
                    decoded = s.decode('utf-16le')
                    strings.add(decoded)
                except UnicodeDecodeError:
                    continue
        string_pool = "\n".join(sorted(strings))
        return string_pool
    except Exception as e:
        logger.error(f"Error extracting strings: {e}")
        return ""

def extract_iat(pe):
    """
    Extracts the Import Address Table (IAT) addresses.
    """
    iat = []
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.address:
                        iat.append(hex(imp.address))
        return "\n".join(iat)
    except Exception as e:
        logger.error(f"Error extracting IAT: {e}")
        return ""

def extract_import_info(pe):
    """
    Extracts import information: DLL names and their imported functions.
    """
    import_info = []
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = [imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal {imp.ordinal}" for imp in entry.imports]
                import_info.append(f"DLL: {dll_name}\n  Functions:\n    - " + "\n    - ".join(functions))
        return "\n\n".join(import_info)
    except Exception as e:
        logger.error(f"Error extracting import information: {e}")
        return ""

def extract_static_info(pe):
    """
    Extracts static information from the PE file.
    """
    try:
        static_info = {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "Number of Sections": pe.FILE_HEADER.NumberOfSections,
            "Time Date Stamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pe.FILE_HEADER.TimeDateStamp)),
            "Characteristics": hex(pe.FILE_HEADER.Characteristics),
            "Size of Optional Header": pe.FILE_HEADER.SizeOfOptionalHeader,
            "Subsystem": pe.OPTIONAL_HEADER.Subsystem
        }
        static_info_formatted = "\n".join([f"{key}: {value}" for key, value in static_info.items()])
        return static_info_formatted
    except Exception as e:
        logger.error(f"Error extracting static information: {e}")
        return ""

def extract_pe_info(file_path):
    """
    Extracts all required PE information.
    """
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as e:
        logger.error(f"Invalid PE file: {e}")
        return None

    string_pool = extract_strings(pe)
    iat = extract_iat(pe)
    import_info = extract_import_info(pe)
    static_info = extract_static_info(pe)

    pe_info = {
        "StringPool": string_pool,
        "IAT": iat,
        "ImportInfo": import_info,
        "StaticInfo": static_info
    }

    return pe_info

def construct_prompt(pe_info):
    """
    Constructs the prompt to be sent to GPT.
    """
    prompt = ANALYSIS_GUIDELINES.format(
        pe_info["StringPool"],
        pe_info["IAT"],
        pe_info["ImportInfo"],
        pe_info["StaticInfo"]
    )
    return prompt

def send_to_ollama(prompt):
    """
    Sends the prompt to Ollama's GPT model and retrieves the response.
    """
    payload = {
        "model": "qwen2.5:14b",
        "prompt": prompt,
        "stream": False
    }

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(OLLAMA_API_URL, json=payload, timeout=120)
            response.raise_for_status()

            response_data = response.json()
            if 'response' in response_data:
                return response_data['response'].strip()
            else:
                logger.error("Unexpected response format from Ollama.")
                return "Error: Unexpected response format."

        except requests.RequestException as e:
            logger.error(f"Error sending request to Ollama (Attempt {attempt + 1}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES - 1:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                logger.error("Max retries reached. Exiting request.")
                return f"Error: {str(e)}"

def sanitize_filename(filename):
    """
    Removes or replaces characters that are invalid in filenames.
    """
    return re.sub(r'[\\/*?:"<>|]', '_', filename)

def save_to_markdown(pe_filename, analysis_result):
    """
    Saves the analysis result to a Markdown file.
    """
    # Get current time
    now = datetime.now()
    analysis_time = now.strftime("%Y%m%d_%H%M%S")

    # Sanitize PE filename
    base_filename = os.path.basename(pe_filename)
    base_filename_no_ext = os.path.splitext(base_filename)[0]
    sanitized_filename = sanitize_filename(base_filename_no_ext)

    # Construct markdown filename
    md_filename = f"GPT逆向-{sanitized_filename}-{analysis_time}.md"

    try:
        with open(md_filename, 'w', encoding='utf-8') as md_file:
            md_file.write(f"# 分析结果 - {base_filename}\n\n")
            md_file.write(f"**分析时间**: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            md_file.write("## 分析内容\n\n")
            md_file.write(analysis_result)
        logger.info(f"Analysis result saved to {md_filename}")
    except Exception as e:
        logger.error(f"Error saving analysis result to markdown file: {e}")

def process_file(file_path):
    """
    Processes a single PE file: extracts information, sends to GPT, and saves the result.
    """
    file_path = file_path.strip('"')
    if not os.path.exists(file_path):
        logger.error(f"File not found: '{file_path}'")
        return

    pe_info = extract_pe_info(file_path)
    if pe_info:
        prompt = construct_prompt(pe_info)
        analysis_result = send_to_ollama(prompt)
        if analysis_result.startswith("Error"):
            logger.error(f"GPT analysis failed for {file_path}: {analysis_result}")
        else:
            logger.info(f"GPT Analysis Result for {file_path}:\n{analysis_result}")
            print(analysis_result)
            save_to_markdown(file_path, analysis_result)
    else:
        logger.error(f"Failed to extract PE info from {file_path}")

def main():
    """
    Main function to handle command-line arguments and process files.
    """
    parser = argparse.ArgumentParser(description="Analyze PE files for potential malicious behavior.")
    parser.add_argument('files', nargs='*', help='Path to PE file(s) to analyze')
    args = parser.parse_args()

    if not args.files:
        file_path = input("Please enter or drag and drop the path to the PE file: ").strip()
        args.files = [file_path]

    for file in args.files:
        process_file(file)

if __name__ == "__main__":
    main()
