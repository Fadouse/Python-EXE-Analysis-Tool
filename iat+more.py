import pefile
import requests
import json
import sys
import os
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import capstone
import re
import time

# Ollama API endpoint (Assume Ollama is running locally)
OLLAMA_API_URL = "http://localhost:11434/api/generate"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Enhanced Analysis Guidelines in English
ANALYSIS_GUIDELINES = (
    "I have extracted the following information from an executable (EXE) file:\n"
    "Entry Point: {}\n"
    "Image Base: {}\n"
    "Imports:\n"
    "{}\n"
    "Function Assembly:\n"
    "{}\n"
    "Please analyze this information and determine if this EXE might be malicious. "
    "If so, provide a high-level analysis of its potential purpose.\n\n"
    "Analysis Guidelines:\n"
    "1. Carefully examine the provided information to avoid misclassification.\n"
    "2. If the information is insufficient, clearly state this and request more specific data.\n"
    "3. When determining 'malicious' or 'non-malicious', provide detailed reasons and observations.\n"
    "4. Point out and explain any suspicious characteristics, even if uncertain.\n"
    "5. If more assembly code is needed:\n"
    "   - Provide a brief analysis of the current logic\n"
    "   - End your response in English with: 'Need more assembly: 0xXXXXXXXX, 0xXXXXXXXX, ...'\n"
    "6. If analysis is complete:\n"
    "   - Provide a comprehensive summary\n"
    "   - If repetitive assembly code is found, mention possible control flow obfuscation and suggest skipping that section\n"
    "7. Pay special attention to:\n"
    "   - File properties and metadata\n"
    "   - Imported functions and libraries\n"
    "   - Strings and encrypted content\n"
    "   - Network communication related code\n"
    "   - File system operations\n"
    "   - Anti-debugging or anti-analysis techniques\n"
    "8. If potential malicious behavior is found, attempt to infer its possible purpose (e.g., remote control, data theft, ransomware)\n"
    "Maintain objectivity in your analysis, avoid definitive conclusions, and provide evidence-based reasonable inferences.\n"
    "Please respond in English, except for the 'Need more assembly' request if applicable.\n"
    "Ensure that any base address requests are in the format: 'Need more assembly: 0xXXXXXXXX, 0xXXXXXXXX, ...'\n"
    "Please follow the format strictly to avoid parsing issues.\n"
    "If you need more assembly, end your response just in English with: 'Need more assembly: 0xXXXXXXXX, 0xXXXXXXXX, ...'\n"
)

MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

def extract_functions(pe, is_64bit):
    functions = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.address:
                    functions.append(imp.address)

    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    functions.append(image_base + entry_point)

    functions = list(set(functions))
    return functions

def extract_function_assembly(pe, function_address, is_64bit):
    assembly = []
    if is_64bit:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = function_address - image_base
    try:
        offset = pe.get_offset_from_rva(rva)
    except pefile.PEFormatError:
        logger.error(f"Cannot get offset for function address: {hex(function_address)}")
        return assembly

    # Read enough bytes to cover the function
    func_data = pe.get_memory_mapped_image()[offset:offset + 4096]  # Increased bytes to ensure full function
    for i in md.disasm(func_data, function_address):
        assembly.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
        if i.mnemonic.startswith('ret'):
            break
    return assembly

def extract_iat_info(file_path):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as e:
        logger.error(f"Invalid PE file: {e}")
        return None

    is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20b

    iat_info = {
        "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
        "Imports": [],
        "Is64Bit": is_64bit,
        "Functions": {}
    }

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            functions = [imp.name.decode('utf-8') if imp.name else f"Ordinal {imp.ordinal}" for imp in entry.imports]
            iat_info["Imports"].append({
                "dll": dll_name,
                "functions": functions
            })

    # Extract entry point function
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
    iat_info["Functions"][hex(entry_point)] = extract_function_assembly(pe, entry_point, is_64bit)

    return iat_info, pe

def construct_prompt(iat_info, is_follow_up=False, custom_prompt=None):
    if not is_follow_up:
        imports_formatted = ""
        for imp in iat_info["Imports"]:
            imports_formatted += f"  DLL: {imp['dll']}\n"
            imports_formatted += "  Functions:\n"
            for func in imp['functions']:
                imports_formatted += f"    - {func}\n"

        functions_formatted = ""
        for func_addr, assembly in iat_info["Functions"].items():
            functions_formatted += f"Function {func_addr}:\n"
            for instr in assembly:
                functions_formatted += f"  {instr}\n"
            functions_formatted += "\n"

        prompt = ANALYSIS_GUIDELINES.format(
            iat_info["EntryPoint"],
            iat_info["ImageBase"],
            imports_formatted,
            functions_formatted
        )
    else:
        if custom_prompt:
            # Include custom prompt if provided
            prompt = custom_prompt + "\n\n"
        prompt = (
            "Here's the additional assembly code you requested:\n\n"
            "Assembly Code:\n" +
            "\n".join([f"Function {addr}:\n" + "\n".join(asm) for addr, asm in iat_info["Functions"].items()]) +
            "\n\n" +
            "Please continue the analysis based on the new assembly code provided.\n\n" +
            "Ensure that any base address requests are in the format: 'Need more assembly: 0xXXXXXXXX, 0xXXXXXXXX, ...'\n"
            "Please adhere to the analysis guidelines previously provided."
        )
    return prompt

def send_to_ollama(iat_info, is_follow_up=False, custom_prompt=None):
    message = construct_prompt(iat_info, is_follow_up, custom_prompt)

    payload = {
        "model": "qwen2.5:14b",
        "prompt": message,
        "stream": True
    }

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(OLLAMA_API_URL, json=payload, stream=True, timeout=120)
            response.raise_for_status()

            full_response = ""
            for line in response.iter_lines():
                if line:
                    try:
                        json_response = json.loads(line)
                        if 'response' in json_response:
                            full_response += json_response['response']
                        if json_response.get('done', False):
                            break
                    except json.JSONDecodeError as json_err:
                        logger.error(f"JSON Decode Error: {json_err}")
                        logger.error(f"Problematic line: {line}")

            # Validate response format
            if validate_response(full_response):
                return full_response.strip()
            else:
                logger.warning("GPT's reply format does not match expectations. Resending system prompt and increasing user prompt weight.")
                # Adjust user prompt weight by emphasizing user instructions
                payload["prompt"] = "### Emphasizing user prompt weight ###\n" + message
                continue

        except requests.RequestException as e:
            logger.error(f"Error sending request to Ollama (Attempt {attempt + 1}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES - 1:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                logger.error("Max retries reached. Exiting request.")
                return f"Error: {str(e)}"

    return "Error: Failed to receive a valid GPT response."

def validate_response(response):
    """
    Validate if the GPT response matches the expected format.
    Expected formats:
    - English analysis content
    - If more assembly is needed, end with 'Need more assembly: 0xXXXXXXXX, 0xXXXXXXXX, ...'
    """
    # Check for 'Need more assembly' request
    need_more_match = re.search(r'Need more assembly:\s*(0x[0-9A-Fa-f]{5,16}(?:,\s*0x[0-9A-Fa-f]{5,16})*)', response)
    if need_more_match:
        return True  # Correct format
    else:
        # Check if the majority of the content is in English
        english_chars = re.findall(r'[A-Za-z]', response)
        if len(english_chars) > len(response) / 2:
            return True
    return False

def get_more_assembly(pe, base_addresses, is_64bit):
    new_functions = {}
    for base_address in base_addresses:
        try:
            base_address_int = int(base_address, 16)
            assembly = extract_function_assembly(pe, base_address_int, is_64bit)
            if assembly:
                new_functions[base_address] = assembly
                logger.info(f"Retrieved assembly for {base_address}.")
            else:
                logger.warning(f"No assembly found at address {base_address}.")
        except Exception as e:
            logger.error(f"Error getting assembly for {base_address}: {str(e)}")
    return new_functions

def process_file(file_path):
    file_path = file_path.strip('"')
    if not os.path.exists(file_path):
        logger.error(f"File not found: '{file_path}'")
        return

    try:
        iat_info, pe = extract_iat_info(file_path)
        if iat_info:
            is_follow_up = False
            requested_addresses = set()
            custom_prompt = None
            while True:
                analysis_result = send_to_ollama(iat_info, is_follow_up, custom_prompt)
                logger.info(f"GPT Analysis Result:\n{analysis_result}")

                # Extract addresses requesting more assembly code
                matches = re.findall(r'Need more assembly:\s*(0x[0-9A-Fa-f]{5,16}(?:,\s*0x[0-9A-Fa-f]{5,16})*)', analysis_result)
                addresses = []
                for match in matches:
                    parts = match.split(',')
                    for part in parts:
                        addr = part.strip()
                        if re.match(r'^0x[0-9A-Fa-f]{5,16}$', addr):
                            if addr not in requested_addresses:
                                addresses.append(addr)
                                requested_addresses.add(addr)
                            else:
                                logger.info(f"Address {addr} has already been requested. Skipping.")
                        else:
                            logger.warning(f"Invalid base address format skipped: {addr}")

                if addresses:
                    logger.info(f"GPT requested more assembly code for base addresses: {addresses}")
                    more_assembly = get_more_assembly(pe, addresses, iat_info["Is64Bit"])
                    if not more_assembly:
                        logger.error("Failed to retrieve additional assembly code.")
                        break
                    iat_info["Functions"].update(more_assembly)
                    is_follow_up = True
                    custom_prompt = None  # Reset custom prompt
                    continue
                else:
                    logger.warning("GPT's reply doesn't match the expected format or analysis is complete.")
                    print(analysis_result)
                    user_decision = input("Do you want to continue analysis or request more information? (y/n): ")
                    if user_decision.lower() != 'y':
                        break
                    else:
                        user_prompt = input("Please enter a custom prompt for GPT: ")
                        custom_prompt = user_prompt
                        is_follow_up = True
        else:
            logger.error(f"Failed to extract IAT info from {file_path}")
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Analyze EXE files for potential malicious behavior.")
    parser.add_argument('files', nargs='*', help='Path to EXE file(s) to analyze')
    args = parser.parse_args()

    if not args.files:
        file_path = input("Please enter or drag and drop the path to the EXE file: ").strip()
        args.files = [file_path]

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_file, file) for file in args.files]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                logger.error(f"Generated an exception: {exc}")

if __name__ == "__main__":
    main()
