# EXE Analysis Tool

This tool is designed to analyze Windows executable (EXE) files, extract important information such as the entry point, image base, and imported functions, and request a high-level analysis via the local Ollama API. It also disassembles executable functions and can handle multiple files simultaneously using multithreading.

## Features

- **PE Header Analysis:** Extracts key details such as the entry point and image base.
- **Import Address Table (IAT) Parsing:** Lists imported DLLs and their respective functions.
- **Function Disassembly:** Disassembles the code starting from the entry point or any requested function address.
- **Ollama API Integration:** Sends the disassembled code for analysis using a locally hosted AI model.
- **Incremental Analysis:** Requests additional assembly disassembly when needed, based on the AI's feedback.
- **Multithreading:** Processes multiple EXE files in parallel for efficiency.
- **Customizable Analysis Prompts:** Users can provide custom prompts during the analysis process.

## Requirements

This project requires Python 3.x and the following libraries:

- `pefile`
- `requests`
- `capstone`
- `argparse`
- `concurrent.futures`
- `logging`

You can install the required libraries via pip:

```bash
pip install pefile requests capstone
```

Usage
To analyze one or more EXE files, run the following command:

bash
Copy code
python analyze_exe.py <path_to_exe_file1> <path_to_exe_file2> ...
If no files are provided, the program will prompt you to enter or drag and drop a file path.

Example
bash
Copy code
python analyze_exe.py C:\path\to\file.exe
Custom Prompts
During the analysis, the AI might request additional assembly disassembly. The tool will allow you to review the analysis and decide whether to proceed. If you choose to continue, you can provide custom prompts for further analysis.

Ollama API
The tool uses the Ollama API for generating analysis. Make sure you have Ollama running locally at http://localhost:11434.

If the tool cannot connect or encounters errors with the API, it will retry up to three times with a delay of 5 seconds between attempts.

Logging
All major events, including errors and retries, are logged. You can view the log messages to troubleshoot or follow the analysis process.

License
This project is licensed under the MIT License. See the LICENSE file for details.
