# LLM_Solver

An AI-powered CTF (Capture The Flag) challenge solver that uses LLM to analyze, plan, and generate exploits for security challenges.

## Prerequisites

- Python 3.8+
- OpenAI API Key
- Ghidra (optional, for binary analysis)

## Installation

```bash
git clone https://github.com/JungWooJJING/LLM_Solver.git
cd LLM_Solver
pip install -r requirements.txt
```

## Configuration

Set the required environment variables:

```bash
export OPENAI_API_KEY="<YOUR_API_KEY>"
```

If you want to use Ghidra for binary analysis:

```bash
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
```

For permanent configuration, add these to your `~/.zshrc` or `~/.bashrc`:

```bash
echo 'export OPENAI_API_KEY="<YOUR_API_KEY>"' >> ~/.zshrc
echo 'export GHIDRA_INSTALL_DIR="/path/to/ghidra"' >> ~/.zshrc
source ~/.zshrc
```

## Usage

```bash
python3 main.py
```

The program will prompt you to enter:
- Challenge title
- Challenge description
- Challenge category (e.g., pwnable, web, crypto, etc.)
- Flag format

## Available Commands

Once the workflow starts, you can use the following commands:

```
--help    : Display the available commands
--ghidra  : Generate a plan based on decompiled and disassembled results
--file    : Paste the challenge source code to locate potential vulnerabilities
--discuss : Discuss the approach with the LLM to set a clear direction
--continue: Continue using LLM with the latest feedback and proceed to the next step
--exploit : Receive an exploit script or detailed exploitation steps
--quit    : Exit the program
```

## Features

- **Planning Agent**: Analyzes challenges and creates exploitation plans
- **Instruction Agent**: Provides step-by-step instructions
- **Parsing Agent**: Parses and analyzes code/binary files
- **Feedback Agent**: Provides feedback on exploitation attempts
- **Exploit Agent**: Generates exploit scripts
- **Scenario Agent**: Manages challenge scenarios
- **Ghidra Integration**: Binary analysis and decompilation support

## License

[Add your license here]
