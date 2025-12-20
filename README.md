# LLM_Solver

An AI-powered CTF (Capture The Flag) challenge solver that uses LLM to analyze, plan, and generate exploits for security challenges. Built with LangGraph for workflow orchestration.

## Prerequisites

- Python 3.8+
- OpenAI API Key (GPT-5.2)
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

### Initial Commands (Before First Execution)
```
--help    : Display the available commands
--file    : Paste the challenge source code to locate potential vulnerabilities
--ghidra  : Generate a plan based on decompiled and disassembled results
--discuss : Discuss the approach with the LLM to set a clear direction
--quit    : Exit the program
```

### Commands (After Initial Setup)
```
--help     : Display the available commands
--discuss  : Discuss the approach with the LLM to set a clear direction
--continue : Continue using LLM with the latest feedback and proceed to the next step
--exploit  : Receive an exploit script or detailed exploitation steps
--quit     : Exit the program
```

## Workflow Visualization

You can visualize the workflow graphs using the visualization script:

```bash
python langgraph/visualize.py
```

This will generate Mermaid diagrams of the workflow graphs, which can be viewed in:
- GitHub (renders Mermaid natively)
- Mermaid Live Editor (https://mermaid.live/)
- Any Markdown viewer with Mermaid support

Output files are saved in `./artifacts/` directory.

## How It Works

### Workflow Flow

1. **Planning Phase (CoT)**: Analyzes challenge and generates multiple attack candidates
2. **Calibration Phase (Cal)**: Scores and ranks candidates
3. **Tool Selection**: Selects appropriate tools based on vulnerability type
4. **Instruction Generation**: Creates executable instructions for selected tracks
5. **Execution**: Runs commands and collects results
6. **Parsing**: Analyzes results and detects flags/signals
7. **Flag Detection**: If flag detected → **PoC Generation** → **END**
8. **Track Update**: Updates vulnerability track progress
9. **Feedback**: Evaluates results and decides next steps
10. **Loop**: Returns to Planning for deeper exploration or new vectors

### Flag Detection & PoC Generation

When a flag is detected during parsing:
- Workflow automatically stops
- PoC (Proof-of-Concept) code is generated
- PoC script is saved to `./artifacts/poc.py` (or appropriate extension)
- Workflow terminates

## Technical Details

- **Model**: GPT-5.2 (GPT-4 support removed)
- **State Management**: In-memory only (no JSON file persistence)
- **Workflow Engine**: LangGraph
- **Multi-Track**: Supports up to 3 parallel vulnerability exploration tracks

## Features

### Core Agents
- **Planning Agent (CoT)**: Analyzes challenges and creates multiple exploitation candidate plans
- **Calibration Agent (Cal)**: Evaluates and scores planning candidates
- **Instruction Agent**: Provides step-by-step executable instructions
- **Parsing Agent**: Parses execution results and detects flags/signals
- **Feedback Agent**: Provides feedback on exploitation attempts
- **Exploit Agent**: Generates exploit scripts
- **PoC Agent**: Generates Proof-of-Concept code when flag is detected
- **Scenario Agent**: Manages challenge scenarios

### Workflow Features
- **LangGraph-based Workflow**: State-based workflow orchestration
- **Multi-Track Planning**: Parallel exploration of up to 3 vulnerability tracks
- **Automatic Flag Detection**: Stops workflow and generates PoC when flag is detected
- **Tool Selection**: Automatic tool selection based on vulnerability type (pwnable/web/reversing)
- **State Management**: In-memory state management (no JSON file persistence)

### Additional Features
- **Ghidra Integration**: Binary analysis and decompilation support
- **Workflow Visualization**: Generate Mermaid diagrams of workflow graphs
