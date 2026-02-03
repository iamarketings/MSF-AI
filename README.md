# Metasploit Framework AI Assistant (MSF-AI v4)

This project is an AI-powered assistant for the Metasploit Framework. It provides a conversational interface to interact with Metasploit and perform various penetration testing tasks autonomously using advanced orchestration.

## Features

*   **Conversational AI:** Interact with Metasploit using natural language powered by DeepSeek and compatible APIs.
*   **Langgraph Orchestration:** A state-of-the-art task orchestrator built with Langgraph that handles planning, execution, and analysis of complex security objectives.
*   **Security Configuration:** Integrated security modes ("safe" and "unsafe") to control the execution of intrusive or dangerous commands.
*   **OS Interaction Tools:** Specialized tools for identifying and interacting with local systems (Linux, WSL, Windows).
*   **Advanced Tool Integration:**
    *   **Reconnaissance:** Real WHOIS, DNS enumeration, and subdomain discovery.
    *   **Web Auditing:** Robust form extraction with BeautifulSoup, WAF detection, and security header checks.
    *   **Post-Exploitation:** Session management and automated command output retrieval.
*   **RAG (Retrieval-Augmented Generation):** AI-enhanced responses using a dedicated Metasploit knowledge base.

## Architecture

The project follows a modular MVC (Model-View-Controller) architecture:
*   `msf_mvc.py`: Main entry point.
*   `msf_aiv4/msf_controller.py`: Logic coordinator.
*   `msf_aiv4/msf_orchestrator.py`: Langgraph-based task execution.
*   `msf_aiv4/tools/`: Category-specific tool implementations.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd msf-ai-assistant
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment:**
    Create a `.env` file in the root directory and add your API keys:
    ```env
    DEEPSEEK_API_KEY=your_api_key_here
    MSF_RPC_PASS=your_msf_password
    ```

4.  **Launch Metasploit RPC:**
    Ensure `msfrpcd` is running before starting the assistant.

## Usage

Run the assistant:
```bash
python3 msf_mvc.py
```

### Security Modes
You can toggle between security modes by asking the AI or editing `config.json`:
*   `safe`: Restricted command execution (informational only).
*   `unsafe`: Full command execution capabilities.

## Requirements

*   Python 3.10+
*   Metasploit Framework
*   Internet access for API and RAG lookups
