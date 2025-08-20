import os
import base64
import requests
from urllib.parse import quote, urlparse
from dotenv import load_dotenv
from langchain.prompts import PromptTemplate
from langchain_xai import ChatXAI  # Assuming valid integration
from langgraph.prebuilt import create_react_agent  # Latest LangGraph API
from langgraph.graph import StateGraph, START, END
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, AIMessage
from typing import TypedDict, List, Dict, Any
from typing_extensions import Annotated  # For state channel customization
from tenacity import retry, stop_after_attempt, wait_exponential

# Reducer function to merge message lists
def reduce_messages(left: List[HumanMessage | AIMessage], right: List[HumanMessage | AIMessage]) -> List[HumanMessage | AIMessage]:
    return left + right

# Load environment variables
load_dotenv()
xai_api_key = os.getenv("XAI_API_KEY")
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
otx_api_key = os.getenv("OTX_API_KEY")
model_name = os.getenv("MODEL_NAME", "grok-3")  # Configurable model name

# Check API keys
if not all([xai_api_key, vt_api_key, otx_api_key]):
    raise ValueError("Missing API keys. Set XAI_API_KEY, VIRUSTOTAL_API_KEY, and OTX_API_KEY in .env file.")

# Initialize LLM
llm = ChatXAI(model_name=model_name, xai_api_key=xai_api_key)

# Define tools with retries and validation
@tool
@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def check_url_virustotal(url: str) -> Dict[str, Any]:
    """Fetches threat intelligence for a URL from VirusTotal API."""
    try:
        # Validate URL
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return {"error": "Invalid URL format"}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(vt_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        if "data" not in data or "attributes" not in data["data"]:
            return {"error": "Invalid VirusTotal response: missing data or attributes"}
        attributes = data["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "categories": attributes.get("categories", {}),
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API error: {str(e)}"}

@tool
@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def check_url_otx(url: str) -> Dict[str, Any]:
    """Fetches threat intelligence for a URL from AlienVault OTX API."""
    try:
        # Validate URL
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return {"error": "Invalid URL format"}

        escaped_url = quote(url, safe="")
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/url/{escaped_url}/general"
        headers = {"X-OTX-API-KEY": otx_api_key}
        response = requests.get(otx_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        if "pulse_info" not in data:
            return {"error": "Invalid OTX response: missing pulse_info"}
        pulse_info = data.get("pulse_info", {})
        return {
            "pulse_count": pulse_info.get("count", 0),
            "pulses": pulse_info.get("pulses", []),
            "indicator_type": data.get("indicator_type"),
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"OTX API error: {str(e)}"}

# Define state schema for LangGraph with Annotated messages
class ThreatIntelState(TypedDict):
    url: str
    vt_result: str
    otx_result: str
    conclusion: str
    messages: Annotated[List[HumanMessage | AIMessage], reduce_messages]  # Use reducer for concurrent updates
    error: str  # For error propagation

# Create ReAct agents using LangGraph (use default prompt)
vt_agent = create_react_agent(llm, [check_url_virustotal])
otx_agent = create_react_agent(llm, [check_url_otx])

# Define conclusion prompt (more explicit)
conclusion_prompt = PromptTemplate(
    input_variables=["url", "vt_result", "otx_result"],
    template="""Based on the following threat intelligence for the URL {url}:

VirusTotal Result: {vt_result}

OTX Result: {otx_result}

Determine if the URL is malicious. 
- Classify as Malicious if VirusTotal malicious > 0 or OTX pulse_count > 1.
- Classify as Suspicious if VirusTotal suspicious > 0 or OTX pulse_count == 1.
- Otherwise, classify as Benign.
Provide the conclusion (Malicious, Benign, or Suspicious) and a brief reasoning.
If there are errors in results, note them and classify conservatively.

Conclusion:"""
)

# Define LangGraph workflow with parallel nodes
def create_workflow():
    workflow = StateGraph(ThreatIntelState)

    # VirusTotal node
    def vt_node(state: ThreatIntelState) -> ThreatIntelState:
        if state.get("error"):
            return state  # Skip if prior error
        input_message = f"Fetch threat intel for this URL: {state['url']}"
        output = vt_agent.invoke({"messages": [HumanMessage(content=input_message)]})
        # Consistent output extraction
        if not isinstance(output, dict) or "messages" not in output:
            return {"error": "Invalid VT agent output format", **state}
        result = output["messages"][-1].content
        return {
            "vt_result": result,
            "messages": output["messages"]  # Reducer will handle concatenation
        }

    # OTX node
    def otx_node(state: ThreatIntelState) -> ThreatIntelState:
        if state.get("error"):
            return state  # Skip if prior error
        input_message = f"Fetch threat intel for this URL: {state['url']}"
        output = otx_agent.invoke({"messages": [HumanMessage(content=input_message)]})
        # Consistent output extraction
        if not isinstance(output, dict) or "messages" not in output:
            return {"error": "Invalid OTX agent output format", **state}
        result = output["messages"][-1].content
        return {
            "otx_result": result,
            "messages": output["messages"]  # Reducer will handle concatenation
        }

    # Conclusion node
    def conclusion_node(state: ThreatIntelState) -> ThreatIntelState:
        if state.get("error"):
            return {"conclusion": f"Error occurred: {state['error']}", **state}
        conclusion_chain = conclusion_prompt | llm
        input_data = {"url": state["url"], "vt_result": state["vt_result"], "otx_result": state["otx_result"]}
        result = conclusion_chain.invoke(input_data)
        conclusion_text = result.content if hasattr(result, "content") else str(result)
        return {
            "conclusion": conclusion_text,
            "messages": [AIMessage(content=conclusion_text)]  # Append conclusion message
        }

    # Define graph structure for parallel execution
    workflow.add_node("vt_node", vt_node)
    workflow.add_node("otx_node", otx_node)
    workflow.add_node("conclusion_node", conclusion_node)

    # Edges: Parallel VT and OTX, then conclusion
    workflow.add_edge(START, "vt_node")
    workflow.add_edge(START, "otx_node")
    workflow.add_edge("vt_node", "conclusion_node")
    workflow.add_edge("otx_node", "conclusion_node")
    workflow.add_edge("conclusion_node", END)

    return workflow.compile()

# Function to run the workflow
def assess_url(url: str) -> Dict[str, Any]:
    # Validate URL
    parsed = urlparse(url)
    if not all([parsed.scheme, parsed.netloc]):
        raise ValueError("Invalid URL: must include scheme (e.g., https://) and domain")

    workflow = create_workflow()
    initial_state = ThreatIntelState(
        url=url,
        vt_result="",
        otx_result="",
        conclusion="",
        messages=[],
        error=""
    )
    result = workflow.invoke(initial_state)
    
    # Return results as dict
    return {
        "url": result["url"],
        "vt_result": result["vt_result"],
        "otx_result": result["otx_result"],
        "conclusion": result["conclusion"],
        "error": result.get("error", None)
    }

# Example usage
if __name__ == "__main__":
    while True:
        url_to_check = input("Enter the URL to check (e.g., https://example.com): ").strip()
        try:
            result = assess_url(url_to_check)
            print(f"\nURL: {result['url']}")
            print(f"VirusTotal Result: {result['vt_result']}")
            print(f"OTX Result: {result['otx_result']}")
            print(f"Conclusion: {result['conclusion']}")
            if result["error"]:
                print(f"Error: {result['error']}")
            break
        except ValueError as e:
            print(f"Error: {e}. Please enter a valid URL.")