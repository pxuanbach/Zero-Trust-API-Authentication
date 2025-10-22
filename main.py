"""
Main entry point for Zero Trust API Authentication system
"""
import argparse
import asyncio
import os
import sys

def run_proxy():
    """Run the proxy server"""
    from src.proxy.main import run_proxy
    run_proxy()

def run_cert_agent():
    """Run the certificate agent"""
    from src.cert_agent.main import run_cert_agent
    adapter_type = os.getenv("CERT_ADAPTER", "internal")
    run_cert_agent(adapter_type=adapter_type)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Zero Trust API Authentication")
    parser.add_argument(
        "service", 
        choices=["proxy", "cert-agent"], 
        help="Service to run"
    )
    parser.add_argument(
        "--adapter", 
        choices=["aws", "internal", "letsencrypt"], 
        default="internal",
        help="Certificate adapter type (for cert-agent)"
    )
    
    args = parser.parse_args()
    
    if args.service == "proxy":
        print("Starting Zero Trust Proxy...")
        run_proxy()
    elif args.service == "cert-agent":
        print(f"Starting Certificate Agent with {args.adapter} adapter...")
        os.environ["CERT_ADAPTER"] = args.adapter
        run_cert_agent()

if __name__ == "__main__":
    main()
