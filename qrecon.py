
#!/usr/bin/env python3
import argparse, sys, os
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.banner import print_banner
from utils.authorization import AuthorizationGate
from utils.logger import QLogger
from modules.enumerator import TargetEnumerator
from modules.rsa_assessor import RSAAssessor
from modules.ecc_assessor import ECCAssessor
from modules.dh_assessor import DHAssessor
from modules.signature_assessor import SignatureAssessor
from modules.symmetric_assessor import SymmetricAssessor
from modules.hash_assessor import HashAssessor
from reports.report_engine import ReportEngine
from modules.api_assessor import APIAssessor
from modules.iot_assessor import IoTAssessor
from modules.starttls_assessor import STARTTLSAssessor

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-t","--target",required=True)
    p.add_argument("-p","--port",type=int,default=443)
    p.add_argument("-o","--output",default="reports")
    p.add_argument("--skip-auth",action="store_true")
    p.add_argument("--verbose",action="store_true")
    return p.parse_args()

def print_summary(r):
    colors = {"CRITICAL":"\033[91m","HIGH":"\033[93m","MEDIUM":"\033[94m","LOW":"\033[92m","UNKNOWN":"\033[97m"}
    reset = "\033[0m"
    sev = r.get("severity","UNKNOWN")
    print("    Status  : " + colors.get(sev,reset) + sev + reset)
    print("    Finding : " + str(r.get("finding","N/A")))

def main():
    print_banner()
    args = parse_args()
    if not args.skip_auth:
        if not AuthorizationGate(args.target).verify():
            print("[!] Authorization not confirmed. Exiting.")
            sys.exit(0)
    logger = QLogger(args.target, args.output)
    print()
    print("[*] Target : " + args.target)
    print("[*] Time   : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print()
    print("=" * 55)
    print("  PHASE 1: TARGET ENUMERATION")
    print("=" * 55)
    enum = TargetEnumerator(args.target, args.port, args.verbose)
    enum_results = enum.run()
    if not enum_results.get("reachable"):
        print("[!] Target unreachable. Exiting.")
        sys.exit(1)
    print()
    print("=" * 55)
    print("  PHASE 2: CRYPTOGRAPHIC ASSESSMENT")
    print("=" * 55)
    modules = [
        ("rsa","RSA Assessment",RSAAssessor),
        ("ecc","ECC Exposure",ECCAssessor),
        ("dh","Key Exchange",DHAssessor),
        ("signature","Digital Signatures",SignatureAssessor),
        ("symmetric","Symmetric Encryption",SymmetricAssessor),
        ("hash","Hash Functions",HashAssessor),
        ("api","API Assessment",APIAssessor),
    ]
    results = {}
    for key,name,Cls in modules:
        print()
        print("[+] " + name)
        print("-" * 40)
        r = Cls(args.target, args.port, enum_results, args.verbose).run()
        results[key] = r
        print_summary(r)
        logger.log_module_result(key, r)
    # IoT Assessment
    print()
    print("[+] IoT Assessment")
    print("-" * 40)
    r = IoTAssessor(args.target, args.verbose).run()
    results["iot"] = r
    print_summary(r)
    logger.log_module_result("iot", r)
    # STARTTLS Assessment
    print()
    print("[+] STARTTLS Assessment")
    print("-" * 40)
    r = STARTTLSAssessor(args.target, verbose=args.verbose).run()
    results["starttls"] = r
    print_summary(r)
    logger.log_module_result("starttls", r)
    weights = {"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":25,"SAFE":0,"UNKNOWN":10}
    scores = [weights.get(results[k].get("severity","UNKNOWN"),10) for k in results]
    avg = sum(scores)/len(scores) if scores else 0
    results["quantum_risk_score"] = avg
    reset = "\033[0m"
    if avg>=75: col="\033[91m"; rat="CRITICAL"
    elif avg>=50: col="\033[93m"; rat="HIGH"
    elif avg>=25: col="\033[94m"; rat="MEDIUM"
    else: col="\033[92m"; rat="LOW"
    print()
    print("=" * 55)
    print("  QUANTUM RISK SCORE")
    print("=" * 55)
    print("  Score  : " + col + str(round(avg,1)) + "/100" + reset)
    print("  Rating : " + col + rat + reset)
    print()
    print("=" * 55)
    path = ReportEngine(args.target, results, args.output).generate()
    print("[OK] Done : " + path)
    print()

if __name__ == "__main__":
    main()
