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
from modules.starttls_assessor import STARTTLSAssessor
from modules.api_assessor import APIAssessor
from modules.iot_assessor import IoTAssessor
from reports.report_engine import ReportEngine

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-p", "--port", type=int, default=443)
    p.add_argument("-o", "--output", default="reports")
    p.add_argument("--skip-auth", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--starttls", choices=["smtp","submission","imap"])
    p.add_argument("--api", action="store_true")
    p.add_argument("--iot", action="store_true")
    return p.parse_args()

def print_summary(r):
    colors = {"CRITICAL":"\033[91m","HIGH":"\033[93m","MEDIUM":"\033[94m","LOW":"\033[92m","UNKNOWN":"\033[97m"}
    reset = "\033[0m"
    sev = r.get("severity","UNKNOWN")
    print("    Status  : " + colors.get(sev,reset) + sev + reset)
    print("    Finding : " + str(r.get("finding","N/A")))

def calc_score(results):
    weights = {"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":25,"INFO":0}
    scores = []
    tls_failed = results.get("tls_failed", False)
    for k in ["rsa","ecc","dh","signature","symmetric","hash"]:
        if k not in results:
            continue
        sev = results[k].get("severity","UNKNOWN")
        if sev == "UNKNOWN":
            # If TLS failed entirely flag as HIGH — server is misconfigured
            scores.append(75 if tls_failed else 50)
        elif sev == "INFO":
            scores.append(0)
        else:
            scores.append(weights.get(sev, 50))
    return round(sum(scores)/len(scores), 1) if scores else 0

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
    tls_failed = enum_results.get("raw_cert") is None
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
    ]
    results = {}
    results["tls_failed"] = tls_failed
    for key, name, Cls in modules:
        print()
        print("[+] " + name)
        print("-" * 40)
        r = Cls(args.target, args.port, enum_results, args.verbose).run()
        results[key] = r
        print_summary(r)
        logger.log_module_result(key, r)
    avg = calc_score(results)
    results["quantum_risk_score"] = avg
    if tls_failed:
        results["tls_misconfiguration"] = True
    reset = "\033[0m"
    if avg>=75: col="\033[91m"; rat="CRITICAL"
    elif avg>=50: col="\033[93m"; rat="HIGH"
    elif avg>=25: col="\033[94m"; rat="MEDIUM"
    else: col="\033[92m"; rat="LOW"
    print()
    print("=" * 55)
    print("  QUANTUM RISK SCORE")
    print("=" * 55)
    if tls_failed:
        print("  \033[93m[!] TLS handshake failed — server misconfigured\033[0m")
    print("  Score  : " + col + str(avg) + "/100" + reset)
    print("  Rating : " + col + rat + reset)
    print()
    print("=" * 55)
    path = ReportEngine(args.target, results, args.output).generate()
    print("[OK] Done : " + path)
    if args.starttls:
        print()
        print("=" * 55)
        print("  STARTTLS ASSESSMENT")
        print("=" * 55)
        st = STARTTLSAssessor(args.target, protocol=args.starttls, verbose=args.verbose)
        st_result = st.run()
        results["starttls"] = st_result
        print_summary(st_result)
    if args.api:
        print()
        print("=" * 55)
        print("  API ENDPOINT SCANNER")
        print("=" * 55)
        api = APIAssessor(args.target, port=args.port, verbose=args.verbose)
        api_result = api.run()
        results["api"] = api_result
        print_summary(api_result)
    if args.iot:
        print()
        print("=" * 55)
        print("  IOT DEVICE ASSESSMENT")
        print("=" * 55)
        iot = IoTAssessor(args.target, verbose=args.verbose)
        iot_result = iot.run()
        results["iot"] = iot_result
        print_summary(iot_result)
    print()

if __name__ == "__main__":
    main()
