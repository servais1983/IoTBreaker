#!/usr/bin/env python3

import argparse
from core import discover, analyze, check
from core.utils import run_script_yaml

def main():
    parser = argparse.ArgumentParser(prog="iotbreaker", description="Pentest IoT CLI - Kali Linux")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("discover", help="Découverte des dispositifs IoT")
      
    analyze_cmd = subparsers.add_parser("analyze")
    analyze_cmd.add_argument("ip")

    check_cmd = subparsers.add_parser("check")
    check_cmd.add_argument("ip")

    run_cmd = subparsers.add_parser("run")
    run_cmd.add_argument("file")

    args = parser.parse_args()

    if args.command == "discover":
        discover.run()
    elif args.command == "analyze":
        analyze.run(args.ip)
    elif args.command == "check":
        check.run(args.ip)
    elif args.command == "run":
        run_script_yaml(args.file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()