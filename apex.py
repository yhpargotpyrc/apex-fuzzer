#!/usr/bin/env python3
"""
APEX Fuzzer - Advanced Persistent EXploration Fuzzer
State-of-the-art multi-target fuzzing framework
Targets: Network Protocols, File Parsers, Linux Kernel, Firmware/IoT
Modes: Source (instrumented) + Binary-only (QEMU/Frida)
"""

import os
import sys
import argparse
import logging
import asyncio
import signal
import json
from pathlib import Path
from datetime import datetime

# Internal modules
from core.engine.orchestrator import FuzzOrchestrator
from core.engine.config import ApexConfig
from core.scheduler.resource_manager import ResourceManager
from core.triage.crash_analyzer import CrashAnalyzer
from dashboards.server import DashboardServer

ASCII_BANNER = r"""
   ___  ____  _______  __   ____                        
  / _ |/ __ \/ __/ \ \/ /  / __/_ _________ ___ ____  
 / __ / /_/ / _/ /   \  /  / _// // /_ /_ // -_) __/  
/_/ |_\____/___/_/|_//_/  /_/  \_,_//__//__/\__/_/     

  APEX - Advanced Persistent EXploration Fuzzer v1.0
  State-of-the-Art | Multi-Target | Source + Binary
  ─────────────────────────────────────────────────
"""

def setup_logging(verbosity: int, log_file: str = None):
    level = [logging.WARNING, logging.INFO, logging.DEBUG][min(verbosity, 2)]
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers
    )

def parse_args():
    parser = argparse.ArgumentParser(
        description="APEX - Advanced Persistent EXploration Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz a network protocol (source mode)
  python apex.py --mode network --target-binary ./target_server --protocol http --source

  # Fuzz a file parser (binary-only via QEMU)
  python apex.py --mode fileparser --target-binary ./parser --format pdf --binary

  # Fuzz Linux kernel syscalls
  python apex.py --mode kernel --syscall-groups net,fs --source

  # Fuzz firmware image
  python apex.py --mode firmware --firmware-image ./fw.bin --arch mips

  # Full campaign with dashboard
  python apex.py --mode network --target-binary ./target --dashboard --workers 8
        """
    )

    # Target selection
    parser.add_argument("--mode", required=True,
        choices=["network", "fileparser", "kernel", "firmware"],
        help="Fuzzing target mode")
    parser.add_argument("--target-binary", help="Path to target binary")
    parser.add_argument("--target-args", default="@@",
        help="Target arguments (use @@ for input file placeholder)")

    # Source vs Binary
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("--source", action="store_true",
        help="Source-based mode (LLVM instrumentation, faster)")
    source_group.add_argument("--binary", action="store_true",
        help="Binary-only mode (QEMU/Frida, slower but universal)")

    # Mode-specific options
    net_group = parser.add_argument_group("Network Protocol Options")
    net_group.add_argument("--protocol", choices=["http", "tls", "ftp", "ssh", "dns",
                                                    "mqtt", "modbus", "custom"],
        help="Protocol type for grammar-aware fuzzing")
    net_group.add_argument("--target-host", default="127.0.0.1")
    net_group.add_argument("--target-port", type=int)

    file_group = parser.add_argument_group("File Parser Options")
    file_group.add_argument("--format", choices=["pdf", "png", "jpeg", "mp4", "zip",
                                                   "elf", "xml", "json", "custom"],
        help="File format for structure-aware fuzzing")

    kernel_group = parser.add_argument_group("Kernel Fuzzing Options")
    kernel_group.add_argument("--syscall-groups",
        help="Comma-separated syscall groups (net,fs,ipc,mem,crypto)")
    kernel_group.add_argument("--kernel-image", help="Custom kernel image for kAFL")

    fw_group = parser.add_argument_group("Firmware Options")
    fw_group.add_argument("--firmware-image", help="Firmware binary image")
    fw_group.add_argument("--arch", choices=["arm", "mips", "mips64", "x86", "ppc"],
        help="Firmware CPU architecture")
    fw_group.add_argument("--endian", choices=["little", "big"], default="little")

    # Engine options
    engine_group = parser.add_argument_group("Engine Options")
    engine_group.add_argument("--workers", type=int, default=4,
        help="Number of parallel fuzzer workers")
    engine_group.add_argument("--corpus", default="./corpus",
        help="Seed corpus directory")
    engine_group.add_argument("--output", default="./crashes",
        help="Crash output directory")
    engine_group.add_argument("--timeout", type=int, default=5000,
        help="Per-execution timeout in milliseconds")
    engine_group.add_argument("--memory-limit", type=int, default=256,
        help="Memory limit per worker in MB")

    # Sanitizers
    san_group = parser.add_argument_group("Sanitizer Options")
    san_group.add_argument("--asan", action="store_true", help="Enable AddressSanitizer")
    san_group.add_argument("--msan", action="store_true", help="Enable MemorySanitizer")
    san_group.add_argument("--ubsan", action="store_true", help="Enable UBSan")
    san_group.add_argument("--tsan", action="store_true", help="Enable ThreadSanitizer")
    san_group.add_argument("--dfsan", action="store_true", help="Enable DataFlowSanitizer (taint)")

    # Advanced
    adv_group = parser.add_argument_group("Advanced Options")
    adv_group.add_argument("--symbolic", action="store_true",
        help="Enable symbolic execution hybrid (angr)")
    adv_group.add_argument("--ml-mutator", action="store_true",
        help="Enable ML-guided mutation scheduling")
    adv_group.add_argument("--snapshot", action="store_true",
        help="Enable snapshot fuzzing (faster for stateful targets)")
    adv_group.add_argument("--cmplog", action="store_true",
        help="Enable CmpLog (comparison logging for deeper coverage)")
    adv_group.add_argument("--grammar-file", help="Custom grammar file (.json/.g4)")

    # Dashboard
    dash_group = parser.add_argument_group("Dashboard Options")
    dash_group.add_argument("--dashboard", action="store_true",
        help="Launch web dashboard")
    dash_group.add_argument("--dashboard-port", type=int, default=8080)

    # Misc
    parser.add_argument("-v", "--verbose", action="count", default=1)
    parser.add_argument("--config", help="Load config from JSON file")
    parser.add_argument("--resume", action="store_true",
        help="Resume a previous fuzzing campaign")
    parser.add_argument("--dry-run", action="store_true",
        help="Validate config and show what would run, without executing")

    return parser.parse_args()


async def main():
    print(ASCII_BANNER)

    args = parse_args()
    setup_logging(args.verbose, log_file=f"apex_{datetime.now():%Y%m%d_%H%M%S}.log")
    log = logging.getLogger("apex.main")

    # Load config
    config = ApexConfig.from_args(args)
    if args.config:
        config.merge_from_file(args.config)

    log.info(f"APEX starting — mode={config.mode}, workers={config.workers}")
    log.info(f"Targets: binary={config.target_binary}, source={config.source_mode}")

    if args.dry_run:
        print("\n[DRY RUN] Configuration:")
        print(json.dumps(config.to_dict(), indent=2))
        return

    # Setup resource manager
    resource_mgr = ResourceManager(
        max_workers=config.workers,
        memory_limit_mb=config.memory_limit
    )
    await resource_mgr.initialize()

    # Setup crash analyzer
    crash_analyzer = CrashAnalyzer(
        output_dir=config.output_dir,
        dedup_method="stack_hash",
        exploitability_check=True
    )

    # Launch dashboard if requested
    dashboard = None
    if args.dashboard:
        dashboard = DashboardServer(port=args.dashboard_port)
        asyncio.create_task(dashboard.start())
        log.info(f"Dashboard: http://localhost:{args.dashboard_port}")

    # Setup signal handlers for graceful shutdown
    orchestrator = FuzzOrchestrator(config, resource_mgr, crash_analyzer, dashboard)

    def shutdown_handler(sig, frame):
        log.info("Shutdown signal received — saving state and exiting...")
        asyncio.create_task(orchestrator.graceful_shutdown())

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Run the campaign
    try:
        stats = await orchestrator.run()
        print("\n" + "="*60)
        print("APEX Campaign Complete")
        print("="*60)
        print(f"  Total executions : {stats.total_executions:,}")
        print(f"  Exec/sec (avg)   : {stats.avg_execs_per_sec:,.0f}")
        print(f"  Unique crashes   : {stats.unique_crashes}")
        print(f"  Coverage paths   : {stats.total_paths:,}")
        print(f"  Runtime          : {stats.runtime_human}")
        print(f"  Crashes saved to : {config.output_dir}")
        print("="*60)
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
