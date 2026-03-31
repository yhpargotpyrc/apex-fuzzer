"""
APEX Configuration System
Handles all config loading, validation, and merging.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

log = logging.getLogger("apex.config")


@dataclass
class ApexConfig:
    # Core
    mode: str = "fileparser"
    target_binary: Optional[str] = None
    target_args: str = "@@"
    source_mode: bool = True  # False = binary-only (QEMU)
    workers: int = 4
    timeout_ms: int = 5000
    memory_limit: int = 256  # MB

    # Corpus & Output
    corpus_dir: str = "./corpus"
    output_dir: str = "./crashes"

    # Network options
    protocol: Optional[str] = None
    target_host: str = "127.0.0.1"
    target_port: Optional[int] = None

    # File parser options
    file_format: Optional[str] = None

    # Kernel options
    syscall_groups: List[str] = field(default_factory=list)
    kernel_image: Optional[str] = None

    # Firmware options
    firmware_image: Optional[str] = None
    firmware_arch: str = "arm"
    firmware_endian: str = "little"

    # Sanitizers
    asan: bool = False
    msan: bool = False
    ubsan: bool = False
    tsan: bool = False
    dfsan: bool = False

    # Advanced
    symbolic: bool = False
    ml_mutator: bool = False
    snapshot: bool = False
    cmplog: bool = False
    grammar_file: Optional[str] = None

    # Dashboard
    dashboard: bool = False
    dashboard_port: int = 8080

    @classmethod
    def from_args(cls, args) -> "ApexConfig":
        """Build config from parsed CLI args."""
        cfg = cls()
        cfg.mode = args.mode
        cfg.target_binary = getattr(args, "target_binary", None)
        cfg.target_args = getattr(args, "target_args", "@@")
        cfg.source_mode = getattr(args, "source", False)
        cfg.workers = args.workers
        cfg.timeout_ms = args.timeout
        cfg.memory_limit = args.memory_limit
        cfg.corpus_dir = args.corpus
        cfg.output_dir = args.output

        cfg.protocol = getattr(args, "protocol", None)
        cfg.target_host = getattr(args, "target_host", "127.0.0.1")
        cfg.target_port = getattr(args, "target_port", None)

        cfg.file_format = getattr(args, "format", None)

        sc = getattr(args, "syscall_groups", None)
        cfg.syscall_groups = sc.split(",") if sc else []
        cfg.kernel_image = getattr(args, "kernel_image", None)

        cfg.firmware_image = getattr(args, "firmware_image", None)
        cfg.firmware_arch = getattr(args, "arch", "arm") or "arm"
        cfg.firmware_endian = getattr(args, "endian", "little")

        cfg.asan = getattr(args, "asan", False)
        cfg.msan = getattr(args, "msan", False)
        cfg.ubsan = getattr(args, "ubsan", False)
        cfg.tsan = getattr(args, "tsan", False)
        cfg.dfsan = getattr(args, "dfsan", False)

        cfg.symbolic = getattr(args, "symbolic", False)
        cfg.ml_mutator = getattr(args, "ml_mutator", False)
        cfg.snapshot = getattr(args, "snapshot", False)
        cfg.cmplog = getattr(args, "cmplog", False)
        cfg.grammar_file = getattr(args, "grammar_file", None)

        cfg.dashboard = getattr(args, "dashboard", False)
        cfg.dashboard_port = getattr(args, "dashboard_port", 8080)

        cfg.validate()
        return cfg

    def merge_from_file(self, path: str):
        """Merge a JSON config file over current settings."""
        data = json.loads(Path(path).read_text())
        for k, v in data.items():
            if hasattr(self, k):
                setattr(self, k, v)
        log.info(f"Merged config from {path}")

    def validate(self):
        """Validate the config and raise on fatal misconfigurations."""
        if self.mode in ("network", "fileparser", "firmware"):
            if not self.target_binary:
                log.warning("No --target-binary specified; module will use its own default.")

        if self.mode == "network" and not self.target_port:
            log.warning("No --target-port; defaulting to protocol default.")

        if self.mode == "firmware":
            if not self.firmware_image:
                raise ValueError("--firmware-image required for firmware mode")
            if not Path(self.firmware_image).exists():
                raise FileNotFoundError(f"Firmware image not found: {self.firmware_image}")

        if self.msan and self.asan:
            raise ValueError("MSan and ASan are mutually exclusive.")

        if self.workers < 1:
            raise ValueError("--workers must be >= 1")

        Path(self.corpus_dir).mkdir(parents=True, exist_ok=True)
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
        log.info(f"Config saved to {path}")
