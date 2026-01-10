#!/usr/bin/env python3
"""
Hash Cracker - Multi-Algorithm Hash Cracking Utility
=====================================================

A comprehensive hash cracking utility supporting multiple algorithms
with dictionary and rule-based attacks. Operates entirely in-memory.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Only crack hashes you have explicit permission to test.
"""

import argparse
import hashlib
import sys
import time
import threading
import itertools
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable, Generator
from datetime import datetime
from enum import Enum


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_THREADS = 4


class HashType(Enum):
    """Supported hash algorithms."""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    NTLM = "ntlm"
    MD5_CRYPT = "md5crypt"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class HashTarget:
    """Represents a hash to crack."""
    hash_value: str
    hash_type: Optional[HashType] = None
    username: Optional[str] = None
    cracked: bool = False
    plaintext: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hash": self.hash_value,
            "type": self.hash_type.value if self.hash_type else None,
            "username": self.username,
            "cracked": self.cracked,
            "plaintext": self.plaintext
        }


@dataclass
class CrackConfig:
    """Configuration for hash cracking."""
    hashes: List[HashTarget] = field(default_factory=list)
    wordlist: Optional[str] = None
    hash_type: Optional[HashType] = None
    threads: int = DEFAULT_THREADS
    rules: List[str] = field(default_factory=list)
    min_length: int = 1
    max_length: int = 8
    charset: str = "lowercase"
    verbose: bool = False
    plan_mode: bool = False


@dataclass
class CrackResult:
    """Result of cracking operation."""
    total_hashes: int = 0
    cracked_count: int = 0
    attempts: int = 0
    duration: float = 0.0
    rate: float = 0.0
    results: List[HashTarget] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_hashes": self.total_hashes,
            "cracked_count": self.cracked_count,
            "attempts": self.attempts,
            "duration": self.duration,
            "rate": self.rate,
            "results": [r.to_dict() for r in self.results if r.cracked]
        }


# =============================================================================
# Hash Functions
# =============================================================================

class HashEngine:
    """
    Hash computation engine supporting multiple algorithms.

    All computations are in-memory with no disk artifacts.
    """

    @staticmethod
    def md5(plaintext: str) -> str:
        """Compute MD5 hash."""
        return hashlib.md5(plaintext.encode()).hexdigest()

    @staticmethod
    def sha1(plaintext: str) -> str:
        """Compute SHA1 hash."""
        return hashlib.sha1(plaintext.encode()).hexdigest()

    @staticmethod
    def sha256(plaintext: str) -> str:
        """Compute SHA256 hash."""
        return hashlib.sha256(plaintext.encode()).hexdigest()

    @staticmethod
    def sha512(plaintext: str) -> str:
        """Compute SHA512 hash."""
        return hashlib.sha512(plaintext.encode()).hexdigest()

    @staticmethod
    def ntlm(plaintext: str) -> str:
        """Compute NTLM hash."""
        return hashlib.new('md4', plaintext.encode('utf-16-le')).hexdigest()

    @classmethod
    def get_hasher(cls, hash_type: HashType) -> Callable[[str], str]:
        """Get hash function for a type."""
        hashers = {
            HashType.MD5: cls.md5,
            HashType.SHA1: cls.sha1,
            HashType.SHA256: cls.sha256,
            HashType.SHA512: cls.sha512,
            HashType.NTLM: cls.ntlm,
        }
        return hashers.get(hash_type, cls.md5)


# =============================================================================
# Hash Type Detection
# =============================================================================

def detect_hash_type(hash_value: str) -> Optional[HashType]:
    """
    Attempt to detect hash type based on length and format.

    Args:
        hash_value: Hash string to analyze

    Returns:
        Detected HashType or None
    """
    hash_value = hash_value.lower().strip()
    length = len(hash_value)

    # Check if valid hex
    try:
        int(hash_value, 16)
    except ValueError:
        return None

    # Detect by length
    if length == 32:
        return HashType.MD5  # Could also be NTLM
    elif length == 40:
        return HashType.SHA1
    elif length == 64:
        return HashType.SHA256
    elif length == 128:
        return HashType.SHA512

    return None


# =============================================================================
# Word Generation
# =============================================================================

class WordGenerator:
    """Generate candidate passwords."""

    CHARSETS = {
        "lowercase": string.ascii_lowercase,
        "uppercase": string.ascii_uppercase,
        "digits": string.digits,
        "alpha": string.ascii_letters,
        "alphanumeric": string.ascii_letters + string.digits,
        "all": string.ascii_letters + string.digits + string.punctuation,
    }

    def __init__(self, config: CrackConfig):
        self.config = config
        self.charset = self.CHARSETS.get(config.charset, string.ascii_lowercase)

    def from_wordlist(self) -> Generator[str, None, None]:
        """Generate words from wordlist file."""
        if not self.config.wordlist:
            return

        try:
            with open(self.config.wordlist, 'r', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        yield word
                        # Apply rules
                        for mutated in self._apply_rules(word):
                            yield mutated
        except Exception:
            pass

    def _apply_rules(self, word: str) -> Generator[str, None, None]:
        """Apply mutation rules to a word."""
        for rule in self.config.rules:
            if rule == "capitalize":
                yield word.capitalize()
            elif rule == "uppercase":
                yield word.upper()
            elif rule == "reverse":
                yield word[::-1]
            elif rule == "append_numbers":
                for i in range(100):
                    yield f"{word}{i}"
            elif rule == "append_year":
                for year in range(2020, 2027):
                    yield f"{word}{year}"
            elif rule == "leet":
                yield self._leetspeak(word)

    def _leetspeak(self, word: str) -> str:
        """Convert word to leetspeak."""
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        return ''.join(leet_map.get(c.lower(), c) for c in word)

    def bruteforce(self) -> Generator[str, None, None]:
        """Generate words via bruteforce."""
        for length in range(self.config.min_length, self.config.max_length + 1):
            for combo in itertools.product(self.charset, repeat=length):
                yield ''.join(combo)


# =============================================================================
# Hash Cracker Core
# =============================================================================

class HashCracker:
    """
    Main hash cracking engine.

    Coordinates hash computation, word generation, and result tracking.
    All operations are in-memory.
    """

    def __init__(self, config: CrackConfig):
        self.config = config
        self.result = CrackResult()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._hash_lookup: Dict[str, HashTarget] = {}
        self._attempts = 0

    def _prepare_hashes(self) -> None:
        """Build hash lookup table."""
        for target in self.config.hashes:
            hash_lower = target.hash_value.lower()
            self._hash_lookup[hash_lower] = target

            # Detect type if not specified
            if not target.hash_type:
                target.hash_type = self.config.hash_type or detect_hash_type(target.hash_value)

    def _check_word(self, word: str, hasher: Callable[[str], str]) -> Optional[str]:
        """
        Check a word against all uncracked hashes.

        Returns the hash value if cracked, None otherwise.
        """
        computed = hasher(word).lower()

        if computed in self._hash_lookup:
            target = self._hash_lookup[computed]
            if not target.cracked:
                return computed

        return None

    def _crack_worker(self, words: List[str]) -> List[tuple]:
        """Worker function to check a batch of words."""
        results = []

        # Get hasher for first hash type (assuming all same type)
        if self.config.hashes:
            hash_type = self.config.hashes[0].hash_type or HashType.MD5
            hasher = HashEngine.get_hasher(hash_type)
        else:
            return results

        for word in words:
            if self._stop_event.is_set():
                break

            with self._lock:
                self._attempts += 1

            cracked_hash = self._check_word(word, hasher)
            if cracked_hash:
                results.append((cracked_hash, word))

                # Check if all hashes cracked
                all_cracked = all(t.cracked for t in self.config.hashes)
                if all_cracked:
                    self._stop_event.set()
                    break

        return results

    def crack(self) -> CrackResult:
        """
        Execute hash cracking.

        Returns:
            CrackResult with cracking statistics and results
        """
        self._prepare_hashes()
        self.result.total_hashes = len(self.config.hashes)

        if self.config.verbose:
            print(f"[*] Loaded {self.result.total_hashes} hashes")

        start_time = time.time()

        # Generate words
        generator = WordGenerator(self.config)

        if self.config.wordlist:
            words = list(generator.from_wordlist())
            if self.config.verbose:
                print(f"[*] Wordlist loaded: {len(words)} candidates")
        else:
            # For bruteforce, we process in chunks
            words = []

        # Process words in batches
        batch_size = 10000
        current_batch = []

        word_iter = iter(words) if words else generator.bruteforce()

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []

            for word in word_iter:
                if self._stop_event.is_set():
                    break

                current_batch.append(word)

                if len(current_batch) >= batch_size:
                    future = executor.submit(self._crack_worker, current_batch.copy())
                    futures.append(future)
                    current_batch = []

                    # Process completed futures
                    for f in [fut for fut in futures if fut.done()]:
                        try:
                            results = f.result()
                            for hash_val, plaintext in results:
                                target = self._hash_lookup.get(hash_val)
                                if target:
                                    target.cracked = True
                                    target.plaintext = plaintext
                                    self.result.cracked_count += 1

                                    if self.config.verbose:
                                        print(f"[+] Cracked: {hash_val[:16]}... = {plaintext}")
                        except Exception:
                            pass

            # Process remaining batch
            if current_batch and not self._stop_event.is_set():
                results = self._crack_worker(current_batch)
                for hash_val, plaintext in results:
                    target = self._hash_lookup.get(hash_val)
                    if target:
                        target.cracked = True
                        target.plaintext = plaintext
                        self.result.cracked_count += 1

        self.result.duration = time.time() - start_time
        self.result.attempts = self._attempts
        self.result.rate = self._attempts / self.result.duration if self.result.duration > 0 else 0
        self.result.results = self.config.hashes

        return self.result

    def stop(self) -> None:
        """Stop cracking operation."""
        self._stop_event.set()


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: CrackConfig) -> None:
    """Display execution plan without performing any actions."""
    print("""
[PLAN MODE] Tool: hash-cracker
================================================================================
""")

    print("HASH TARGETS")
    print("-" * 40)
    print(f"  Total Hashes:    {len(config.hashes)}")
    for i, target in enumerate(config.hashes[:5]):
        hash_type = target.hash_type.value if target.hash_type else "auto-detect"
        print(f"  [{i+1}] {target.hash_value[:32]}... ({hash_type})")
    if len(config.hashes) > 5:
        print(f"  ... and {len(config.hashes) - 5} more")
    print()

    print("ATTACK CONFIGURATION")
    print("-" * 40)
    if config.wordlist:
        print(f"  Mode:            Dictionary Attack")
        print(f"  Wordlist:        {config.wordlist}")
    else:
        print(f"  Mode:            Bruteforce Attack")
        print(f"  Charset:         {config.charset}")
        print(f"  Length Range:    {config.min_length} - {config.max_length}")

    if config.rules:
        print(f"  Rules:           {', '.join(config.rules)}")
    print(f"  Threads:         {config.threads}")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. Load and validate target hashes")
    print("  2. Auto-detect hash types (if not specified)")
    if config.wordlist:
        print("  3. Load wordlist into memory")
        if config.rules:
            print("  4. Apply mutation rules to each word")
        print("  5. Compute hashes and compare (multi-threaded)")
    else:
        print("  3. Generate bruteforce candidates")
        print("  4. Compute hashes and compare (multi-threaded)")
    print("  6. Report cracked hashes")
    print()

    print("SUPPORTED ALGORITHMS")
    print("-" * 40)
    print("  - MD5 (32 characters)")
    print("  - SHA1 (40 characters)")
    print("  - SHA256 (64 characters)")
    print("  - SHA512 (128 characters)")
    print("  - NTLM (32 characters)")
    print()

    print("OPSEC CONSIDERATIONS")
    print("-" * 40)
    print("  - All operations are in-memory")
    print("  - No network activity")
    print("  - No disk writes for hash computations")
    print("  - Results can be exported to file if needed")
    print()

    print("=" * 80)
    print("No actions will be taken. Remove --plan flag to execute.")
    print("=" * 80)


# =============================================================================
# Documentation Hooks
# =============================================================================

def get_documentation() -> Dict[str, Any]:
    """Return structured documentation for integration."""
    return {
        "name": "hash-cracker",
        "version": "1.0.0",
        "category": "utility",
        "description": "Multi-algorithm hash cracking utility",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Multiple hash algorithm support",
            "Dictionary attacks",
            "Bruteforce attacks",
            "Rule-based mutations",
            "Auto hash type detection",
            "Multi-threaded processing",
            "In-memory operation"
        ],
        "supported_algorithms": ["MD5", "SHA1", "SHA256", "SHA512", "NTLM"],
        "arguments": {
            "hash": {
                "type": "string",
                "description": "Hash to crack (or use --file)"
            },
            "--file": {
                "type": "file",
                "description": "File containing hashes"
            },
            "--wordlist": {
                "type": "file",
                "description": "Wordlist for dictionary attack"
            },
            "--type": {
                "type": "string",
                "choices": ["md5", "sha1", "sha256", "sha512", "ntlm"],
                "description": "Hash type (auto-detect if not specified)"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan"
            }
        }
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Hash Cracker - Multi-Algorithm Hash Cracking Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
  %(prog)s --file hashes.txt -w rockyou.txt --type md5
  %(prog)s 5f4dcc3b5aa765d61d8327deb882cf99 --bruteforce -c alphanumeric

WARNING: Only crack hashes you have permission to test.
        """
    )

    parser.add_argument(
        "hash",
        nargs="?",
        help="Hash to crack"
    )

    parser.add_argument(
        "-f", "--file",
        help="File containing hashes (one per line)"
    )

    parser.add_argument(
        "-w", "--wordlist",
        help="Wordlist for dictionary attack"
    )

    parser.add_argument(
        "-t", "--type",
        choices=["md5", "sha1", "sha256", "sha512", "ntlm"],
        help="Hash type (auto-detect if not specified)"
    )

    parser.add_argument(
        "-r", "--rules",
        help="Comma-separated rules: capitalize,uppercase,reverse,append_numbers,append_year,leet"
    )

    parser.add_argument(
        "-b", "--bruteforce",
        action="store_true",
        help="Enable bruteforce mode (if no wordlist)"
    )

    parser.add_argument(
        "-c", "--charset",
        default="lowercase",
        choices=["lowercase", "uppercase", "digits", "alpha", "alphanumeric", "all"],
        help="Charset for bruteforce (default: lowercase)"
    )

    parser.add_argument(
        "--min-length",
        type=int,
        default=1,
        help="Minimum length for bruteforce (default: 1)"
    )

    parser.add_argument(
        "--max-length",
        type=int,
        default=6,
        help="Maximum length for bruteforce (default: 6)"
    )

    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of threads (default: {DEFAULT_THREADS})"
    )

    parser.add_argument(
        "-p", "--plan",
        action="store_true",
        help="Show execution plan without cracking"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for results"
    )

    return parser.parse_args()


def load_hashes(args) -> List[HashTarget]:
    """Load hashes from arguments."""
    hashes = []

    # Single hash
    if args.hash:
        hashes.append(HashTarget(hash_value=args.hash))

    # Hash file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Support username:hash format
                        if ':' in line:
                            username, hash_val = line.split(':', 1)
                            hashes.append(HashTarget(hash_value=hash_val, username=username))
                        else:
                            hashes.append(HashTarget(hash_value=line))
        except Exception as e:
            print(f"[!] Error loading hash file: {e}")

    return hashes


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Load hashes
    hashes = load_hashes(args)

    if not hashes and not args.plan:
        print("[!] No hashes specified")
        print("[*] Use a hash argument or --file option")
        return 1

    # Parse hash type
    hash_type = None
    if args.type:
        hash_type = HashType(args.type)

    # Parse rules
    rules = []
    if args.rules:
        rules = [r.strip() for r in args.rules.split(',')]

    # Build configuration
    config = CrackConfig(
        hashes=hashes if hashes else [HashTarget(hash_value="example")],
        wordlist=args.wordlist,
        hash_type=hash_type,
        threads=args.threads,
        rules=rules,
        min_length=args.min_length,
        max_length=args.max_length,
        charset=args.charset,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute cracking
    print(f"[*] Hash Cracker starting...")
    print(f"[*] Hashes: {len(config.hashes)}")
    print(f"[*] Mode: {'Dictionary' if config.wordlist else 'Bruteforce'}")

    cracker = HashCracker(config)

    try:
        result = cracker.crack()

        # Display results
        print()
        print("=" * 60)
        print("CRACKING RESULTS")
        print("=" * 60)
        print(f"Total hashes:     {result.total_hashes}")
        print(f"Cracked:          {result.cracked_count}")
        print(f"Attempts:         {result.attempts:,}")
        print(f"Duration:         {result.duration:.2f}s")
        print(f"Rate:             {result.rate:,.0f} H/s")
        print()

        if result.cracked_count > 0:
            print("CRACKED HASHES:")
            print("-" * 60)
            for target in result.results:
                if target.cracked:
                    user_str = f"{target.username}:" if target.username else ""
                    print(f"  {user_str}{target.hash_value[:32]}... = {target.plaintext}")

        # Output to file if requested
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Cracking interrupted by user")
        cracker.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
