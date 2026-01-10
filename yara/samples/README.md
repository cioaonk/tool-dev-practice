# Test Samples Directory

This directory contains test samples for validating YARA rules.

## Structure

```
samples/
├── benign/           # Benign files for false positive testing
│   ├── hello.txt     # Simple text file
│   ├── calculator.py # Benign Python script
│   └── webpage.html  # Simple HTML file
└── README.md         # This file
```

## Purpose

These samples are used to:

1. **Verify Detection**: Ensure rules detect intended patterns
2. **Test False Positives**: Ensure benign files don't trigger alerts
3. **Performance Testing**: Benchmark scanning speed

## Usage

```bash
# Scan benign samples (should produce 0 matches)
python ../yara_scanner.py --directory ./benign --recursive

# Scan all samples
python ../yara_scanner.py --directory . --recursive
```

## Adding Test Samples

When adding new test samples:

1. Place benign files in `benign/` subdirectory
2. Document the expected behavior
3. Run tests to verify rule behavior

## Warning

Do not store actual malware samples in this directory unless in a properly isolated environment.
