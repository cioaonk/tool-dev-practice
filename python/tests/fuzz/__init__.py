"""
CPTC11 Fuzz Tests Package
=========================

This package contains property-based fuzz tests using Hypothesis.
Fuzz tests generate random inputs to find edge cases and potential
security vulnerabilities in input validation functions.

Test Modules:
- test_fuzz_network_inputs.py: IP address and CIDR range parsing
- test_fuzz_port_inputs.py: Port specification parsing
- test_fuzz_url_inputs.py: URL and path handling

Run fuzz tests with:
    pytest tests/fuzz/ -v -m fuzz --hypothesis-show-statistics

Or use the Makefile:
    make test-fuzz
"""
