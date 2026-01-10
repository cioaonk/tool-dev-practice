# Beginner Feedback Report

**Reviewer**: Alex Chen
**Background**: College sophomore, basic Python knowledge (Python 101), no penetration testing experience
**Skill Level**: 1/5
**Date**: January 2026

---

## Executive Summary

As someone completely new to cybersecurity and penetration testing, I found these training materials to be very thorough but also quite overwhelming at times. There is a LOT of information here, and while the structure is good, I often felt lost without more foundational explanations. This report captures my honest experience working through the materials as a beginner.

---

## Overall Impressions

### What Works Well
- The materials are well-organized with clear directory structure
- The progression path (Phase 1-4) makes sense conceptually
- Including "plan mode" (`--plan`) before actual execution is a great safety feature
- The diagrams (like the TCP handshake) are helpful visual aids
- Having a time estimate for each walkthrough is appreciated

### What Needs Improvement
- Too many assumed prerequisites that are not actually explained
- Jumps from basic concepts to complex commands too quickly
- Missing "why" explanations for many steps
- Terminology is not defined for beginners
- No glossary or quick reference for unfamiliar terms

---

## Document-by-Document Review

### README.md

**Difficulty Rating: 3/5** (harder than it should be for an intro document)

#### Confusing Parts

1. **Prerequisites Table** - The "Beginner" prerequisites say:
   - "Basic networking (IP addresses, ports, protocols)"
   - "Client-server architecture"

   **My Question**: What does "basic" mean? I know what an IP address looks like (like 192.168.1.1), but I do not know what a "port" actually is or does. Is it like a door? A channel? The document never explains this.

2. **CIDR Notation** - The document mentions "/24 network" multiple times but never explains what this means. I had to Google it. Why not include a quick explanation like "a /24 network contains 256 IP addresses"?

3. **Root/Administrator access** - The prerequisites mention needing "Root/Administrator access for certain scanning techniques." What does this mean practically? Will I break something if I do not have root? Which techniques need it?

4. **Phase 3 mentions "reverse shells"** - I have no idea what a reverse shell is at this point. The term just appears with no context. Should I be scared? Is this legal?

#### Suggestions
- Add a "Key Terms" section at the beginning defining: port, protocol, shell, reverse shell, enumeration, fingerprinting
- Explain CIDR notation briefly
- Add a "What You Will Learn" section that explains the overall goal in plain English

---

### Network Scanner Walkthrough

**Difficulty Rating: 3.5/5** (intermediate, not beginner)

#### Things I Liked
- The TCP handshake diagram is great - finally I understand SYN/ACK!
- The "Stealth Continuum" diagram is helpful
- Expected output examples show me what success looks like
- Troubleshooting section is practical

#### Confusing Parts

1. **Page 1 hits me with "reconnaissance"** - What does reconnaissance even mean in this context? I think it means gathering information, but is it like spying? Scouting?

2. **"Your Machine | Target (port open)" diagrams** - I understand the arrows, but what is actually happening? What is a SYN? What is RST? These acronyms are never defined.

3. **Scanning Method Comparison Table** - Lists "TCP Connect", "TCP SYN", "UDP", "ARP", "DNS" - I recognize TCP and DNS from school, but:
   - What is the difference between TCP Connect and TCP SYN?
   - What is ARP?
   - What is "LAN" in the ARP row?

4. **"Privileges" column** - Some say "None" and some say "Root". What happens if I do not have root? Will the tool fail? Will it work partially?

5. **Pattern 3: Stealthy Scanning** - The command has flags like `--delay-min 2 --delay-max 10`. What are the units? Seconds? Milliseconds? Minutes?

6. **Programmatic Integration section** - Shows Python code importing from "tool". As a Python 101 student, I do not understand:
   - Where does the `tool` module come from?
   - What is `ScanConfig`? A class? A function?
   - The code assumes I know what a "config object" pattern is

7. **Port Scanner section mentions "top20" and "top100"** - Top 20 of what? Most common ports on the internet? Most commonly attacked? How do I know what is in this list?

#### My "Dumb Questions"
- If I scan something, can the target see that I scanned them?
- Is it illegal to scan networks? The document mentions "authorized testing" but what if I accidentally scan something I should not?
- Why would I need "stealth"? Am I hiding from someone?
- What is a "banner" and why would I want to "grab" it?

#### Suggestions
- Add a "What is a Port?" section explaining ports with real-world analogies (like: "If an IP address is like a building address, a port is like an apartment number")
- Define SYN, ACK, RST - maybe with a quick reference card
- Clarify units for all timing parameters
- Add a warning about legal considerations BEFORE the technical content

---

### Payload Generator Walkthrough

**Difficulty Rating: 4/5** (definitely not beginner-friendly)

#### Things I Liked
- The ASCII diagrams showing how reverse shells work are helpful
- The table comparing shell types gives good overview
- Having both `--plan` output and actual execution examples is nice

#### Confusing Parts

1. **The word "payload"** - This sounds scary and military. Is this like a bomb? The document never defines what a payload actually is in this context.

2. **"Reverse Shell Architecture" diagram** - I kind of understand it (target connects back to attacker), but:
   - Why is this needed? Why not just connect directly?
   - What is a "handler"?
   - What does "bidirectional shell communication" mean?

3. **Detection Vectors table** - Mentions "AMSI", "Living-off-the-land", "AV" - none of these are explained:
   - What is AMSI?
   - What does "living-off-the-land" mean? Are we camping?
   - I assume AV is antivirus but it should be spelled out

4. **The generated Python payload code**:
   ```python
   os.dup2(s.fileno(),0)
   os.dup2(s.fileno(),1)
   os.dup2(s.fileno(),2)
   ```
   I have taken Python 101 but I have no idea what `dup2` does or what 0, 1, 2 mean here. This is way beyond my current skill level.

5. **Obfuscation Levels** - What is obfuscation? The table says Level 0 is "No obfuscation" and Level 3 is "Advanced techniques" but what does obfuscation actually DO?

6. **Shellcode Encoder section** - This entire section lost me:
   - What is shellcode?
   - What is XOR encoding?
   - Why would I need to encode anything?
   - What are "null bytes" and why are they bad?

7. **"Download cradle"** - What is a cradle? Why would I download one?

#### My "Dumb Questions"
- Is creating a payload legal?
- If I generate a reverse shell, will antivirus flag my computer?
- What actually happens when a reverse shell "connects back"? Do I see a command prompt?
- Why are there so many different languages (Python, Bash, PowerShell) for the same thing?

#### Suggestions
- Add a beginner intro explaining: "A payload is simply code that runs on a target system to give you access"
- Explain the fundamental concept of reverse vs. bind shells with a real-world analogy (like: "Imagine you cannot call someone because they have blocked incoming calls, but they CAN call you - that is like a reverse shell")
- Add a "You do not need to understand this yet" marker for advanced sections like shellcode encoding
- Include a legal disclaimer at the BEGINNING of this walkthrough

---

### EDR Evasion Walkthrough

**Difficulty Rating: 5/5** (way too advanced for beginners)

#### Honest Assessment
I am going to be blunt: I should not be reading this walkthrough yet. Almost nothing in this document makes sense to me as a beginner. I will try to identify what confused me, but this entire walkthrough feels like it belongs in an advanced course.

#### Confusing Parts (there are many)

1. **The title itself** - "EDR Evasion" - What is EDR? The document eventually explains it stands for "Endpoint Detection and Response" but this should be defined IMMEDIATELY, ideally before the table of contents.

2. **Prerequisites say "Understanding of Windows architecture (processes, memory, DLLs)"** - I do not have this understanding at all. What is a DLL? What does "process" mean in Windows specifically?

3. **First diagram shows "ntdll.dll"** - I have never heard of this. What is ntdll? Why does it matter?

4. **Assembly code appears**:
   ```asm
   mov r10, rcx          ; 4C 8B D1
   mov eax, 0x18         ; B8 18 00 00 00
   syscall               ; 0F 05
   ```
   I have never seen assembly language before. I do not know what `mov`, `rcx`, `eax`, or `syscall` mean. The hex codes mean nothing to me.

5. **"User-Mode Hooks"** - What is user mode? What is a hook? Why would anyone want to "hook" something?

6. **"Kernel callbacks", "ETW"** - These terms just appear without explanation. The document assumes I know what a kernel is and what ETW stands for.

7. **"MITRE ATT&CK"** - This is mentioned many times but I have no idea what it is. Is it a tool? A framework? A company? A database?

8. **The AMSI section** - Talks about "patching AmsiScanBuffer" - I do not understand:
   - What is patching?
   - What is a buffer?
   - Why would I want to patch anything?

#### My "Dumb Questions"
- Is this walkthrough teaching me to evade security software? Is that legal?
- Why would I ever need to know assembly language?
- If EDR is meant to protect computers, why am I learning to bypass it?
- This feels like hacking - am I learning to be a hacker?

#### Suggestions
- Add a CLEAR prerequisite check at the beginning: "Do not proceed unless you understand X, Y, Z"
- Consider splitting into two walkthroughs: "Understanding EDR" (beginner) and "EDR Evasion Techniques" (advanced)
- Add context about when/why this knowledge is useful (red team engagements, competition scenarios)
- The disclaimer at the top is good but should be more prominent

---

### Lab 01: Network Reconnaissance

**Difficulty Rating: 3/5** (manageable with the walkthrough)

#### Things I Liked
- Clear task structure with levels
- Having validation criteria ("You should discover at least 5 live hosts")
- Hints in collapsible sections - I can try first, then get help
- Point values help me understand priorities
- Scenario context (CorpTech Industries) makes it feel real

#### Confusing Parts

1. **Task 1 uses `/path/to/network-scanner/tool.py`** - This is a placeholder path. What is the ACTUAL path? I do not know how to find where the tools are installed.

2. **Task 2 mentions "top100" ports** - Still do not know what this list contains

3. **Task 5 says to design a "scan strategy"** - I do not have enough knowledge yet to design anything. How can I design something I barely understand?

4. **Challenge 1: "Identify the Domain Controller"** - What is a domain controller? I know it is a Windows thing but what does it actually do?

5. **Challenge 3: "Time-optimized"** - Optimize for what exactly? Speed vs. stealth? I thought being fast was bad because of detection?

#### My "Dumb Questions"
- Where do I get the actual lab environment? The setup section says "target lab network" but how do I set this up?
- If I am at home practicing, do I need special software?
- Can I accidentally break something in the lab?

#### Suggestions
- Provide actual tool paths, not placeholders
- Add a "Lab Setup Guide" section with instructions on how to create/access the lab environment
- Include screenshots showing what successful output looks like
- Consider a "Task 0" that just verifies the environment is working

---

## Terminology That Needs Definitions

Here is a list of terms that appeared without adequate explanation:

| Term | Where It Appeared | My Understanding Level |
|------|-------------------|----------------------|
| Port | Throughout | Vague - something services listen on? |
| Protocol | README | Very vague |
| Enumeration | README | No idea |
| Fingerprinting | README | Sounds like crime shows |
| Shell | Payload walkthrough | A command line thing? |
| Reverse shell | Payload walkthrough | Sort of understand after reading |
| Payload | Payload walkthrough | Still unclear |
| Obfuscation | Payload walkthrough | Hiding something? |
| Shellcode | Payload walkthrough | No clue |
| EDR | EDR walkthrough | Defined eventually but late |
| AMSI | Multiple places | No idea |
| Syscall | EDR walkthrough | Something low-level? |
| Hooking | EDR walkthrough | No idea |
| Kernel | EDR walkthrough | The core of the OS? |
| ntdll | EDR walkthrough | Never heard of it |
| MITRE ATT&CK | EDR walkthrough | Some framework? |

---

## Recommended Additions

### 1. Glossary Document
Create a `/training/glossary.md` with definitions of all technical terms, sorted alphabetically.

### 2. "Absolute Beginner" Prerequisites Document
Before any walkthroughs, create a document that teaches:
- What is a port?
- What is TCP vs UDP?
- What is the command line?
- What does "running as root" mean?
- What is a network range?
- What is CIDR notation?

### 3. Legal and Ethics Section
Add a dedicated document covering:
- When is scanning legal?
- What authorization do you need?
- What can go wrong?
- Competition rules and boundaries

### 4. Visual Workflow Diagram
Create a visual showing the entire learning path:
```
[You Are Here] --> Network Scanning --> Port Scanning --> Service ID --> Payloads --> Evasion
     ^
     |
     Prerequisites
```

### 5. FAQ Document
Common questions like:
- "Will my antivirus flag these tools?"
- "Can I practice at home?"
- "What if I scan the wrong thing by accident?"

---

## Summary Ratings

| Document | Difficulty | Beginner-Friendly? | Suggested Skill Level |
|----------|------------|-------------------|----------------------|
| README.md | 3/5 | Partially | 2/5 |
| Network Scanner Walkthrough | 3.5/5 | Partially | 2/5 |
| Payload Generator Walkthrough | 4/5 | No | 3/5 |
| EDR Evasion Walkthrough | 5/5 | Definitely No | 4/5 |
| Lab 01 | 3/5 | Yes, with walkthrough | 2/5 |

---

## Final Thoughts

I appreciate that these materials exist and are well-structured. However, as a true beginner, I feel like I am being thrown into the deep end without swimming lessons.

The progression makes sense (scanning before payloads before evasion), but each individual walkthrough assumes more knowledge than I have. The Network Scanner walkthrough is the most accessible, and I would focus on making it even more beginner-friendly first.

The EDR Evasion walkthrough should probably have a big warning that says "Complete all previous modules before attempting this one" and maybe even a quick quiz to check prerequisites.

Despite my struggles, I am excited to learn more. I just need more foundational material to build on.

---

**Questions for the Training Team:**

1. Is there a recommended external resource (book, course) for the true prerequisites?
2. Should I set up my own lab environment? If so, how?
3. Are there practice exercises simpler than Lab 01 to start with?
4. Is there a Discord/Slack for asking questions during learning?

---

*Report submitted by Alex Chen - Beginner Security Student*
