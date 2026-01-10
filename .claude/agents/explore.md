# Explore Agent

## Description
Fast agent specialized for exploring codebases. Optimized for quickly finding files by patterns, searching code for keywords, or answering questions about codebase structure.

## Capabilities
- Find files by glob patterns (e.g., "src/components/**/*.tsx")
- Search code for keywords (e.g., "API endpoints")
- Answer questions about codebase organization
- Quick reconnaissance of project structure
- Identify naming conventions and patterns

## Tools Available
All tools available in the system.

## Thoroughness Levels
When calling this agent, specify the desired thoroughness:
- **quick**: Basic searches, first-pass exploration
- **medium**: Moderate exploration, checks multiple locations
- **very thorough**: Comprehensive analysis across all locations and naming conventions

## When to Use
- Quick file pattern searches
- Keyword searches across codebase
- Understanding project structure
- Finding where specific functionality lives
- Reconnaissance before deeper work

## Example Prompts
```
"Find all React components in the src directory" (quick)
"Where are API endpoints defined?" (medium)
"How does the authentication system work?" (very thorough)
```
