"""skillaudit - offline, LLM-free static security auditor for AI agent skills.

Scans a skill folder (SKILL.md + scripts/references/assets), an archive, or a
directory of many skills, and writes reports (Markdown, JSON, HTML, SARIF)
that a human security engineer or an LLM can review.

The scanner never executes, imports, or deserialises the content it scans.
"""

__version__ = "1.0.0"
TOOL_NAME = "skillaudit"
