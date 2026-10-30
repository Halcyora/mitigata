# AI GitHub Repository Catalogue — PS5 Annotated

Prepared: 11 October 2026. Updated for PS5 relevance: 31 October 2026.  
A curated exploration list, not a ranked benchmark or production certification.

> **PS5 context:** Only **LangGraph** (04-Orchestration) is required for PS5. The other entries are reference material for future framework decisions.

| Category | Repository | What to explore | PS5 Relevance |
| --- | --- | --- | --- |
| 01-Discovery | [Awesome LLM Apps](https://github.com/Shubhamsaboo/awesome-llm-apps) | Agent, skills and RAG application examples | ⬜ Not needed for PS5 |
| 01-Discovery | [Awesome AI Agents](https://github.com/e2b-dev/awesome-ai-agents) | Directory of autonomous-agent projects | ⬜ Not needed for PS5 |
| 02-Agent-Platforms | [Dify](https://github.com/langgenius/dify) | Application platform for agent workflows, RAG, models and tools; supports self-hosting | ⬜ Not needed for PS5 |
| 02-Agent-Platforms | [Flowise](https://github.com/FlowiseAI/Flowise) | Visual builder for AI agents and workflows | ⬜ Not needed for PS5 |
| 03-Coding-Agents | [OpenHands](https://github.com/OpenHands/OpenHands) | AI-driven software-development platform | ⬜ Not needed for PS5 |
| 04-Orchestration | [LangGraph](https://github.com/langchain-ai/langgraph) | Long-running stateful agent orchestration, durable execution and human review | ✅ **Required** — PS5 §3.3 verification loop; see [04-Orchestration/LangGraph.md](04-Orchestration/LangGraph.md) |
| 04-Orchestration | [CrewAI](https://github.com/crewAIInc/crewAI) | Framework coordinating role-based agents and tasks | ⬜ Not needed for PS5 |
| 05-Automation | [n8n](https://github.com/n8n-io/n8n) | Workflow automation with AI capabilities and integrations; fair-code licensing | ⬜ Not needed for PS5 |
| 06-Skills-and-Guardrails | [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | Programmable guardrails for LLM conversational systems; not a replacement for execution isolation | ⬜ Not needed for PS5 |
| 06-Skills-and-Guardrails | [Matt Pocock Skills](https://github.com/mattpocock/skills) | Composable engineering instructions to review and adapt for coding agents | ⬜ Not needed for PS5 |

## PS5 Quick Reference

For PS5, go directly to:

1. **[LangGraph.md](04-Orchestration/LangGraph.md)** — state machine design, skeleton code, safety constraints
2. **[08-Prototypes/README.md](08-Prototypes/README.md)** — architecture decisions, vulnerability seeding plan, setup instructions
3. **[../docs/PS5-SAST-DAST-Correlation-Engine.md](../docs/PS5-SAST-DAST-Correlation-Engine.md)** — full problem statement and scoring

## General exploration order (non-PS5)

1. Awesome LLM Apps: discover concrete examples.
2. Dify or Flowise: inspect a complete visual application platform.
3. OpenHands: inspect coding-agent execution.
4. LangGraph or CrewAI: examine orchestration approaches.
5. n8n: explore integrations and operational workflows.
6. Matt Pocock Skills and NeMo Guardrails: distinguish behavioral guidance from programmable controls.

Before commercial adoption, verify the current license, deployment requirements, maintenance, data handling and security model.
