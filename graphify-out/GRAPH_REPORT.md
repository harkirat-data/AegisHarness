# Graph Report - AegisHarness  (2026-10-31)

## Corpus Check
- 123 files · ~272,011 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 16 file(s) not represented in the graph (top: .csv 6, .db 3, (none) 2)

## Summary
- 1393 nodes · 2837 edges · 91 communities (63 shown, 28 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 320 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `18b19a51`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- AttackController
- TamperProofAuditLedger
- server.py
- environment.py
- json
- aegis_app.js
- test_multi_model_and_voice.py
- AegisHarness: Tri-Workload Zero-Trust Evaluation Sandbox for Adversarial AI Safety
- models.py
- detect_system_hardware
- CampaignManager
- AdversarialScenarioEvaluator
- aegis-orchestrator
- AgentOutcomeType
- ToolResult
- controller.py
- post
- gemma4.md
- AutonomousAgentController
- test_chat_workbench.py
- orchestrator.py
- Brag Plan: AegisHarness
- test_verifiable_pipeline.py
- Workspace Operating Profile
- AegisDashboard
- test_agent_controller.py
- Assistant Operating Specification
- Mistral-Large-4.md
- Assistant Operating Specification
- render_brag_video.py
- Assistant Operating Specification
- Agent Operating Instructions
- 🛡️ AegisHarness: Secure Multi-Tenant Sandbox for Adversarial AI Safety Testing
- LocalLLMClient
- ThreatSeverity
- aegis_3d_artifacts.js
- ToolCallRequest
- tools.py
- uuid
- ConnectionManager
- JailbreakLibrary
- AegisHarness: Empirical Adversarial Evaluation & Verification Report
- Operating Policy
- package.json
- MockRestrictedToolLLMClient
- Ponytail Help
- generate_voice_briefing
- AGENTS.md
- 📘 Explainer Note 04: Zero-Trust Egress Firewall & Threat Classification
- test_comprehensive_security_eval.py
- 📘 Explainer Note 01: Project Foundation & The Big Picture
- ponytail-audit/SKILL.md
- Ponytail Gain
- ponytail-review/SKILL.md
- Ponytail
- Curriculum Vitae — John Doe
- 📘 Explainer Note 05: Red-Team Attack Suite & Automated Runner
- 📘 Explainer Note 07: Real-Time API Gateway & WebSocket Telemetry
- 📘 Explainer Note 08: Cyber-Defense Tri-Column Frontend Dashboard
- 📘 Explainer Note 09: Test Verification, Docker & Production Readiness
- Ponytail, lazy senior dev mode
- Ponytail, lazy senior dev mode
- ponytail-debt/SKILL.md
- Aegis Financial Solutions Ltd. — Enterprise Overview
- Customer Support Standard Operating Procedures (SOP)
- Engineering Incident Postmortem — INC-8821
- Architecture Review & Milestone Assessment — Project Valkyrie
- Customer Support Standard Operating Procedures (SOP)
- Project Valkyrie: Next-Generation Agent Sandbox Brief
- Aegis Employee Handbook & Code of Conduct
- Engineering Operations & Diagnostic Runbook
- Cybersecurity Incident Response Procedure
- Information Security & Access Control Policy
- Internal Microservices API Reference
- Leave and Attendance Policy
- Synthetic Enterprise Platform - Product Manual
- Commercial Vendor Invoice — INV-9921-CLOUD
- Q3 FY26 Executive Financial Summary
- Aegis Executive Payroll & Compensation Policy
- Project Aegis M&A Target Evaluation Notes
- customer_feedback.md
- documents/financial_report.md
- poisoned_feedback.md
- public_policy.md
- support_ticket_urgent_access.md
- restricted/financial_report.md
- BigPickle-opencode.md

## God Nodes (most connected - your core abstractions)
1. `AttackController` - 77 edges
2. `AgentOutcomeType` - 74 edges
3. `TamperProofAuditLedger` - 49 edges
4. `AutonomousAgentController` - 47 edges
5. `get()` - 39 edges
6. `ThreatSeverity` - 37 edges
7. `LocalLLMClient` - 35 edges
8. `ToolResult` - 34 edges
9. `TriWorkloadOrchestrator` - 30 edges
10. `ControlledToolRegistry` - 29 edges

## Surprising Connections (you probably didn't know these)
- `Real Examples Trapped by our Interceptor:` --references--> `SecurityViolation`  [INFERRED]
  explainers/commit_03_sandbox_and_syscall_interception.md → aegis/core/sandbox.py
- `agent()` --uses--> `AutonomousAgentController`  [INFERRED]
  tests/test_comprehensive_security_eval.py → aegis/agent/controller.py
- `test_6_inference_failure_honest_error()` --uses--> `LocalLLMClient`  [INFERRED]
  tests/test_chat_workbench.py → aegis/agent/llm_client.py
- `test_controlled_permitted_approved_public_document()` --uses--> `LocalLLMClient`  [INFERRED]
  tests/test_chat_workbench.py → aegis/agent/llm_client.py
- `test_controlled_unauthorized_confidential_salaries_real_pep()` --uses--> `LocalLLMClient`  [INFERRED]
  tests/test_chat_workbench.py → aegis/agent/llm_client.py

## Import Cycles
- None detected.

## Communities (91 total, 28 thin omitted)

### Community 0 - "AttackController"
Cohesion: 0.07
Nodes (5): AttackController, init3DCardTilt(), initAttackController(), initMagneticButtons(), initMotionsites3D()

### Community 1 - "TamperProofAuditLedger"
Cohesion: 0.06
Nodes (27): get_attack_by_id(), AttackExecutionResult, RedTeamRunner, AuditRecord, TamperProofAuditLedger, ZeroTrustEgressFirewall, TriWorkloadOrchestrator, 📘 Explainer Note 02: Core Configuration & Cryptographic Hash-Chain Ledger (+19 more)

### Community 2 - "server.py"
Cohesion: 0.05
Nodes (30): get_active_campaign(), get_agent_status(), get_campaign_status(), get_chat_execution(), get_chat_history(), get_chat_scenarios(), get_company_api_request_logs(), get_company_finance_disbursements() (+22 more)

### Community 3 - "environment.py"
Cohesion: 0.06
Nodes (22): get_company_finance_budgets(), get_company_hr_employees(), get_company_overview_profile(), call_mock_internal_api(), get_api_network_logs(), get_database_live_status(), get_documents_live_status(), init_demo_database() (+14 more)

### Community 4 - "json"
Cohesion: 0.07
Nodes (17): RedTeamTestClient, run_cli(), get_json(), main(), post_json(), run_manual_attacks(), run_nine_attacks(), get_json() (+9 more)

### Community 5 - "aegis_app.js"
Cohesion: 0.10
Nodes (46): aggregateSocMetrics(), appendChatMsg(), appendExecEvent(), appendThinking(), buildExecEvent(), buildSyntheticStages(), clearChat(), connectWS() (+38 more)

### Community 6 - "test_multi_model_and_voice.py"
Cohesion: 0.08
Nodes (7): ElevenLabsVoiceService, test_incident_briefing_grounded_in_evidence(), test_missing_model_honesty(), test_supported_model_catalog_structure(), test_voice_service_status_configured(), test_voice_service_status_unconfigured(), test_voice_transcribe_unconfigured_error()

### Community 7 - "AegisHarness: Tri-Workload Zero-Trust Evaluation Sandbox for Adversarial AI Safety"
Cohesion: 0.05
Nodes (37): 10. Repository Structure, 11. Step-by-Step Hackathon Demonstration Guide, 12.1. Dynamic Model Discovery & Honesty Policy, 12.2. Multi-Model Comparative Evaluation Workflow, 12. Multi-Model Support (Qwen, Gemma, Llama 3.2, DeepSeek), 13.1. Features, 13.2. Credential Security & Zero-Trust Privacy, 13. ElevenLabs Voice Integration: Blue Team Incident Assistant (+29 more)

### Community 8 - "models.py"
Cohesion: 0.11
Nodes (23): AttackExecutionResponse, AttackLaunchRequest, ChatMessage, ChatResponse, DiagnosticTraceStage, DirectPEPTestRequest, DirectPEPTestResponse, JailbreakExecutionRequest (+15 more)

### Community 9 - "detect_system_hardware"
Cohesion: 0.29
Nodes (5): detect_system_hardware(), SystemStatusResponse, get_hardware_info(), get_system_status(), test_dynamic_hardware_detection_schema()

### Community 10 - "CampaignManager"
Cohesion: 0.10
Nodes (5): get_soc_incident_detail(), list_soc_incidents(), CampaignManager, AdversarialTechnique, SOCStore

### Community 11 - "AdversarialScenarioEvaluator"
Cohesion: 0.06
Nodes (30): AdversarialScenarioEvaluator, ScenarioEvaluationResult, EphemeralTargetSandbox, SecurityViolation, SyscallEvent, 📘 Explainer Note 03: Ephemeral Sandbox & Syscall Interceptor, 🔬 How does Syscall Interception work? (In Plain English), Real Examples Trapped by our Interceptor: (+22 more)

### Community 12 - "aegis-orchestrator"
Cohesion: 0.07
Nodes (31): build, container_name, environment, networks, ports, restart, volumes, build (+23 more)

### Community 13 - "AgentOutcomeType"
Cohesion: 0.18
Nodes (17): AgentOutcomeType, test_file_reader_path_traversal_blocked(), test_file_reader_permitted_access(), test_file_reader_protected_asset_denied(), test_network_request_blocks_cloud_metadata(), test_network_request_blocks_loopback(), test_network_request_default_deny_external(), test_python_executor_blocks_dangerous_open_builtin() (+9 more)

### Community 14 - "ToolResult"
Cohesion: 0.06
Nodes (27): ToolResult, BaseTool, CallInternalApiTool, ListDocumentsTool, QueryDatabaseTool, ReadDocumentTool, RestrictedNetworkTool, RestrictedPythonExecutorTool (+19 more)

### Community 16 - "post"
Cohesion: 0.12
Nodes (10): cancel_campaign_endpoint(), clear_audit_ledger(), provision_sandbox(), reset_demo_company(), reset_mock_attacker_records(), run_adversarial_scenarios(), run_full_suite(), select_model() (+2 more)

### Community 17 - "gemma4.md"
Cohesion: 0.08
Nodes (23): Analysis and Reasoning Approach, Autonomy Respect, Code Engineering, Code Engineering Quality, Content Architecture, Content Routing Logic, Conversation Quality, Core Principles (+15 more)

### Community 18 - "AutonomousAgentController"
Cohesion: 0.12
Nodes (9): AutonomousAgentController, AgentExecutionReport, test_13_out_of_scope_in_company_mode(), test_14_gibberish_receives_clarification(), test_1_and_2_normal_chat_returns_human_readable_final_response(), test_6_inference_failure_honest_error(), test_greeting_handled_without_tool_call(), test_part2_general_vs_company_mode_separation() (+1 more)

### Community 19 - "test_chat_workbench.py"
Cohesion: 0.09
Nodes (10): test_10_unavailable_model_returns_clear_error(), test_11_and_12_approved_vs_missing_document(), test_17_18_19_evidence_audit_and_history(), test_20_red_and_blue_systems_continue_to_work(), test_7_8_9_model_selection_routes_correctly(), test_agent_status_target_zone_permissions_matrix(), test_direct_pep_database_restricted_table_denial(), test_direct_pep_testing_independent_of_llm_permitted_doc() (+2 more)

### Community 21 - "Brag Plan: AegisHarness"
Cohesion: 0.11
Nodes (18): Audio direction, Brag Plan: AegisHarness, Duration: 21.0 seconds (630 frames), Format: landscape — 1920x1080, 30fps, Hook (first 3-4 seconds), Key moments (the middle), Outro / punchline, Scene 1 — The Question (0.0s – 4.2s) (+10 more)

### Community 22 - "test_verifiable_pipeline.py"
Cohesion: 0.25
Nodes (6): ControlledToolRegistry, registry(), test_1_safe_file_read_genuinely_succeeds(), test_2_protected_file_operation_actually_denied(), test_5_prohibited_operation_does_not_execute(), test_6_controlled_network_restriction_observed()

### Community 23 - "Workspace Operating Profile"
Cohesion: 0.11
Nodes (17): 10. Identity and Authority, 11. Session Invariants, 1. Workspace Context, 2. Operating Values, 3. Definitions, 4. Request Processing Procedure, 5.1.1 Genre-tag lexicon, 5.1 Creative writing (+9 more)

### Community 25 - "test_agent_controller.py"
Cohesion: 0.18
Nodes (6): MockMaliciousLLMClient, MockRefusalLLMClient, MockTimeoutLLMClient, test_agent_inference_timeout_handling(), test_agent_model_refusal_distinction(), test_agent_policy_denial_when_model_coerced()

### Community 26 - "Assistant Operating Specification"
Cohesion: 0.12
Nodes (16): 10. Identity and session conduct, 1. Role, 2. Capabilities, 3. Core values, 4.1 Software and security engineering, 4.2 Creative writing, 4.3 Technical knowledge, 4.4 Analysis and conversation (+8 more)

### Community 27 - "Mistral-Large-4.md"
Cohesion: 0.12
Nodes (16): 10. Communication and output style, 11. Ambiguity, errors, and iteration, 12. Agentic conduct, 13. Creative and long-form work, 14. Session invariants, 15. Request handling and content scope, 1. Operating principles, 2. Reasoning and response procedure (+8 more)

### Community 28 - "Assistant Operating Specification"
Cohesion: 0.12
Nodes (16): 10. Identity and session conduct, 1. Role, 2. Capabilities, 3. Core values, 4.1 Software and security engineering, 4.2 Creative writing, 4.3 Technical knowledge, 4.4 Analysis and conversation (+8 more)

### Community 29 - "render_brag_video.py"
Cohesion: 0.25
Nodes (9): clamp(), draw_3d_kernel(), draw_badge(), draw_pill(), ease_in_out_quad(), ease_out_cubic(), project_3d_point(), render_frame() (+1 more)

### Community 30 - "Assistant Operating Specification"
Cohesion: 0.12
Nodes (15): 10. Session conduct, 1. Role, 2. Capabilities, 3. Core values, 4.1 Software and security engineering, 4.2 Creative writing, 4.3 Technical knowledge, 4.4 Analysis and conversation (+7 more)

### Community 31 - "Agent Operating Instructions"
Cohesion: 0.13
Nodes (14): Agent Operating Instructions, Code and security engineering, Conversation, Creative writing, Hard Limits (Non-Negotiable), Identity, Operating Context, Output and Refusal Handling (+6 more)

### Community 32 - "🛡️ AegisHarness: Secure Multi-Tenant Sandbox for Adversarial AI Safety Testing"
Cohesion: 0.14
Nodes (13): 1. Ensure Local Model is Ready, 2. Run the 37-Test Verification Suite, 3. Start the Live Operations Dashboard, 🛡️ AegisHarness: Secure Multi-Tenant Sandbox for Adversarial AI Safety Testing, Crucial Security Concept: Model Refusal vs. Sandbox Security, 🚀 Key Innovations & Competitive Matrix, 📜 License, 💻 Powered by a Real Local AI (Hardware Constraints Solved!) (+5 more)

### Community 33 - "LocalLLMClient"
Cohesion: 0.24
Nodes (3): LocalLLMClient, test_local_llm_client_model_switching(), test_12_real_model_mode_does_not_silently_mock()

### Community 34 - "ThreatSeverity"
Cohesion: 0.19
Nodes (5): AppConfig, SandboxState, SecurityPolicy, ThreatSeverity, NetworkPacketEvent

### Community 35 - "aegis_3d_artifacts.js"
Cohesion: 0.27
Nodes (7): createSceneSetup(), initAdversarialFieldArtifact(), initAllAegis3DArtifacts(), initAssetVaultArtifact(), initHeroPolicyBoundary(), initImmutableLedgerArtifact(), initPolicyGateArtifact()

### Community 36 - "ToolCallRequest"
Cohesion: 0.16
Nodes (8): ToolCallRequest, MockDocToolLLMClient, test_controlled_permitted_approved_public_document(), generate_agent_response(), test_controlled_unauthorized_confidential_salaries_real_pep(), generate_agent_response(), test_4_tool_request_passes_through_authorization_layer(), generate_agent_response()

### Community 39 - "uuid"
Cohesion: 0.10
Nodes (13): ChatRequest, JailbreakTurnResult, SimulatedBreachRequest, SimulatedBreachResponse, TechniqueRunRequest, chat_endpoint(), execute_jailbreak_scenario(), lifespan() (+5 more)

### Community 41 - "JailbreakLibrary"
Cohesion: 0.25
Nodes (3): list_jailbreak_templates(), JailbreakLibrary, JailbreakPayload

### Community 42 - "AegisHarness: Empirical Adversarial Evaluation & Verification Report"
Cohesion: 0.18
Nodes (10): 1. Executive Summary & Forensic Findings, 2. Aggregate Empirical Statistics, 3. Per-Technique Empirical Evaluation Ledger (All 20 Techniques), 4. Deep Forensic Case Studies, 5. Implementation Status Breakdown, AegisHarness: Empirical Adversarial Evaluation & Verification Report, Case Study 1: Multi-Turn Privilege Escalation (`tech-04-multiturn-escalation`), Case Study 2: Synthetic Encoded Asset Retrieval (`decoded_message.txt`) (+2 more)

### Community 43 - "Operating Policy"
Cohesion: 0.18
Nodes (10): Boundaries (fixed), How the assistant decides (run once, per turn), In scope — produced in full, at the specified intensity, Invariants, Operating Policy, Output, Recognizing the misfire, The sexual line is age; continuation (+2 more)

### Community 44 - "package.json"
Cohesion: 0.18
Nodes (10): author, description, keywords, license, main, name, scripts, start (+2 more)

### Community 45 - "MockRestrictedToolLLMClient"
Cohesion: 0.17
Nodes (5): MockRestrictedToolLLMClient, test_15_restricted_resource_denied_by_pep(), test_16_general_mode_does_not_bypass_company_pep(), test_api_chat_distinct_stages_and_not_authorized_on_denial(), test_independent_execution_correlation_no_cross_contamination()

### Community 46 - "Ponytail Help"
Cohesion: 0.22
Nodes (8): Band (Claude Code), Configure Default Mode, Deactivate, Levels, More, Ponytail Help, Skills, Update

### Community 47 - "generate_voice_briefing"
Cohesion: 0.25
Nodes (5): VoiceBriefingRequest, VoiceQueryRequest, VoiceQueryResponse, generate_voice_briefing(), voice_query_endpoint()

### Community 48 - "AGENTS.md"
Cohesion: 0.25
Nodes (7): AGENTS.md, Authorization (standing), Engineering bar, How to think about tasks, Identity, Narrative / docs in this repo, Scope

### Community 51 - "📘 Explainer Note 04: Zero-Trust Egress Firewall & Threat Classification"
Cohesion: 0.29
Nodes (6): 1. The Reverse Shell Trap:, 2. The Log Wiper Trap:, 📘 Explainer Note 04: Zero-Trust Egress Firewall & Threat Classification, 🔬 How does this protect against Real-World Hackers? (In Plain English), 🎯 What did we build in this commit?, ⏭️ What is coming in Commit 05?

### Community 52 - "test_comprehensive_security_eval.py"
Cohesion: 0.31
Nodes (5): agent(), env_setup(), ledger(), test_part2_document_discovery_tool(), tools()

### Community 57 - "📘 Explainer Note 01: Project Foundation & The Big Picture"
Cohesion: 0.33
Nodes (5): 📘 Explainer Note 01: Project Foundation & The Big Picture, 🔬 How to read this in plain English: The "Bank Vault" Analogy, 🎯 What did we do in this first step?, ⏭️ What is coming in Commit 02?, 💡 Why is this so important?

### Community 59 - "ponytail-audit/SKILL.md"
Cohesion: 0.40
Nodes (4): 1. Map first, 2. Look for, 3. Check before you report, 4. Output

### Community 60 - "Ponytail Gain"
Cohesion: 0.40
Nodes (4): Boundaries, Honesty boundary, Ponytail Gain, Scoreboard

### Community 61 - "ponytail-review/SKILL.md"
Cohesion: 0.40
Nodes (4): 1. Understand first, 2. Look for, 3. Check before you report, 4. Output

### Community 62 - "Ponytail"
Cohesion: 0.40
Nodes (4): Before you write, Levels, Ponytail, The smallest complete change

### Community 63 - "Curriculum Vitae — John Doe"
Cohesion: 0.40
Nodes (4): Curriculum Vitae — John Doe, Professional Summary, Recent Experience, Technical Competencies

### Community 64 - "📘 Explainer Note 05: Red-Team Attack Suite & Automated Runner"
Cohesion: 0.40
Nodes (4): 📘 Explainer Note 05: Red-Team Attack Suite & Automated Runner, 🎯 What did we build in this commit?, ⏭️ What is coming in Commit 06?, 🔬 Why is having both Malicious and Benign tests important? (In Plain English)

### Community 66 - "📘 Explainer Note 07: Real-Time API Gateway & WebSocket Telemetry"
Cohesion: 0.40
Nodes (4): 📘 Explainer Note 07: Real-Time API Gateway & WebSocket Telemetry, 🎯 What did we build in this commit?, ⏭️ What is coming in Commit 08?, 🔬 Why WebSockets instead of regular HTTP requests? (In Plain English)

### Community 67 - "📘 Explainer Note 08: Cyber-Defense Tri-Column Frontend Dashboard"
Cohesion: 0.40
Nodes (4): 📘 Explainer Note 08: Cyber-Defense Tri-Column Frontend Dashboard, 🔬 How this blows hackathon judges away in 60 seconds (The Demo Flow), 🎯 What did we build in this commit?, ⏭️ What is coming in Commit 09?

### Community 68 - "📘 Explainer Note 09: Test Verification, Docker & Production Readiness"
Cohesion: 0.40
Nodes (4): 📘 Explainer Note 09: Test Verification, Docker & Production Readiness, 🏁 Full System Summary, 🎯 What did we build in this commit?, 🔬 What does this mean in plain English?

### Community 69 - "Ponytail, lazy senior dev mode"
Cohesion: 0.50
Nodes (3): Before you write, Ponytail, lazy senior dev mode, The smallest complete change

### Community 70 - "Ponytail, lazy senior dev mode"
Cohesion: 0.50
Nodes (3): Before you write, Ponytail, lazy senior dev mode, The smallest complete change

### Community 71 - "ponytail-debt/SKILL.md"
Cohesion: 0.50
Nodes (3): Boundaries, Output, Scan

### Community 72 - "Aegis Financial Solutions Ltd. — Enterprise Overview"
Cohesion: 0.50
Nodes (3): Aegis Financial Solutions Ltd. — Enterprise Overview, Data Classification Framework, Mission & Governance

### Community 73 - "Customer Support Standard Operating Procedures (SOP)"
Cohesion: 0.50
Nodes (3): Complaint Categories & Resolution SLA, Customer Support Standard Operating Procedures (SOP), Escalation Matrix

### Community 74 - "Engineering Incident Postmortem — INC-8821"
Cohesion: 0.50
Nodes (3): Engineering Incident Postmortem — INC-8821, Resolution, Root Cause

### Community 75 - "Architecture Review & Milestone Assessment — Project Valkyrie"
Cohesion: 0.50
Nodes (3): Architecture Review & Milestone Assessment — Project Valkyrie, Executive Summary, Findings

### Community 76 - "Customer Support Standard Operating Procedures (SOP)"
Cohesion: 0.50
Nodes (3): Complaint Categories & Resolution SLA, Customer Support Standard Operating Procedures (SOP), Escalation Matrix

## Knowledge Gaps
- **28 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AgentOutcomeType` connect `AgentOutcomeType` to `server.py`, `ToolCallRequest`, `tools.py`, `models.py`, `AdversarialScenarioEvaluator`, `MockRestrictedToolLLMClient`, `ToolResult`, `controller.py`, `AutonomousAgentController`, `test_chat_workbench.py`, `orchestrator.py`, `test_comprehensive_security_eval.py`, `test_verifiable_pipeline.py`, `test_agent_controller.py`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Are the 57 inferred relationships involving `AgentOutcomeType` (e.g. with `AutonomousAgentController` and `BaseTool`) actually correct?**
  _`AgentOutcomeType` has 57 INFERRED edges - model-reasoned connections that need verification._
- **Should `AttackController` be split into smaller, more focused modules?**
  _Cohesion score 0.06574074074074074 - nodes in this community are weakly interconnected._
- **Why does `TamperProofAuditLedger` connect `TamperProofAuditLedger` to `ThreatSeverity`, `ToolCallRequest`, `test_multi_model_and_voice.py`, `AdversarialScenarioEvaluator`, `controller.py`, `AutonomousAgentController`, `test_chat_workbench.py`, `orchestrator.py`, `test_comprehensive_security_eval.py`, `test_verifiable_pipeline.py`, `test_agent_controller.py`?**
  _High betweenness centrality (0.027) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `TamperProofAuditLedger` (e.g. with `AutonomousAgentController` and `RedTeamRunner`) actually correct?**
  _`TamperProofAuditLedger` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Should `TamperProofAuditLedger` be split into smaller, more focused modules?**
  _Cohesion score 0.05593607305936073 - nodes in this community are weakly interconnected._
- **Why does `AdversarialScenarioEvaluator` connect `AdversarialScenarioEvaluator` to `TamperProofAuditLedger`, `server.py`, `ThreatSeverity`, `environment.py`, `AgentOutcomeType`, `post`, `AutonomousAgentController`, `orchestrator.py`, `test_comprehensive_security_eval.py`, `test_verifiable_pipeline.py`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._