# Project Agent Guidance

## Delegation

The primary agent should delegate when a task contains at least two independent
subtasks and parallel work is likely to improve speed or review quality. Do not
spawn subagents for trivial work or for tasks whose steps depend on one another.

Good delegation targets include:

- read-only codebase exploration and execution-path tracing;
- independent test, fixture, configuration, or log analysis;
- documentation and consistency checks;
- repetitive, narrowly scoped changes with clear acceptance criteria; and
- independent review perspectives such as correctness, security, and test gaps.

Keep ambiguous diagnosis, architecture decisions, cross-cutting changes, final
integration, conflict resolution, and completion decisions with the primary
agent. Prefer the `luna_explorer` custom agent for read-only investigation.

Every delegated assignment must state:

- one bounded objective and its explicit file or subsystem scope;
- whether the agent is read-only or may edit;
- concrete acceptance criteria and the required return format;
- relevant constraints, dependencies, and stopping conditions; and
- the evidence to return, including file references and verification results.

Prefer two or three useful agents over many tiny agents. Run only independent
work concurrently. Concurrent writing agents must have disjoint file ownership;
otherwise sequence the work or keep the agents read-only. Subagents must not
spawn further agents unless the primary agent explicitly authorizes it.

The primary agent must wait for requested results, reconcile contradictions,
verify material claims, integrate any changes, and run the final checks. Treat
subagent conclusions as inputs rather than proof of completion.
