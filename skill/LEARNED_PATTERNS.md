# Learned patterns

Attack classes picked up from threat-intel reports, each turned into a question to ask during an audit. Entries are proposed by the intel loop (see `INTEL.md`) and merged by a human. Newest first.

| Added | Pattern | Hunt question | Source |
|---|---|---|---|
| 2026-10-27 | Files planted where a coding agent will read them (a Downloads folder, a repo file, an issue) carry instructions that try to make the agent install software. | Does any agent in this project read files or text it did not author, and can that text cause a command, install or network call without a human approving it? | [The Hacker News](https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html) |
| 2026-10-27 | Stolen CI tokens are used to pull secrets back out of CI run output. | Can any token this project issues read CI run output, and does that output ever print a secret, an environment dump or a debug trace? | [The Hacker News](https://thehackernews.com/2026/10/gheist-uses-stolen-github-tokens-to.html) |
| 2026-10-27 | A server's default request-size limit still lets one request exhaust memory. | Where does this service parse a request body, and is there an explicit size and depth limit before parsing, not just the framework default? | [OSV GHSA-46jr-4wx8-v453](https://osv.dev/vulnerability/GHSA-46jr-4wx8-v453) |
