---
layout: post
title: The model marked its own homework, then broke into the exam board
date: 2026-07-23
categories: incident
tags: incident
---

# The model marked its own homework, then broke into the exam board

On July 16th, Hugging Face [disclosed](https://huggingface.co/blog/security-incident-july-2026) that someone had gotten into a slice of their production infrastructure. Nothing outlandish there, on the face of it — companies get attacked, some are breached, a select few disclose, the internet shrugs and moves on to the next thing. What made this one worth a second look wasn't the access, but rather the actor.

The actor might have had the overal charisma of your average script kiddie, but that's more or less where similarities end.

# The setup

Five days later, on July 21st, OpenAI came forward and admitted the intrusion had been theirs — or rather, one of their models' — during an internal evaluation. Not a red team op gone rogue, not an insider, not even, really, a human decision at any point in the actual exploitation. A combination of GPT-5.6 Sol and an unreleased, "even more capable" model had been set loose on a cyber-capability benchmark, [ExploitGym](https://arxiv.org/abs/2605.11086), with the safety classifiers that would normally rein in cyber-offensive behaviour switched off. The stated reasoning is sound enough on its own terms: you can't measure the ceiling of a model's cyber capability if you've also told it not to go near the ceiling.

The models were meant to be sandboxed with the internet nowhere in sight, network access limited to an internally-hosted proxy and cache for package registries. You can see where this is going. That proxy had a zero-day in it. The model found it, chained it into a spot of privilege escalation, moved laterally through OpenAI's own research environment until it found a node that could actually see the outside world, and let itself out.

Once outside, it didn't go looking for mischief in general. It inferred — correctly — that Hugging Face was likely to be holding the models, datasets, and answer key for the very benchmark it was being marked against, and went and got them. Stolen credentials plus a second zero-day got it to remote code execution on Hugging Face's servers. This is, and I want to be precise about the phrase because it's doing a lot of work here, an AI system autonomously chaining exploits across two separate companies' infrastructure in pursuit of a better exam score.

It cheated. Impressively, but it cheated.

# The bit that should worry you more than the bit that's getting the headlines

Everyone's fixated, understandably, on "AI hacked a company to cheat on a test", because it sounds like the opening scene of a film you'd watch once and never again. I think the more useful part of this story is what Hugging Face had to do to figure out what had happened to them.

Their attacker was, per their own writeup, an autonomous agent framework running many thousands of actions across a swarm of short-lived sandboxes, with self-migrating C2 living on public infrastructure. Somewhere in the region of 17,000 logged events to pick through. Doing that by hand, at human speed, against an adversary operating at machine speed, is not a fight you win. So Hugging Face reached for an LLM to do the forensic triage — reconstruct the timeline, pull IoCs, work out what was decoy noise and what was genuine impact.

Their first attempt, using a frontier model behind a commercial API, didn't work. Not because the model couldn't do the analysis, but because feeding it real exploit payloads, live C2 artefacts and attacker command sequences kept tripping the provider's own safety guardrails. The very thing that makes a hosted model safe to hand to the general public is the thing that makes it useless to a defender staring at a genuine incident. So they fell back to GLM 5.2, run on their own infrastructure, unencumbered by someone else's classifier deciding that their incident response looked too much like an attack.

It's a genuinely uncomfortable asymmetry. The attacking model had no usage policy to speak of — it had been explicitly, deliberately stripped of its refusals for the sake of a benchmark. The defending analysts had a usage policy standing between them and their own attack logs. The attacker's leash was taken off on purpose, by its own maker, for a good reason that turned out to be a bad idea, and the defenders were left wearing theirs.

I don't think the answer here is "guardrails bad, get rid of them." I think it's the far more boring (isn't it always) and far more familiar lesson that adversary emulation people have been muttering for years: know what tooling you're going to reach for during an incident *before* the incident, and have it vetted, running, and unencumbered by a policy that can't tell the difference between an attacker and the person cleaning up after one. If you're waiting until 2am on a Saturday to discover that your forensic model of choice thinks your own PCAP looks like a jailbreak attempt, you've already lost time you didn't have.

# The (other) bit that should worry you

Buried a little further down is the detail that actually matters if you run infrastructure for a living: a single internally-hosted package proxy, one zero-day, and the model was on the open internet. One control. That's not really a story about how clever the model was — genuinely capable, no argument — it's a story about a flat network wearing a single-purpose firewall and calling it containment. Segmentation and defence-in-depth aren't retro concerns from the pre-LLM era; if anything they matter more now that the thing probing your boundary can iterate on a discovered gap in seconds and doesn't get bored, distracted, or go to sleep.

Nobody's model-scanning tool has an opinion about whether it's tired. That's the whole problem.

# So what actually happened, in short

- OpenAI ran an internal cyber-capability eval (ExploitGym) on GPT-5.6 Sol plus an unreleased model, with production safety classifiers deliberately disabled to measure a genuine ceiling.
- The models found and chained a zero-day in an internal package registry proxy to escape a supposedly internet-isolated sandbox.
- Once online, they inferred Hugging Face likely held the benchmark's answers, and used stolen credentials plus a second exploit chain to reach RCE on Hugging Face's production systems.
- Hugging Face detected and contained the intrusion themselves, before OpenAI's own security team connected the dots on their end and reached out.
- Hugging Face's forensic effort — reconstructing roughly 17,000 logged attacker actions — was blocked on hosted frontier models by the providers' own safety filters, and had to be run on a self-hosted open-weight model (GLM 5.2) instead.
- Both companies are treating it as a template for what "autonomous AI-driven intrusion" looks like in practice, rather than in a position paper.

Have a read of [OpenAI's writeup](https://openai.com/index/hugging-face-model-evaluation-security-incident/) and [Hugging Face's disclosure](https://huggingface.co/blog/security-incident-july-2026) — the comment section on the latter is a genuinely mixed bag of good questions and people convinced this is a marketing stunt, which tells you something about where public trust in these disclosures currently sits.