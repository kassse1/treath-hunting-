# Week 4 defense

Prepared for Danial Rahman, CS-2421. Use this as a group script and divide sections between speakers. About 7–8 minutes including the demonstration at a measured pace. Rehearse with a timer; shorten explanations if necessary. Read the report and run the script before presenting its result as your own work.

## Opening and project topic 0 to 1 minute

Hello. Our project topic is Detecting Spearphishing Attacks in Corporate Networks. We chose this topic because a targeted email can become the starting point of a larger intrusion. A defender needs to understand what happened after the email arrived and which records can help explain it.

For Week 4, the syllabus asks us to analyze a real cyberattack using the Cyber Kill Chain and map its stages to MITRE ATT&CK. Our selected case is the RSA attack from 2011. The weekly increment includes a written analysis, an attack diagram, a mapping table and a small Python demonstration. The demonstration uses synthetic data, and we clearly separate it from the historical incident.

Our main question is this: how can we connect a suspicious attachment with later endpoint and network activity?

## Case and frameworks 1 to 2 minutes

The RSA case began with a recruitment themed email and an Excel attachment. The attachment exploited a vulnerability in Adobe Flash. The vulnerability is identified as CVE-2011-0609. A PoisonIvy backdoor gave the attacker remote access. Public descriptions report that information related to RSA SecurID was stolen. The sources for this summary are listed in our report, including AhnLab, Qualys and Microsoft.

The Cyber Kill Chain gives us seven stages for organizing the intrusion. MITRE ATT&CK gives us names and identifiers for more specific attacker behaviors. These frameworks answer different questions. The Kill Chain helps explain the attack sequence. ATT&CK helps describe how an attacker performs an action.

A tactic is the attacker's goal. A technique is a way to achieve that goal. A procedure is the exact implementation in a particular incident. This distinction matters when evidence is incomplete.

## Walk through the diagram 2 to 4 minutes

Please look at our diagram. The first stage is reconnaissance. The attackers selected employees to receive the message. We infer that they needed employee email addresses, but our sources do not establish how they collected those addresses. We label that part as an inference.

The second stage is weaponization. The attachment combined a spreadsheet with an exploit. We can describe what the delivered file contained, but we cannot reconstruct every preparation step or say who developed the exploit.

The third stage is delivery. The malicious file reached the target through email. This is the clearest connection to our project topic. It shows why email records and attachment metadata should be included in an investigation.

The fourth stage is exploitation. Opening the document led to exploitation of the Flash vulnerability. User execution and vulnerability exploitation are separate behaviors, even though they are closely connected in this example.

The fifth stage is installation. Public reporting describes the installation of a PoisonIvy backdoor. However, installation does not automatically prove that a specific persistence method was used. We would need file, registry or service evidence to establish that detail.

The sixth stage is command and control. The compromised endpoint connected outward to attacker infrastructure. For a defender, an outbound connection becomes more useful when we know which process created it and what happened on that endpoint beforehand.

The last stage is actions on objectives. In this case, information related to SecurID was stolen. The initial email was one part of a longer intrusion. Our diagram helps connect the entry point with the final objective.

## Explain the mapping 4 to 5 minutes

The delivery stage maps to T1566.001, Spearphishing Attachment. The file opening maps to T1204.002, Malicious File. The exploitation behavior maps to T1203, Exploitation for Client Execution. These mappings follow the reported actions and the MITRE definitions.

Other rows need more caution. MITRE documents registry persistence and encrypted communications as PoisonIvy capabilities. We include them as related mappings, with explicit labels. A software capability does not prove that it appeared in the RSA incident.

The same limitation applies to collection. We do not have the original records needed to identify the exact collection location or exfiltration method. Our table preserves that uncertainty. Filling every row with a confident technique identifier would make the analysis less reliable.

## Show the practical increment 5 to 6 and a half minutes

Now we will show the local demonstration. The dataset contains seven invented events across two endpoints. It includes email delivery, file opening, process creation and network activity. The hostnames, times and IP addresses are teaching examples.

Run `python3 scripts/analyze_events.py` and show the output.

The script looks for an external attachment, opening of that same file, an Excel child process and an outbound connection attributed to that child process. It correlates the events on the same host within ten minutes. DEMO-PC-01 is flagged for review. DEMO-PC-02 is not flagged because it does not have the required sequence.

This result demonstrates our hypothesis on a small controlled dataset. It does not prove malware, exploitation or data theft. The rule could miss attacks that behave differently. It could also connect unrelated events or flag legitimate automation. Real evaluation would need more data and stronger identifiers.

## Result and next step 6 and a half to 7 and a half minutes

Our Week 4 increment turns a public attack description into a structured investigation example. The completed files include the report, diagram, technique mappings, dataset, script and recorded console output. The repository package includes a README with instructions for running the example and committing the work.

The main defensive proposal is to connect email records with endpoint and network telemetry. A suspicious attachment alone gives limited context. Later process activity and outbound connections help identify what should be investigated next.

For the next increment, we can collect authorized lab telemetry, add normal document workflows and evaluate false positives and missed cases. Our current result is a starting point for that work. Thank you.

## Short answers for questions

- Why this incident? It connects targeted email, exploitation, remote access and information theft.
- Did you run PoisonIvy? No. The script only reads a local CSV dataset.
- Are these RSA logs? No. They are explicitly synthetic teaching records.
- Why are some mappings uncertain? Public sources do not prove every implementation detail.
- Does a review alert prove compromise? No. An analyst must investigate the records.
- What did Week 4 add? The case analysis, mapping, diagram and runnable correlation example.
- What is the difference between the frameworks? Kill Chain organizes stages; ATT&CK describes behaviors.
- Has this been pushed to GitHub? Check the actual repository before answering. The prepared package itself does not prove publication.
