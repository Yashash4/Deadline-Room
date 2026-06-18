# DORA breach-notification corpus

Regulation (EU) 2022/2554 of the European Parliament and of the Council of 14
December 2022 on digital operational resilience for the financial sector (the
DORA Regulation), with the major-incident classification criteria in Commission
Delegated Regulation (EU) 2024/1772 (the RTS). Article 19 is the major
ICT-related incident reporting duty the Deadline Room grounds the DORA filing
against. Text reproduced verbatim from the official text on EUR-Lex (CELEX
32022R2554 and 32024R1772), normalized only by removing em/en dashes per this
repository's hygiene rule (none were present in the reproduced paragraphs).

Chunk markers are HTML comments that open with the literal "chunk:" keyword and
carry three pipe-separated fields (the stable id, the formal citation, and a short
title). The markers themselves begin below.

<!-- chunk: DORA-2022/2554-Art19(1) | DORA Regulation (EU) 2022/2554 Article 19(1) | Reporting of major ICT-related incidents -->
1. Financial entities shall report major ICT-related incidents to the relevant
competent authority as referred to in Article 46 in accordance with paragraph 4 of
this Article.

Where a financial entity is subject to supervision by more than one national
competent authority referred to in Article 46, Member States shall designate a
single competent authority as the relevant competent authority responsible for
carrying out the functions and duties provided for in this Article.

Credit institutions classified as significant, in accordance with Article 6(4) of
Regulation (EU) No 1024/2013, shall report major ICT-related incidents to the
relevant national competent authority designated in accordance with Article 4 of
Directive 2013/36/EU, which shall immediately transmit that report to the ECB.

<!-- chunk: DORA-2022/2554-Art19(3) | DORA Regulation (EU) 2022/2554 Article 19(3) | Notifications and reports to the competent authority -->
3. Where a major ICT-related incident occurs and has an impact on the financial
interests of clients, financial entities shall, without undue delay as soon as
they become aware of it, inform their clients about the major ICT-related incident
and about the measures that have been taken to mitigate the adverse effects of
such incident.

In the case of a significant cyber threat, financial entities shall, where
applicable, inform their clients that are potentially affected of any appropriate
protection measures which the latter may consider taking.

<!-- chunk: DORA-2022/2554-Art19(4) | DORA Regulation (EU) 2022/2554 Article 19(4) | Initial, intermediate, and final reports -->
4. Financial entities shall submit to the relevant competent authority referred to
in Article 46:

(a) an initial notification;

(b) an intermediate report after the initial notification referred to in point
(a), as soon as the status of the original incident has changed significantly or
the handling of the major ICT-related incident has changed based on new
information available, followed, as appropriate, by updated notifications every
time a relevant status update is available, as well as upon a specific request of
the competent authority;

(c) a final report, when the root cause analysis has been completed, regardless of
whether mitigation measures have already been implemented, and when the actual
impact figures are available to replace estimates.

<!-- chunk: DORA-RTS-2024/1772-Art1 | Commission Delegated Regulation (EU) 2024/1772 Article 1 | Materiality thresholds for classification of major incidents -->
Summary (not verbatim): Commission Delegated Regulation (EU) 2024/1772 (the RTS
adopted under DORA Article 18(3)) classifies an ICT-related incident as MAJOR when
it meets the materiality thresholds across a set of classification criteria. The
criteria are: clients, financial counterparts and transactions affected; the
reputational impact; the duration and service downtime; the geographical spread,
in particular across the territories of two or more Member States; the data losses
the incident entails, in respect of availability, authenticity, integrity, or
confidentiality of data; the criticality of services affected, including the
financial entity's transactions and operations; and the economic impact, both
direct and indirect, in absolute and relative terms. An incident is major when it
affects critical services and meets either the threshold on clients/counterparts/
transactions together with the data-losses threshold, or two or more of the other
criteria. The precise per-criterion numeric thresholds are set out in the RTS
articles on EUR-Lex (CELEX 32024R1772); this chunk is labelled a summary because
those exact numeric thresholds are not reproduced verbatim here.

<!-- chunk: DORA-RTS-2024/1772-Art19 | Commission Delegated Regulation (EU) 2024/1772 (reporting time limits, read with DORA Art 19) | Time limits for the initial notification and reports -->
Summary (not verbatim): the reporting time limits for a major ICT-related incident
are set by Commission Delegated Regulation (EU) 2024/1772 read with the reporting
implementing standards adopted under DORA Article 20. In outline, the initial
notification is due as early as possible and within the time limit set by the
standards once the incident is classified as major; an intermediate report follows
within the time limit set after the initial notification or when the status
changes significantly; and a final report follows within one month of the
intermediate report, once the root-cause analysis is complete and actual impact
figures are available. The Deadline Room models the initial-notification window as
a 72-hour clock from incident occurrence. The exact hour figures are in the
delegated and implementing regulations on EUR-Lex; this chunk is labelled a summary
because those precise figures are not reproduced verbatim here.
