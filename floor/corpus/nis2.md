# NIS2 breach-notification corpus

Directive (EU) 2022/2555 of the European Parliament and of the Council of 14
December 2022 on measures for a high common level of cybersecurity across the
Union (the NIS2 Directive). Article 23 is the significant-incident reporting duty
the Deadline Room grounds the NIS2 early-warning and full-notification filings
against. Text reproduced verbatim from the official text on EUR-Lex (CELEX
32022L2555), normalized only by removing em/en dashes per this repository's
hygiene rule (none were present in the reproduced paragraphs).

Chunk markers are HTML comments that open with the literal "chunk:" keyword and
carry three pipe-separated fields (the stable id, the formal citation, and a short
title). The markers themselves begin below.

<!-- chunk: NIS2-Art23(1) | NIS2 Article 23(1) | Duty to notify significant incidents -->
1. Each Member State shall ensure that essential and important entities notify,
without undue delay, its CSIRT or, where applicable, its competent authority in
accordance with paragraph 4 of any incident that has a significant impact on the
provision of their services as referred to in paragraph 3 (significant incident).
Where appropriate, entities concerned shall notify, without undue delay, the
recipients of their services of significant incidents that are likely to adversely
affect the provision of those services. Each Member State shall ensure that those
entities report, among other things, any information enabling the CSIRT or, where
applicable, the competent authority to determine any cross-border impact of the
incident. The mere act of notification shall not subject the notifying entity to
increased liability.

<!-- chunk: NIS2-Art23(3) | NIS2 Article 23(3) | When an incident is significant -->
3. An incident shall be considered to be significant if:

(a) it has caused or is capable of causing severe operational disruption of the
services or financial loss for the entity concerned;

(b) it has affected or is capable of affecting other natural or legal persons by
causing considerable material or non-material damage.

<!-- chunk: NIS2-Art23(4) | NIS2 Article 23(4) | Notification stages and deadlines -->
4. Member States shall ensure that, for the purpose of notification under
paragraph 1, the entities concerned submit to the CSIRT or, where applicable, the
competent authority:

(a) without undue delay and in any event within 24 hours of becoming aware of the
significant incident, an early warning, which, where applicable, shall indicate
whether the significant incident is suspected of being caused by unlawful or
malicious acts or could have a cross-border impact;

(b) without undue delay and in any event within 72 hours of becoming aware of the
significant incident, an incident notification, which, where applicable, shall
update the information referred to in point (a) and indicate an initial assessment
of the significant incident, including its severity and impact, as well as, where
available, the indicators of compromise;

(c) upon the request of a CSIRT or, where applicable, a competent authority, an
intermediate report on relevant status updates;

(d) a final report not later than one month after the submission of the incident
notification under point (b), including the following:

(i) a detailed description of the incident, including its severity and impact;

(ii) the type of threat or root cause that is likely to have triggered the
incident;

(iii) applied and ongoing mitigation measures;

(iv) where applicable, the cross-border impact of the incident;

(e) in the event of an ongoing incident at the time of the submission of the final
report referred to in point (d), Member States shall ensure that entities
concerned provide a progress report at that time and a final report within one
month of their handling of the incident.

<!-- chunk: NIS2-Recital-101 | NIS2 Recital 101 | Purpose of the reporting timeline -->
Summary (not verbatim): NIS2 Recital 101 explains that a graduated reporting
timeline (an early warning within 24 hours, a fuller incident notification within
72 hours, and a final report within one month) balances the need for rapid
information to enable the CSIRT or competent authority to react and limit the
incident's spread against the reporting burden on the entity while it is still
responding. The early warning is deliberately light so it can be submitted fast;
the 72-hour notification carries the initial severity and impact assessment and any
indicators of compromise. The exact recital wording is on EUR-Lex (CELEX
32022L2555); this chunk is labelled a summary because the precise recital text is
not reproduced here.
