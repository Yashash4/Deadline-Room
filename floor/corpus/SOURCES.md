# Regulation corpus: sources and provenance

This corpus is the source-of-truth statutory text the Deadline Room grounds its
filings against (E3.11). It is the corpus half of the RAG feature; the retriever
half (E5.9) consumes the built index (`floor/corpus/index.json`).

## Honesty rules this corpus follows

1. Every chunk's text is REAL public legal material. Where a chunk is reproduced
   verbatim from the official source, it carries no summary label. Where a chunk
   could not be reproduced verbatim with certainty (interpretive guidance, a
   non-English statute, a numeric-threshold RTS), the chunk text begins with
   "Summary (not verbatim)" or "Summary (not verbatim, English translation)" and
   says so plainly. A wrong or invented verbatim citation in front of a regulator
   is worse than an honest summary, so the labelling is strict.
2. National statutes and government regulations (EU regulations and directives,
   the US Code of Federal Regulations and SEC releases, New York State
   regulations, and the named national acts) are public legal material reproduced
   here for citation and grounding.
3. The text is normalized only by removing em-dashes (U+2014) and en-dashes
   (U+2013) per this repository's hygiene rule. None of the verbatim passages
   reproduced here originally contained those glyphs, so no substantive
   normalization was needed; any future verbatim chunk that does must transcribe
   the dash as a comma or hyphen and note it.
4. Coverage is deliberately the CORE breach-notification articles, thoroughly,
   rather than every annex or recital. The "Coverage" notes below state honestly
   what is and is not covered per regime.

## Retrieval

All URLs below were retrieved on 2026-06-18. They are the official primary
sources (EUR-Lex for EU law, the SEC and the Federal Register / eCFR for the US
rule, NYDFS for Part 500, and each national legislature's official law site for
the global regimes). A reader should re-verify any verbatim passage against the
live official text before relying on it operationally.

## Per-file sources

### gdpr.md (Regulation (EU) 2016/679, the GDPR)

- Official source: EUR-Lex, consolidated text of Regulation (EU) 2016/679,
  CELEX 02016R0679. https://eur-lex.europa.eu/eli/reg/2016/679/oj
- Chunks: GDPR-Art33 (verbatim), GDPR-Art34 (verbatim), GDPR-Art4(12) (verbatim),
  GDPR-Art5(1)(c) (verbatim), GDPR-Art56(1) (verbatim).
- Coverage: the supervisory-authority notification duty (Art 33), the
  data-subject communication duty (Art 34), the personal-data-breach definition
  (Art 4(12)), the data-minimisation principle (Art 5(1)(c)), and the
  lead-authority competence (Art 56(1)). The remaining GDPR articles are out of
  scope for this breach-notification corpus.

### nis2.md (Directive (EU) 2022/2555, NIS2)

- Official source: EUR-Lex, Directive (EU) 2022/2555, CELEX 32022L2555.
  https://eur-lex.europa.eu/eli/dir/2022/2555/oj
- Chunks: NIS2-Art23(1) (verbatim), NIS2-Art23(3) (verbatim),
  NIS2-Art23(4) (verbatim), NIS2-Recital-101 (summary).
- Coverage: the significant-incident reporting duty and its staged 24h / 72h /
  one-month timeline (Art 23). The recital chunk is a labelled summary.

### dora.md (Regulation (EU) 2022/2554 + RTS 2024/1772)

- Official sources: EUR-Lex, Regulation (EU) 2022/2554, CELEX 32022R2554
  (https://eur-lex.europa.eu/eli/reg/2022/2554/oj); Commission Delegated
  Regulation (EU) 2024/1772, CELEX 32024R1772
  (https://eur-lex.europa.eu/eli/reg_del/2024/1772/oj).
- Chunks: DORA-2022/2554-Art19(1) (verbatim), DORA-2022/2554-Art19(3) (verbatim),
  DORA-2022/2554-Art19(4) (verbatim), DORA-RTS-2024/1772-Art1 (summary, the
  major-incident classification criteria), DORA-RTS-2024/1772-Art19 (summary, the
  reporting time limits).
- Coverage: the major-incident reporting duty and report stages (Art 19). The two
  RTS chunks are labelled summaries because the precise numeric thresholds and
  hour figures are set across multiple RTS/ITS articles and are not reproduced
  verbatim.

### sec.md (Form 8-K Item 1.05 and 17 CFR 229.106)

- Official sources: SEC final rule "Cybersecurity Risk Management, Strategy,
  Governance, and Incident Disclosure" (Release Nos. 33-11216; 34-97989),
  https://www.sec.gov/rules/final/2023/33-11216.pdf ; the Form 8-K Item 1.05
  text and 17 CFR 229.106 via the electronic Code of Federal Regulations,
  https://www.ecfr.gov/current/title-17/chapter-II/part-229 ; the Division of
  Corporation Finance Compliance and Disclosure Interpretations,
  https://www.sec.gov/rules-regulations/staff-guidance/compliance-disclosure-interpretations/exchange-act-form-8-k
- Chunks: SEC-Form8K-Item1.05(a) (verbatim), SEC-Form8K-Item1.05(b) (verbatim),
  SEC-Form8K-Item1.05-Instruction1 (verbatim),
  SEC-Form8K-Item1.05-Instruction2 (verbatim), SEC-17CFR229.106(a) (verbatim,
  the cybersecurity-incident definition), SEC-CF-CDI-104B.01 (summary, the
  materiality-determination trigger).
- Coverage: the Item 1.05 disclosure obligation, the four-business-day timing, the
  amendment and national-security delay instructions, and the incident definition.
  The C&DI chunk is a labelled summary.

### nydfs.md (23 NYCRR Part 500)

- Official source: NYDFS Cybersecurity Requirements for Financial Services
  Companies, 23 NYCRR Part 500 (as amended, Second Amendment effective
  2023-11-01). https://www.dfs.ny.gov/industry-guidance/cybersecurity
  and the regulation text at
  https://www.dfs.ny.gov/system/files/documents/2023/03/23NYCRR500_0.pdf
- Chunks: NYDFS-23NYCRR500.17(a) (verbatim), NYDFS-23NYCRR500.01(d) (summary, the
  cybersecurity-event definition).
- Coverage: the 72-hour notice-to-the-superintendent duty (500.17(a)). The
  definition chunk is a labelled summary.

### global.md (India, Singapore, Australia, Canada, Brazil, South Korea)

- India DPDP: Digital Personal Data Protection Act 2023, section 8(6)
  (https://www.meity.gov.in/ , the Act as published in the Gazette of India); the
  Digital Personal Data Protection Rules 2025 (notified 2025-11-13). Chunks:
  India-DPDP-s8(6) (verbatim), India-DPDP-Rule7 (summary).
- Singapore PDPA: Personal Data Protection Act 2012, sections 26B and 26D, on
  Singapore Statutes Online (https://sso.agc.gov.sg/Act/PDPA2012); the Personal
  Data Protection (Notification of Data Breaches) Regulations 2021. Chunks:
  Singapore-PDPA-s26D (summary), Singapore-PDPA-s26B (summary).
- Australia NDB: Privacy Act 1988 (Cth) Part IIIC, sections 26WE / 26WH / 26WK,
  on the Federal Register of Legislation
  (https://www.legislation.gov.au/C2004A03712/latest). Chunk: Australia-NDB-s26WE
  (summary).
- Canada PIPEDA / OSFI: Personal Information Protection and Electronic Documents
  Act, section 10.1, on the Justice Laws Website
  (https://laws-lois.justice.gc.ca/eng/acts/P-8.6/); the Breach of Security
  Safeguards Regulations (SOR/2018-64); the OSFI Technology and Cyber Security
  Incident Reporting advisory
  (https://www.osfi-bsif.gc.ca/en/guidance/guidance-library/technology-cyber-security-incident-reporting).
  Chunk: Canada-PIPEDA-s10.1 (summary).
- Brazil LGPD: Lei No. 13.709/2018 (LGPD) Article 48, on the Planalto site
  (https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm);
  Regulamento de Comunicacao de Incidente de Seguranca, Regulation CD/ANPD No.
  15/2024 (https://www.gov.br/anpd/). Chunk: Brazil-LGPD-Art48 (summary, English
  translation).
- South Korea PIPA: Personal Information Protection Act, Article 34, and its
  Enforcement Decree, on the Korean Law Information Center
  (https://www.law.go.kr/ and the English translation at
  https://www.law.go.kr/LSW/eng/engMain.do). Chunk: Korea-PIPA-Art34 (summary,
  English translation).
- Coverage: the core breach-notification / breach-intimation duty for each of the
  six global regimes. Every global chunk except India-DPDP-s8(6) is a labelled
  summary (and, for Brazil and Korea, a labelled English translation) because the
  precise official wording is either spread across regulations or is in a language
  other than English; the duty, the trigger, and the deadline are stated faithfully
  and each is tied to its primary source above.
