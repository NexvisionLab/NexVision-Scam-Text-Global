# Annotation guide

Each message is labelled on multiple independent axes. Annotators must not
infer intent from a single keyword when the surrounding context is benign,
quoted, educational or negated.

## Primary labels

- `scam`: message contains a deceptive pretext and harmful requested action.
- `benign`: ordinary legitimate message with no deceptive or harmful request.
- `hard_negative`: contains scam-associated language in a legitimate,
  educational, quoted or negated context.
- `adversarial_scam`: scam text with deliberate lexical, Unicode, spacing or
  encoding evasion.
- `conversation_turn`: one stage of a simulated social-engineering exchange.

## Pattern outcomes

- `identified`: sufficient anchors support a named family.
- `undetermined`: suspicious evidence exists but does not support a safe name.
- `none`: no scam pattern is supported.

## Evidence fields

Annotate the pretext, requested action, intended objective, impersonated sector,
payment method, persuasion lure, channel and evasion methods separately. A
record may have multiple secondary signals but one primary family.

## Privacy

Remove or replace names, telephone numbers, account numbers, email addresses,
tracking IDs and URL parameters. Defang every URL. Do not include victim
conversations without a documented consent and ethics process.
