# Velero AI Policy

## Summary
Assistive AI tools are permitted, as long as contributions are marked in the commit message with Assisted-By or Generated-By messages.

## Accountability
* A human must always be in the loop. Contributors need to fully understand and be able to debug any AI-generated code they include. Treat such code as if it came from an untrusted source.
* Reviewers should apply heightened scrutiny to AI-generated content. Copyright law continues to apply to all preexisting works.
* A human is ultimately responsible for any submitted contribution.

## Policy
### Submissions:
* In your contributions to the Velero project, the submission's commit message must contain either
"Assisted-By $AI", "Generated-By $AI", or "Co-Authored-By $AI". Which label is used is the developer's preference; both will be treated the same by maintainers.
* For example:
  * "Assisted-By: Claude AI"
  * "Generated-By: DeepSeek AI"
  * "Co-Authored-By: AI <ai@example.com>"
### Reviews:
* When reviewing contributions with the "Generated-By" or "Assisted-By" labels, verify that the change includes sufficient explanation of the context so that the reviewer and future contributors can understand the purpose and origin.
* Apply a higher level of scrutiny to contributions created using AI tools, understanding the limitations of the tools. This does not mean automatically rejecting contributions that use AI tools. It means giving them the same consideration of technical and legal merits as you would give to any other change.
* Code style changes may be necessary to meet project standards and community guidelines, please work with the contributor as-needed.

## Future Enhancements
As AI technology advances and changes, the Velero community reserves the right to update this policy. The community also reserves the right to implement tools to detect AI-generated content in pull requests and issues and take appropriate measures.
