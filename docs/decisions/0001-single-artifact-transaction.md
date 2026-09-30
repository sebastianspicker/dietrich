# 0001: One artifact transaction owns publication

Status: accepted

Every format writer produces an unpublished candidate. The make-editable
application service validates optional post-processing, then hands one final
publication to `ArtifactTransaction`.

Previously each handler published on its own and re-signing ran afterward, so a
signing failure could report overall failure after an unsigned output had already
appeared. Centralizing publication also gives decrypted output one mode policy
and one cleanup contract, without adding a generic repository, adapter hierarchy,
or unit-of-work framework.
