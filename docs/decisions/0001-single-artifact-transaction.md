# 0001: One artifact transaction owns publication

Status: accepted

Every format writer produces an unpublished candidate. The make-editable application service
validates optional post-processing and delegates one final publication to `ArtifactTransaction`.

Previously, each handler published independently and re-signing happened afterward. A signing
failure could therefore report overall failure after an unsigned output had already appeared.
Centralizing publication also gives decrypted output one private mode policy and one cleanup
contract without adding a generic repository, adapter hierarchy, or unit-of-work framework.
