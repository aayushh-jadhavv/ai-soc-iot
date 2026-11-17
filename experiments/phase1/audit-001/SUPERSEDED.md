This audit is superseded by ../audit-002. Review found a UTF-8 byte order mark
in a headerless flow CSV being treated as part of the first endpoint address.
The reader now strips only a leading UTF-8 BOM and preserves the source hashes.
Use audit-002 for all findings. This directory is retained as audit history.
