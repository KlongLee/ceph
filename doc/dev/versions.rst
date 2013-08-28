==============
Public OSD Version
==============
At present, there is one main version, maintained on-disk as
pg_log.head and in-memory as OpContext::at_version.
Clients see this version in one of two ways:
1) The long-standing MOSDOpReply::reassert_version,
2) the much newer objclass API function get_current_version().

The semantics on both of these are not quite as you'd expect.

reassert_version is usually set by looking at the
OpContext::reply_version. reply_version is left at zero on successful
read operations. On any operation returning ENOENT, reassert_version
is instead set from the pg_info_t::last_update value. On successful
write operations, reply_version is set equal to
object_info_t::user_version. (On replays, reassert_version is set
directly from the PG log entry's version.)

The user_version semantics are: for a non-watch write, update
user_version to the value of OpContext::version_at following the
preparation of the Op (just before writing out the new state to disk;
so this version has been updated with anything necessary to make the
object writeable, etc). For a watch write, do not change the
user_version (meaning it is different from the
object_info_t::version). For a read, of course do not change it.

This means that the reassert_version is *normally* the value it should
be in order to replay the Op if necessary, but not for Watch
operations. (It appears this has caused problems in the past and so
the new LingerOp framework never replays them; it just generates new
ones.) The point here being that clients can look at the
reassert_version, compare it to previous versions, and see if there's
been a write they care about (if watching an rbd head object to
refresh it on version changes, for instance). These versions are often
shared with other clients via Notify mechanisms, and could be shared
via other channels as well.

The newer get_current_version() function returns whatever the current
contents of OpContext::at_version are. On read operations, that's 0;
on write operations it's whatever that version happens to be. It
*normally* will be equal to the reassert_version that gets returned,
but in unusual circumstances it might be different. So far no users
expect that version to have any relationship to the reassert_version,
though; they just want get_current_version() to be monotonically
increasing.

Plan for new user_version support
===============================

In order to properly support caching pools, we would like to separate
the user_version from the underlying pg log versions. This is
necessary to support moving objects back and forth between different
pools while still maintaining the version semantics we have previously
provided. Obviously old clients won't be able to handle the caching
pools, so we don't need to worry about them when we do these. But we
*do* need them to interoperate with new clients on non-caching
pools. This obviously means:

*) new and old clients must use and spread the same version on
operations in normal pools.

However, the old clients have only one version (the reassert_version),
which they must use both for replay and as the version they spread
(eg, in notifies). That implies:
1) we cannot fix the conflict in reassert_version on watch ops for old
clients.
2) the reassert version must match the user version seen by new
clients for all ops on normal pools
  2b) the user version and the replay version must be the same for ops
  on normal pools, except on watch ops
3) we need to keep track of the old-style user version and return that
in the reassert_version from the OSD

Conclusions:
We add two new fields to MOSDOpReply: user_version and
replay_version. The old replay_version becomes bad_replay_version (or
similar) and stays in the same place it used to be in the encoding for
old clients to use. New clients reference replay_version and
user_version as appropriate.  The OSD updates user_version on all
user-visibile writes (ie, non-watch write ops) to the max of
at_version and user_version+1, and fills in the bad_replay_version
based on the user_version instead of the OpContext::at_version. For
normal pools, the at_version will always be the higher value and so
old clients see the same behavior they always have. New clients,
seeing a user_version matching the bad_replay_version which the old
clients are consuming, interoperate successfully on normal pools.
On caching pools, we don't need to worry about old clients, and new
clients are happy because our MAX algorithm ensures they never see
versions go backwards. Hurray!


