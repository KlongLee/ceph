  $ rbd create foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd flatten foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd resize foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd rm foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd import-diff /tmp/diff foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd mv foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd mv foo@snap bar
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd mv foo@snap bar@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta list foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta get foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta get foo@snap key
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta set foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta set foo@snap key
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta set foo@snap key val
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta remove foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd image-meta remove foo@snap key
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd snap ls foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd snap purge foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd watch foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd status foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd feature disable foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd feature disable foo@snap layering
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd feature enable foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd feature enable foo@snap layering
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd lock list foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd lock add foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd lock add foo@snap id
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd lock remove foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd lock remove foo@snap id
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd lock remove foo@snap id client.1234
  rbd: snapname specified for a command that doesn't use it
  [1]
  $ rbd bench-write foo@snap
  rbd: snapname specified for a command that doesn't use it
  [1]

  $ rbd clone foo@snap bar@snap
  rbd: destination snapname specified for a command that doesn't use it
  [1]
  $ rbd import /bin/ls ls@snap
  rbd: destination snapname specified for a command that doesn't use it
  [1]
  $ rbd cp foo bar@snap
  rbd: destination snapname specified for a command that doesn't use it
  [1]
  $ rbd cp foo@snap bar@snap
  rbd: destination snapname specified for a command that doesn't use it
  [1]
  $ rbd mv foo bar@snap
  rbd: destination snapname specified for a command that doesn't use it
  [1]
