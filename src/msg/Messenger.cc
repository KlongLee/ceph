
#include "include/types.h"
#include "Messenger.h"

#include "SimpleMessenger.h"

Messenger *Messenger::create(CephContext *cct,
			     entity_name_t name,
			     string lname,
			     uint64_t nonce)
{
  if (cct->_conf->ms_type == "simple")
    return new SimpleMessenger(cct, name, lname, nonce);
  derr << "unrecognized ms_type '" << cct->_conf->ms_type << "'" << dendl;
  return NULL;
}
