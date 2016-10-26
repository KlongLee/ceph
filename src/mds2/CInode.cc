#include "CInode.h"
#include "CDir.h"
#include "CDentry.h"

#include "MDSRank.h"
#include "MDCache.h"
#include "Mutation.h"

#include "messages/MClientCaps.h"

#define dout_subsys ceph_subsys_mds
#undef dout_prefix
#define dout_prefix *_dout << "mds." << mdcache->mds->get_nodeid() << ".cache.inode(" << vino() << ") "

LockType CInode::versionlock_type(CEPH_LOCK_IVERSION);
LockType CInode::authlock_type(CEPH_LOCK_IAUTH);
LockType CInode::linklock_type(CEPH_LOCK_ILINK);
LockType CInode::dirfragtreelock_type(CEPH_LOCK_IDFT);
LockType CInode::filelock_type(CEPH_LOCK_IFILE);
LockType CInode::xattrlock_type(CEPH_LOCK_IXATTR);
LockType CInode::snaplock_type(CEPH_LOCK_ISNAP);
LockType CInode::nestlock_type(CEPH_LOCK_INEST);
LockType CInode::flocklock_type(CEPH_LOCK_IFLOCK);
LockType CInode::policylock_type(CEPH_LOCK_IPOLICY);

ostream& operator<<(ostream& out, const CInode& in)
{
  return out;
}

CInode::CInode(MDCache *_mdcache) :
  CObject("CInode"), mdcache(_mdcache),
  parent(NULL),
  versionlock(this, &versionlock_type),
  authlock(this, &authlock_type),
  linklock(this, &linklock_type),
  dirfragtreelock(this, &dirfragtreelock_type),
  filelock(this, &filelock_type),
  xattrlock(this, &xattrlock_type),
  snaplock(this, &snaplock_type),
  nestlock(this, &nestlock_type),
  flocklock(this, &flocklock_type),
  policylock(this, &policylock_type),
  loner_cap(-1), want_loner_cap(-1),
  want_max_size(0)
{

}

void CInode::first_get()
{
  Mutex::Locker l(mutex);
  if (parent)
    parent->get(CDentry::PIN_INODEPIN);
}
void CInode::last_put()
{
  Mutex::Locker l(mutex);
  if (parent)
    parent->put(CDentry::PIN_INODEPIN);
}

void CInode::get_dirfrags(list<CDirRef>& ls)
{
  for (auto p = dirfrags.begin(); p != dirfrags.end(); ++p)
    ls.push_back(p->second);
}

CDirRef CInode::get_or_open_dirfrag(frag_t fg)
{
  CDirRef ref = get_dirfrag(fg);
  if (!ref) {
    assert(fg == frag_t());
    CDir *dir = new CDir(this);
    dirfrags[fg] = dir;
    dir->__set_version(1);
    ref = dir;
  }
  return ref;
}

inode_t *CInode::project_inode(std::map<string, bufferptr> **ppx)
{
  mutex_assert_locked_by_me();
  const xattr_map_t *px = NULL;
  if (projected_nodes.empty()) {
    if (ppx)
      px = get_xattrs();
    projected_nodes.push_back(projected_inode_t(inode, px));
    if (ppx)
      *ppx = &projected_nodes.back().xattrs;
  } else {
    const inode_t *pi = get_projected_inode();
    if (ppx)
      px = get_projected_xattrs();
    projected_nodes.push_back(projected_inode_t(*pi, px));
    if (ppx)
      *ppx = &projected_nodes.back().xattrs;
  }
  dout(10) << "project_inode " << &projected_nodes.back() << dendl;
  return &projected_nodes.back().inode;
}

void CInode::pop_and_dirty_projected_inode(LogSegment *ls)
{
  mutex_assert_locked_by_me();
  assert(!projected_nodes.empty());

  projected_inode_t *pi = &projected_nodes.front();
  dout(10) << "pop_and_dirty_projected_inode " << pi << dendl;

  mark_dirty(pi->inode.version, ls);
  inode = pi->inode;

  if (pi->xattrs_projected)
    xattrs.swap(pi->xattrs);

  projected_nodes.pop_front();
}

version_t CInode::pre_dirty()
{
  mutex_assert_locked_by_me();
  version_t pv;
  CDentry* parent_dn = get_projected_parent_dn();
  if (parent_dn) {
    pv = parent_dn->pre_dirty(get_projected_version());
    dout(10) << "pre_dirty " << pv << " (current v " << inode.version << ")" << dendl;
  } else {
    assert(is_base());
    pv = get_projected_version() + 1;
  }
  return pv;
}

void CInode::_mark_dirty(LogSegment *ls)
{
  if (!state_test(STATE_DIRTY)) {
    state_set(STATE_DIRTY);
    get(PIN_DIRTY);
//    assert(ls);
  }

  /*
  if (ls)
    ls->dirty_inodes.push_back(&item_dirty);
    */
}

void CInode::mark_dirty(version_t pv, LogSegment *ls) {
  mutex_assert_locked_by_me();
  dout(10) << "mark_dirty " << *this << dendl;

  // touch my private version
  assert(inode.version < pv);
  inode.version = pv;
  _mark_dirty(ls);

  // mark dentry too
  if (parent)
    parent->mark_dirty(pv, ls);
}


void CInode::mark_clean()
{
  dout(10) << " mark_clean " << *this << dendl;
  if (state_test(STATE_DIRTY)) {
    state_clear(STATE_DIRTY);
    put(PIN_DIRTY);

    // remove myself from ls dirty list
//    item_dirty.remove_myself();
  }
}

CDentryRef CInode::get_lock_parent_dn()
{
  for (;;) {
    CDentryRef dn;
    mutex_lock();
    dn = get_parent_dn();
    bool done = dn->get_dir_inode()->mutex_trylock();
    mutex_unlock();
    if (done)
      return dn;

    dn->get_dir_inode()->mutex_lock();
    const CDentry::linkage_t* dnl = dn->get_linkage();
    if (!dnl->is_primary() || dnl->get_inode() != this) {
      dn->get_dir_inode()->mutex_unlock();
      continue;
    }
    return dn;
  }
}

CDentryRef CInode::get_lock_projected_parent_dn()
{
  for (;;) {
    CDentryRef dn;
    mutex_lock();
    dn = get_projected_parent_dn();
    bool done = dn->get_dir_inode()->mutex_trylock();
    mutex_unlock();
    if (done)
      return dn;

    dn->get_dir_inode()->mutex_lock();
    const CDentry::linkage_t* dnl = dn->get_projected_linkage();
    if (!dnl->is_primary() || dnl->get_inode() != this) {
      dn->get_dir_inode()->mutex_unlock();
      continue;
    }
    return dn;
  }
}

bool CInode::is_projected_ancestor_of(CInode *other) const
{
  // caller should hold MDCache::rename_dir_mutex
  while (other) {
    if (other == this)
      return true;
    other->mutex_lock();
    CDentry *parent_dn = other->get_projected_parent_dn();
    other->mutex_unlock();
    if (!parent_dn)
      break;
    other = parent_dn->get_dir_inode();
  }
  return false;
}


int CInode::encode_inodestat(bufferlist& bl, Session *session,
			     unsigned max_bytes, int getattr_wants)
{
  client_t client = session->get_client();
  assert(session->connection);

  snapid_t snapid = CEPH_NOSNAP;
  
  // pick a version!
  const inode_t *oi = get_inode();
  const inode_t *pi = get_projected_inode();
  const xattr_map_t *pxattrs = 0;
  
  // "fake" a version that is old (stable) version, +1 if projected.
  version_t version = (oi->version * 2) + is_projected();

  Capability *cap = get_client_cap(client);
  bool pfile = filelock.is_xlocked_by_client(client) || get_loner() == client;
  bool pauth = authlock.is_xlocked_by_client(client) || get_loner() == client;
  bool plink = linklock.is_xlocked_by_client(client) || get_loner() == client;
  bool pxattr = xattrlock.is_xlocked_by_client(client) || get_loner() == client;
  bool plocal = versionlock.get_last_wrlock_client() == client;
  bool ppolicy = policylock.is_xlocked_by_client(client) || get_loner()==client;
  
  const inode_t *any_i = (pfile|pauth|plink|pxattr|plocal) ? pi : oi;
  
  dout(20) << " pfile " << pfile << " pauth " << pauth
	   << " plink " << plink << " pxattr " << pxattr
	   << " plocal " << plocal << " ctime " << any_i->ctime
	   << dendl;

  // file
  const inode_t *file_i = pfile ? pi:oi;
  file_layout_t layout;
  if (is_dir()) {
    layout = (ppolicy ? pi : oi)->layout;
  } else {
    layout = file_i->layout;
  }

  // max_size is min of projected, actual
  uint64_t max_size;
  {
    auto p = oi->client_ranges.find(client);
    auto q = pi->client_ranges.find(client);
    if (p == oi->client_ranges.end() ||
	q == pi->client_ranges.end())
      max_size = 0;
    else
      max_size = MIN(p->second.range.last, q->second.range.last);
  }

  // inline data
  version_t inline_version = CEPH_INLINE_NONE;
  bufferlist inline_data;
#if 0
  if (file_i->inline_data.version == CEPH_INLINE_NONE) {
    inline_version = CEPH_INLINE_NONE;
  } else if (!cap ||
	     cap->client_inline_version < file_i->inline_data.version ||
	     (getattr_wants & CEPH_CAP_FILE_RD)) { // client requests inline data
    inline_version = file_i->inline_data.version;
    if (file_i->inline_data.length() > 0)
      inline_data = file_i->inline_data.get_data();
  }
#endif

  // nest (do same as file... :/)
  if (cap) {
    cap->last_rbytes = file_i->rstat.rbytes;
    cap->last_rsize = file_i->rstat.rsize();
  }

  // auth
  const inode_t *auth_i = pauth ? pi:oi;

  // link
  const inode_t *link_i = plink ? pi:oi;
  
  // xattr
  const inode_t *xattr_i = pxattr ? pi:oi;

  // xattr
  bufferlist xbl;
  version_t xattr_version;
  if (!cap || cap->client_xattr_version < xattr_i->xattr_version ||
      (getattr_wants & CEPH_CAP_XATTR_SHARED)) { // client requests xattrs
    if (!pxattrs)
      pxattrs = pxattr ? get_projected_xattrs() : &xattrs;
    ::encode(*pxattrs, xbl);
    xattr_version = xattr_i->xattr_version;
  } else {
    xattr_version = 0;
  }
  
  // do we have room?
  if (max_bytes) {
    unsigned bytes = 8 + 8 + 4 + 8 + 8 + sizeof(ceph_mds_reply_cap) +
      sizeof(struct ceph_file_layout) + 4 + layout.pool_ns.size() +
      sizeof(struct ceph_timespec) * 3 +
      4 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 4 +
      8 + 8 + 8 + 8 + 8 + sizeof(struct ceph_timespec) +
      4;
    bytes += sizeof(__u32);
    bytes += (sizeof(__u32) + sizeof(__u32)) * 0 /*  dirfragtree._splits.size() */;
    bytes += sizeof(__u32) + symlink.length();
    bytes += sizeof(__u32) + xbl.length();
    bytes += sizeof(version_t) + sizeof(__u32) + inline_data.length();
    if (bytes > max_bytes)
      return -ENOSPC;
  }


  // encode caps
  if (!cap) {
    // add a new cap
    cap = add_client_cap(client, session);
    if (is_auth()) {
      if (choose_ideal_loner() >= 0)
        try_set_loner();
      else if (get_wanted_loner() < 0)
        try_drop_loner();
    }
  }

  int likes = get_caps_liked();
  int allowed = get_caps_allowed_for_client(session, file_i);
  int issue = (cap->wanted() | likes) & allowed;
  cap->issue_norevoke(issue);
  issue = cap->pending();
  cap->set_last_issue();
  cap->set_last_issue_stamp(ceph_clock_now(g_ceph_context));
  cap->clear_new();

  struct ceph_mds_reply_cap ecap;
  ecap.caps = issue;
  ecap.wanted = cap->wanted();
  ecap.cap_id = cap->get_cap_id();
  ecap.seq = cap->get_last_seq();
  dout(10) << "encode_inodestat issuing " << ccap_string(issue)
           << " seq " << cap->get_last_seq() << dendl;
  ecap.mseq = cap->get_mseq();
  ecap.realm = CEPH_INO_ROOT;

  ecap.flags = CEPH_CAP_FLAG_AUTH;
  dout(10) << "encode_inodestat caps " << ccap_string(ecap.caps)
	   << " seq " << ecap.seq << " mseq " << ecap.mseq
	   << " xattrv " << xattr_version << " len " << xbl.length()
	   << dendl;

  if (inline_data.length() && cap) {
    if ((cap->pending() | getattr_wants) & CEPH_CAP_FILE_SHARED) {
      dout(10) << "including inline version " << inline_version << dendl;
      cap->client_inline_version = inline_version;
    } else {
      dout(10) << "dropping inline version " << inline_version << dendl;
      inline_version = 0;
      inline_data.clear();
    }
  }

  // include those xattrs?
  if (xbl.length() && cap) {
    if ((cap->pending() | getattr_wants) & CEPH_CAP_XATTR_SHARED) {
      dout(10) << "including xattrs version " << xattr_i->xattr_version << dendl;
      cap->client_xattr_version = xattr_i->xattr_version;
    } else {
      dout(10) << "dropping xattrs version " << xattr_i->xattr_version << dendl;
      xbl.clear(); // no xattrs .. XXX what's this about?!?
      xattr_version = 0;
    }
  }

  /*
   * note: encoding matches MClientReply::InodeStat
   */
  ::encode(oi->ino, bl);
  ::encode(snapid, bl);
  ::encode(oi->rdev, bl);
  ::encode(version, bl);

  ::encode(xattr_version, bl);

  ::encode(ecap, bl);
  {
    ceph_file_layout legacy_layout;
    layout.to_legacy(&legacy_layout);
    ::encode(legacy_layout, bl);
  }
  ::encode(any_i->ctime, bl);
  ::encode(file_i->mtime, bl);
  ::encode(file_i->atime, bl);
  ::encode(file_i->time_warp_seq, bl);
  ::encode(file_i->size, bl);
  ::encode(max_size, bl);
  ::encode(file_i->truncate_size, bl);
  ::encode(file_i->truncate_seq, bl);

  ::encode(auth_i->mode, bl);
  ::encode((uint32_t)auth_i->uid, bl);
  ::encode((uint32_t)auth_i->gid, bl);

  ::encode(link_i->nlink, bl);

  ::encode(file_i->dirstat.nfiles, bl);
  ::encode(file_i->dirstat.nsubdirs, bl);
  ::encode(file_i->rstat.rbytes, bl);
  ::encode(file_i->rstat.rfiles, bl);
  ::encode(file_i->rstat.rsubdirs, bl);
  ::encode(file_i->rstat.rctime, bl);

  {
    fragtree_t empty;
    empty.encode(bl);
  }
  //dirfragtree.encode(bl);

  ::encode(symlink, bl);
  if (session->connection->has_feature(CEPH_FEATURE_DIRLAYOUTHASH)) {
    ::encode(file_i->dir_layout, bl);
  }
  ::encode(xbl, bl);
  if (session->connection->has_feature(CEPH_FEATURE_MDS_INLINE_DATA)) {
    ::encode(inline_version, bl);
    ::encode(inline_data, bl);
  }
  if (session->connection->has_feature(CEPH_FEATURE_MDS_QUOTA)) {
    const inode_t *policy_i = ppolicy ? pi : oi;
    ::encode(policy_i->quota, bl);
  }
  if (session->connection->has_feature(CEPH_FEATURE_FS_FILE_LAYOUT_V2)) {
    ::encode(layout.pool_ns, bl);
  }

  return 0;
}


void CInode::encode_cap_message(MClientCaps *m, Capability *cap)
{
  assert(cap);

  client_t client = cap->get_client();

  bool pfile = filelock.is_xlocked_by_client(client) || (cap->issued() & CEPH_CAP_FILE_EXCL);
  bool pauth = authlock.is_xlocked_by_client(client);
  bool plink = linklock.is_xlocked_by_client(client);
  bool pxattr = xattrlock.is_xlocked_by_client(client);

  const inode_t *oi = get_inode();
  const inode_t *pi = get_projected_inode();
  const inode_t *i = (pfile|pauth|plink|pxattr) ? pi : oi;

  dout(20) << "encode_cap_message pfile " << pfile
           << " pauth " << pauth << " plink " << plink << " pxattr " << pxattr
           << " ctime " << i->ctime << dendl;

  i = pfile ? pi:oi;
  m->layout = i->layout;
  m->size = i->size;
  m->truncate_seq = i->truncate_seq;
  m->truncate_size = i->truncate_size;
  m->mtime = i->mtime;
  m->atime = i->atime;
  m->ctime = i->ctime;
  m->time_warp_seq = i->time_warp_seq;

  m->inline_version = CEPH_INLINE_NONE;
  /*
  if (cap->client_inline_version < i->inline_data.version) {
    m->inline_version = cap->client_inline_version = i->inline_data.version;
    if (i->inline_data.length() > 0)
      m->inline_data = i->inline_data.get_data();
  } else {
    m->inline_version = 0;
  }
  */

  // max_size is min of projected, actual.
  uint64_t oldms = 0, newms = 0;
  {
    auto p = oi->client_ranges.find(client);
    if (p != oi->client_ranges.end())
      oldms = p->second.range.last;
    auto q = pi->client_ranges.find(client);
    if (p != pi->client_ranges.end())
      newms = q->second.range.last;
  }
  m->max_size = MIN(oldms, newms);

  i = pauth ? pi:oi;
  m->head.mode = i->mode;
  m->head.uid = i->uid;
  m->head.gid = i->gid;

  i = plink ? pi:oi;
  m->head.nlink = i->nlink;

  i = pxattr ? pi:oi;
  const xattr_map_t *ix = pxattr ? get_projected_xattrs() : &xattrs;
  if ((cap->pending() & CEPH_CAP_XATTR_SHARED) &&
      i->xattr_version > cap->client_xattr_version) {
    dout(10) << "    including xattrs v " << i->xattr_version << dendl;
    ::encode(*ix, m->xattrbl);
    m->head.xattr_version = i->xattr_version;
    cap->client_xattr_version = i->xattr_version;
  }
}

void CInode::name_stray_dentry(string& dname) const
{
  char s[20];
  snprintf(s, sizeof(s), "%llx", (unsigned long long)inode.ino.val);
  dname = s;
}

int CInode::get_caps_liked() const
{
  if (is_dir())
    return CEPH_CAP_PIN | CEPH_CAP_ANY_EXCL | CEPH_CAP_ANY_SHARED;  // but not, say, FILE_RD|WR|WRBUFFER
  else
    return CEPH_CAP_ANY & ~CEPH_CAP_FILE_LAZYIO;
}

int CInode::get_caps_allowed_ever() const
{
  int allowed;
  if (is_dir())
    allowed = CEPH_CAP_PIN | CEPH_CAP_ANY_EXCL | CEPH_CAP_ANY_SHARED;
  else
    allowed = CEPH_CAP_ANY;
  return allowed &
    (CEPH_CAP_PIN |
     (filelock.gcaps_allowed_ever() << filelock.get_cap_shift()) |
     (authlock.gcaps_allowed_ever() << authlock.get_cap_shift()) |
     (xattrlock.gcaps_allowed_ever() << xattrlock.get_cap_shift()) |
     (linklock.gcaps_allowed_ever() << linklock.get_cap_shift()));
}

int CInode::get_caps_allowed_by_type(int type) const
{
  return
    CEPH_CAP_PIN |
    (filelock.gcaps_allowed(type) << filelock.get_cap_shift()) |
    (authlock.gcaps_allowed(type) << authlock.get_cap_shift()) |
    (xattrlock.gcaps_allowed(type) << xattrlock.get_cap_shift()) |
    (linklock.gcaps_allowed(type) << linklock.get_cap_shift());
}

int CInode::get_caps_careful() const
{
  return
    (filelock.gcaps_careful() << filelock.get_cap_shift()) |
    (authlock.gcaps_careful() << authlock.get_cap_shift()) |
    (xattrlock.gcaps_careful() << xattrlock.get_cap_shift()) |
    (linklock.gcaps_careful() << linklock.get_cap_shift());
}

int CInode::get_xlocker_mask(client_t client) const
{
  return
    (filelock.gcaps_xlocker_mask(client) << filelock.get_cap_shift()) |
    (authlock.gcaps_xlocker_mask(client) << authlock.get_cap_shift()) |
    (xattrlock.gcaps_xlocker_mask(client) << xattrlock.get_cap_shift()) |
    (linklock.gcaps_xlocker_mask(client) << linklock.get_cap_shift());
}

int CInode::get_caps_allowed_for_client(Session *session, const inode_t *file_i) const
{
  client_t client = session->info.inst.name.num();
  int allowed;
  if (client == get_loner()) {
    // as the loner, we get the loner_caps AND any xlocker_caps for things we have xlocked
    allowed =
      get_caps_allowed_by_type(CAP_LONER) |
      (get_caps_allowed_by_type(CAP_XLOCKER) & get_xlocker_mask(client));
  } else {
    allowed = get_caps_allowed_by_type(CAP_ANY);
  }

  if (!is_dir()) {
    if ((file_i->inline_data.version != CEPH_INLINE_NONE &&
         !session->connection->has_feature(CEPH_FEATURE_MDS_INLINE_DATA)) ||
        (!file_i->layout.pool_ns.empty() &&
         !session->connection->has_feature(CEPH_FEATURE_FS_FILE_LAYOUT_V2)))
      allowed &= ~(CEPH_CAP_FILE_RD | CEPH_CAP_FILE_WR);
  }
  return allowed;
}

// caps issued, wanted
int CInode::get_caps_issued(int *ploner, int *pother, int *pxlocker,
                            int shift, int mask)
{ 
  int c = 0;
  int loner = 0, other = 0, xlocker = 0;
  if (!is_auth()) {
    loner_cap = -1;
  }
  
  for (map<client_t,Capability*>::const_iterator it = client_caps.begin();
       it != client_caps.end();
       ++it) {
    int i = it->second->issued();
    c |= i;
    if (it->first == loner_cap)
      loner |= i;
    else
      other |= i;
    xlocker |= get_xlocker_mask(it->first) & i;
  }
  if (ploner) *ploner = (loner >> shift) & mask;
  if (pother) *pother = (other >> shift) & mask; 
  if (pxlocker) *pxlocker = (xlocker >> shift) & mask;
  return (c >> shift) & mask;
}

bool CInode::is_any_caps_wanted() const
{
  for (map<client_t,Capability*>::const_iterator it = client_caps.begin();
       it != client_caps.end();
       ++it)
    if (it->second->wanted())
      return true;
  return false;
}

int CInode::get_caps_wanted(int *ploner, int *pother, int shift, int mask) const
{
  int w = 0;
  int loner = 0, other = 0;
  for (map<client_t,Capability*>::const_iterator it = client_caps.begin();
       it != client_caps.end();
       ++it) {
    if (!it->second->is_stale()) {
      int t = it->second->wanted();
      w |= t;
      if (it->first == loner_cap)
        loner |= t;
      else
        other |= t;
    }
    //cout << " get_caps_wanted client " << it->first << " " << cap_string(it->second.wanted()) << endl;
  }
  if (ploner) *ploner = (loner >> shift) & mask;
  if (pother) *pother = (other >> shift) & mask;
  return (w >> shift) & mask;
}

bool CInode::issued_caps_need_gather(SimpleLock *lock)
{
  int loner_issued, other_issued, xlocker_issued;
  get_caps_issued(&loner_issued, &other_issued, &xlocker_issued,
                  lock->get_cap_shift(), lock->get_cap_mask());
  if ((loner_issued & ~lock->gcaps_allowed(CAP_LONER)) ||
      (other_issued & ~lock->gcaps_allowed(CAP_ANY)) ||
      (xlocker_issued & ~lock->gcaps_allowed(CAP_XLOCKER)))
    return true;
  return false;
}

client_t CInode::calc_ideal_loner()
{
  int n = 0;
  client_t loner = -1;
  for (map<client_t,Capability*>::iterator it = client_caps.begin();
       it != client_caps.end();
       ++it)
    if (!it->second->is_stale() &&
        (it->second->wanted() & (CEPH_CAP_ANY_WR|CEPH_CAP_FILE_WR|CEPH_CAP_FILE_RD))) {
      if (n)
        return -1;
      n++;
      loner = it->first;
    }
  return loner;
}

client_t CInode::choose_ideal_loner()
{
  want_loner_cap = calc_ideal_loner();
  return want_loner_cap;
}

void CInode::set_loner_cap(client_t l)
{
  loner_cap = l;
  authlock.set_excl_client(loner_cap);
  filelock.set_excl_client(loner_cap);
  linklock.set_excl_client(loner_cap);
  xattrlock.set_excl_client(loner_cap);
}

bool CInode::try_set_loner()
{
  assert(want_loner_cap >= 0);
  if (loner_cap >= 0 && loner_cap != want_loner_cap)
    return false;
  set_loner_cap(want_loner_cap);
  return true;
}

bool CInode::try_drop_loner()
{
  if (loner_cap < 0)
    return true;

  int other_allowed = get_caps_allowed_by_type(CAP_ANY);
  Capability *cap = get_client_cap(loner_cap);
  if (!cap ||
      (cap->issued() & ~other_allowed) == 0) {
    set_loner_cap(-1);
    return true;
  }
  return false;
}

void CInode::start_scatter(ScatterLock *lock)
{
  mutex_assert_locked_by_me();
  dout(10) << "start_scatter " << *lock << " on " << *this << dendl;

  for (auto p = dirfrags.begin(); p != dirfrags.end(); ++p) {
    frag_t fg = p->first;
    CDir *dir = p->second;
    dout(20) << fg << " " << *dir << dendl;
    switch (lock->get_type()) {
      case CEPH_LOCK_IFILE:
      case CEPH_LOCK_INEST:
	finish_scatter_update(lock, dir);
	break;
      case CEPH_LOCK_IDFT:
	//dir->state_clear(CDir::STATE_DIRTYDFT);
	break;
    }
  }
}

void CInode::__frag_update_finish(CDir *dir, MutationRef& mut)
{
  mut->wait_committing();
  dout(10) << "__finish_frag_update on " << *dir << dendl;

  mut->apply();
  mut->cleanup();
}


class C_Inode_FragUpdate : public MDSInternalContextBase {
  CInode *in;
  CDir *dir;
  MutationRef mut;
  MDSRank *get_mds() { return in->mdcache->mds; }
  void finish(int r) {
    in->__frag_update_finish(dir, mut);
  }
public:
  C_Inode_FragUpdate(CInode *i, CDir *d, MutationRef& m)
    : in(i), dir(d), mut(m) {}
};

void CInode::finish_scatter_update(ScatterLock *lock, CDir *dir)
{ 
  const inode_t *pi = get_projected_inode();
  frag_t fg = dir->get_frag();

  version_t inode_version;
  version_t dir_accounted_version;
  switch (lock->get_type()) {
  case CEPH_LOCK_IFILE:
    inode_version = pi->dirstat.version;
    dir_accounted_version = dir->get_projected_fnode()->accounted_fragstat.version;
    break;
  case CEPH_LOCK_INEST: 
    inode_version = pi->rstat.version;
    dir_accounted_version = dir->get_projected_fnode()->accounted_rstat.version;
    break;
  default:
    assert(0); 
  }

  if (dir->get_version() == 0) {
    dout(10) << "finish_scatter_update " << fg << " not loaded, marking " << *lock << " stale " << *dir << dendl;
  } else {
    if (dir_accounted_version != inode_version) {
      dout(10) << "finish_scatter_update " << fg << " journaling accounted scatterstat update v" << inode_version << dendl;

      MutationRef mut(new MutationImpl);

      fnode_t *pf = dir->project_fnode();
      pf->version = dir->pre_dirty();

      const char *ename = 0;
      switch (lock->get_type()) {
      case CEPH_LOCK_IFILE:
	pf->fragstat.version = pi->dirstat.version;
	pf->accounted_fragstat = pf->fragstat;
	ename = "lock ifile accounted scatter stat update";
	break;
      case CEPH_LOCK_INEST: 
	pf->rstat.version = pi->rstat.version;
	pf->accounted_rstat = pf->rstat;
	ename = "lock inest accounted scatter stat update";
	break;
      default:
	assert(0);
      }

      mut->add_projected_fnode(dir, false);
      mut->pin(dir);

      mdcache->start_log_entry();
      // use finisher to simulate log flush
      mdcache->mds->queue_context(new C_Inode_FragUpdate(this, dir, mut));
      mdcache->submit_log_entry();

      mut->start_committing();
    } else {
      dout(10) << "finish_scatter_update " << fg << " accounted " << *lock
	       << " scatter stat unchanged at v" << dir_accounted_version << dendl;
    }
  }
}

void CInode::finish_scatter_gather_update(int type, MutationRef& mut)
{
  dout(10) << "finish_scatter_gather_update " << type << " on " << *this << dendl;

  switch (type) {
  case CEPH_LOCK_IFILE:
    {
      inode_t *pi = __get_projected_inode();

      bool touched_mtime = false;
      dout(20) << "  orig dirstat " << pi->dirstat << dendl;
      pi->dirstat.version++;
      for (auto p = dirfrags.begin(); p != dirfrags.end(); ++p) {
	frag_t fg = p->first;
	CDir *dir = p->second;
	dout(20) << fg << " " << *dir << dendl;

	bool update = dir->get_version() > 0;
	const fnode_t *pf = update ? dir->project_fnode() : dir->get_projected_fnode();

	if (pf->accounted_fragstat.version == pi->dirstat.version - 1) {
	  dout(20) << fg << "           fragstat " << pf->fragstat << dendl;
	  dout(20) << fg << " accounted_fragstat " << pf->accounted_fragstat << dendl;
	  pi->dirstat.add_delta(pf->fragstat, pf->accounted_fragstat, touched_mtime);
	} else {
	  dout(20) << fg << " skipping STALE accounted_fragstat " << pf->accounted_fragstat << dendl;
	}

	if (update) {
	  mut->pin(dir);
	  mut->add_projected_fnode(dir, true);
	  fnode_t *pf = dir->__get_projected_fnode();
	  pf->version = dir->pre_dirty();

	  pf->fragstat.version = pi->dirstat.version;
	  pf->accounted_fragstat = pf->fragstat;
	  dout(10) << fg << " updated accounted_fragstat " << pf->fragstat << " on " << *dir << dendl;
	}
      }
      if (touched_mtime)
	pi->mtime = pi->ctime = pi->dirstat.mtime;
      dout(20) << " final dirstat " << pi->dirstat << dendl;
    }
    break;

  case CEPH_LOCK_INEST:
    {
      inode_t *pi = __get_projected_inode();

      dout(20) << "  orig rstat " << pi->rstat << dendl;
      pi->rstat.version++;
      for (auto p = dirfrags.begin(); p != dirfrags.end(); ++p) {
	frag_t fg = p->first;
	CDir *dir = p->second;
	dout(20) << fg << " " << *dir << dendl;

	bool update = dir->get_version() > 0;
	const fnode_t *pf = update ? dir->project_fnode() : dir->get_projected_fnode();

	if (pf->accounted_rstat.version == pi->rstat.version-1) {
	  // only pull this frag's dirty rstat inodes into the frag if
	  // the frag is non-stale and updateable.  if it's stale,
	  // that info will just get thrown out!
	  if (update)
	    dir->assimilate_dirty_rstat_inodes(mut);

	  dout(20) << fg << "           rstat " << pf->rstat << dendl;
	  dout(20) << fg << " accounted_rstat " << pf->accounted_rstat << dendl;
	  mdcache->project_rstat_frag_to_inode(pf, pi);
	} else {
	  dout(20) << fg << " skipping STALE accounted_rstat " << pf->accounted_rstat << dendl;
	}
	if (update) {
	  mut->pin(dir);
	  mut->add_projected_fnode(dir, true);
	  fnode_t *pf = dir->__get_projected_fnode();
	  pf->version = dir->pre_dirty();

	  pf->rstat.version = pi->rstat.version;
	  pf->accounted_rstat = pf->rstat;
	  dout(10) << fg << " updated accounted_rstat " << pf->rstat << " on " << *dir << dendl;
	}
      }
      dout(20) << " final rstat " << pi->rstat << dendl;
    }
    break;

  case CEPH_LOCK_IDFT:
    break;

  default:
    assert(0);
  }
}

void CInode::finish_scatter_gather_update_accounted(int type, MutationRef& mut, EMetaBlob *metablob)
{
  dout(10) << "finish_scatter_gather_update_accounted " << type << " on " << *this << dendl;
  assert(is_auth());

  for (auto p = dirfrags.begin(); p != dirfrags.end(); ++p) {
    CDir *dir = p->second;
    if (dir->get_version() == 0)
      continue;
    
    if (type == CEPH_LOCK_IDFT)
      continue;  // nothing to do.

    dout(10) << " journaling updated frag accounted_ on " << *dir << dendl;
    assert(dir->is_projected());
    //metablob->add_dir(dir, true);

    if (type == CEPH_LOCK_INEST)
      dir->assimilate_dirty_rstat_inodes_finish(mut, metablob);
  }
}

void CInode::mark_dirty_rstat()
{
  mutex_assert_locked_by_me();
  if (!state_test(STATE_DIRTYRSTAT)) {
    dout(10) << "mark_dirty_rstat" << dendl;
    state_set(STATE_DIRTYRSTAT);
    get(PIN_DIRTYRSTAT);
    CDentry *dn = get_projected_parent_dn();
    dn->get_dir()->add_dirty_rstat_inode(this);
  }
}
void CInode::clear_dirty_rstat()
{
  mutex_assert_locked_by_me();
  if (state_test(STATE_DIRTYRSTAT)) {
    dout(10) << "clear_dirty_rstat" << dendl;
    CDentry *dn = get_projected_parent_dn();
    dn->get_dir()->remove_dirty_rstat_inode(this);
    state_clear(STATE_DIRTYRSTAT);
    put(PIN_DIRTYRSTAT);
  }
}

void CInode::clear_dirty_scattered(int type)
{
  dout(10) << "clear_dirty_scattered " << type << " on " << *this << dendl;
  switch (type) {
    case CEPH_LOCK_IFILE:
//      item_dirty_dirfrag_dir.remove_myself();
      break;
    case CEPH_LOCK_INEST:
//      item_dirty_dirfrag_nest.remove_myself();
      break;
    case CEPH_LOCK_IDFT:
//      item_dirty_dirfrag_dirfragtree.remove_myself();
      break;
    default:
      assert(0);
  }
}

Capability *CInode::add_client_cap(client_t client, Session *session)
{
  mutex_assert_locked_by_me();

  if (client_caps.empty()) {
    get(PIN_CAPS);
/*
    if (conrealm)
      containing_realm = conrealm;
    else
      containing_realm = find_snaprealm();
    containing_realm->inodes_with_caps.push_back(&item_caps);
    dout(10) << "add_client_cap first cap, joining realm " << *containing_realm << dendl;
*/
  }

/*
  mdcache->num_caps++;
  if (client_caps.empty())
    mdcache->num_inodes_with_caps++;
*/

  Capability *cap = new Capability(this, session, mdcache->get_new_cap_id());
  assert(client_caps.count(client) == 0);
  client_caps[client] = cap;

  session->lock();
  session->caps.push_back(&cap->item_session_caps);
  if (session->is_stale())
    cap->mark_stale();
  session->unlock();

  cap->client_follows = 1;

//  containing_realm->add_cap(client, cap);

  return cap;
}

void CInode::remove_client_cap(client_t client, Session *session)
{
  mutex_assert_locked_by_me();
  assert(client_caps.count(client) == 1);
  Capability *cap = client_caps[client];
  assert(cap->get_session() == session);

  session->lock();
  cap->item_session_caps.remove_myself();
  session->unlock();
/*
  cap->item_revoking_caps.remove_myself();
  cap->item_client_revoking_caps.remove_myself();
  containing_realm->remove_cap(client, cap);
*/

  if (client == loner_cap)
    loner_cap = -1;

  client_caps.erase(client);
  delete cap;
  if (client_caps.empty()) {
    put(PIN_CAPS);
//    dout(10) << "remove_client_cap last cap, leaving realm " << *containing_realm << dendl;
//    item_caps.remove_myself();
//    containing_realm = NULL;
  }
//  mdcache->num_caps--;

  //clean up advisory locks
/*
  bool fcntl_removed = fcntl_locks ? fcntl_locks->remove_all_from(client) : false;
  bool flock_removed = flock_locks ? flock_locks->remove_all_from(client) : false;
  if (fcntl_removed || flock_removed) {
    list<MDSInternalContextBase*> waiters;
    take_waiting(CInode::WAIT_FLOCK, waiters);
    mdcache->mds->queue_waiters(waiters);
  }
*/
}

void intrusive_ptr_add_ref(CInode *o)
{
  o->get(CObject::PIN_INTRUSIVEPTR);
}
void intrusive_ptr_release(CInode *o)
{
  o->put(CObject::PIN_INTRUSIVEPTR);
}
