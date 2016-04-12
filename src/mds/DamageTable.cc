// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#include "common/debug.h"

#include "mds/CDir.h"

#include "DamageTable.h"

#define dout_subsys ceph_subsys_mds
#undef dout_prefix
#define dout_prefix *_dout << "mds." << rank << ".damage " << __func__ << " "


DamageEntry::~DamageEntry()
{}

bool DamageTable::notify_dentry(
    inodeno_t ino, frag_t frag,
    snapid_t snap_id, const std::string &dname)
{
  if (oversized()) {
    return true;
  }

  // Special cases: damage to these dirfrags is considered fatal to
  // the MDS rank that owns them.
  if (
      (MDS_INO_IS_MDSDIR(ino) && MDS_INO_MDSDIR_OWNER(ino) == rank)
      ||
      (MDS_INO_IS_STRAY(ino) && MDS_INO_STRAY_OWNER(ino) == rank)
     ) {
    derr << "Damage to dentries in fragment " << frag << " of ino " << ino
         << "is fatal because it is a system directory for this rank" << dendl;
    return true;
  }

  DamageEntryRef entry = std::make_shared<DentryDamage>(
      ino, frag, dname, snap_id);
  dentries[DirFragIdent(ino, frag)][DentryIdent(dname, snap_id)] = entry;
  by_id[entry->id] = entry;

  return false;
}

bool DamageTable::notify_dirfrag(inodeno_t ino, frag_t frag)
{
  // Special cases: damage to these dirfrags is considered fatal to
  // the MDS rank that owns them.
  if (
      (MDS_INO_IS_STRAY(ino) && MDS_INO_STRAY_OWNER(ino) == rank)
      ||
      (ino == MDS_INO_ROOT)
     ) {
    derr << "Damage to fragment " << frag << " of ino " << ino
         << " is fatal because it is a system directory for this rank" << dendl;
    return true;
  }

  if (oversized()) {
    return true;
  }

  DamageEntryRef entry = std::make_shared<DirFragDamage>(ino, frag);
  dirfrags[DirFragIdent(ino, frag)] = entry;
  by_id[entry->id] = entry;

  return false;
}

bool DamageTable::notify_remote_damaged(inodeno_t ino)
{
  if (oversized()) {
    return true;
  }

  auto entry = std::make_shared<BacktraceDamage>(ino);
  remotes[ino] = entry;
  by_id[entry->id] = entry;

  return false;
}

bool DamageTable::oversized() const
{
  return by_id.size() > (size_t)(g_conf->mds_damage_table_max_entries);
}

bool DamageTable::is_dentry_damaged(
        const CDir *dir_frag,
        const std::string &dname,
        const snapid_t snap_id) const
{
  if (dentries.count(
        DirFragIdent(dir_frag->inode->ino(), dir_frag->frag)
        ) == 0) {
    return false;
  }

  const std::map<DentryIdent, DamageEntryRef> &frag_dentries =
    dentries.at(DirFragIdent(dir_frag->inode->ino(), dir_frag->frag));

  return frag_dentries.count(DentryIdent(dname, snap_id)) > 0;
}

bool DamageTable::is_dirfrag_damaged(
    const CDir *dir_frag) const
{
  return dirfrags.count(
      DirFragIdent(dir_frag->inode->ino(), dir_frag->frag)) > 0;
}

bool DamageTable::is_remote_damaged(
    const inodeno_t ino) const
{
  return remotes.count(ino) > 0;
}

void DamageTable::dump(Formatter *f) const
{
  f->open_array_section("damage_table");
  for (const auto &i : by_id)
  {
    i.second->dump(f);
  }
  f->close_section();
}

void DamageTable::erase(damage_entry_id_t damage_id)
{
  if (by_id.count(damage_id) == 0) {
    return;
  }

  DamageEntryRef entry = by_id.at(damage_id);
  assert(entry->id == damage_id);  // Sanity

  const auto type = entry->get_type();
  if (type == DAMAGE_ENTRY_DIRFRAG) {
    auto dirfrag_entry = std::static_pointer_cast<DirFragDamage>(entry);
    dirfrags.erase(DirFragIdent(dirfrag_entry->ino, dirfrag_entry->frag));
  } else if (type == DAMAGE_ENTRY_DENTRY) {
    auto dentry_entry = std::static_pointer_cast<DentryDamage>(entry);
    dentries.erase(DirFragIdent(dentry_entry->ino, dentry_entry->frag));
  } else if (type == DAMAGE_ENTRY_BACKTRACE) {
    auto backtrace_entry = std::static_pointer_cast<BacktraceDamage>(entry);
    remotes.erase(backtrace_entry->ino);
  } else {
    derr << "Invalid type " << type << dendl;
    assert(0);
  }

  by_id.erase(damage_id);
}

