// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef RBD_MIRROR_IMAGE_REPLAYER_UTILS_H
#define RBD_MIRROR_IMAGE_REPLAYER_UTILS_H

namespace cls { namespace journal { struct Client; } }
namespace librbd { namespace journal { struct MirrorPeerClientMeta; } }

namespace rbd {
namespace mirror {
namespace image_replayer {
namespace util {

bool decode_client_meta(const cls::journal::Client& client,
                        librbd::journal::MirrorPeerClientMeta* client_meta);

} // namespace util
} // namespace image_replayer
} // namespace mirror
} // namespace rbd

#endif // RBD_MIRROR_IMAGE_REPLAYER_UTILS_H
