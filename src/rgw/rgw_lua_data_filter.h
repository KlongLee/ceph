#pragma once

#include "rgw_op.h"

class DoutPrefixProvider;

namespace rgw::lua {

class RGWObjFilter {
  req_state* const s;
  const rgw::lua::LuaRuntimeMeta scripts_meta;

public:
  RGWObjFilter(req_state* s,
      const rgw::lua::LuaRuntimeMeta scripts_meta) : 
    s(s), scripts_meta(scripts_meta) {}

  int execute(bufferlist& bl, off_t offset, const char* op_name) const;
};

class RGWGetObjFilter : public RGWGetObj_Filter {
  const RGWObjFilter filter;

public:
  RGWGetObjFilter(req_state* s,
      const rgw::lua::LuaRuntimeMeta& scripts_meta,
      RGWGetObj_Filter* next) : RGWGetObj_Filter(next), filter(s, scripts_meta) 
  {}

  ~RGWGetObjFilter() override = default;

  int handle_data(bufferlist& bl,
                  off_t bl_ofs,
                  off_t bl_len) override;

};

class RGWPutObjFilter : public rgw::putobj::Pipe {
  const RGWObjFilter filter;

public:
  RGWPutObjFilter(req_state* s,
      const rgw::lua::LuaRuntimeMeta& scripts_meta,
      rgw::sal::DataProcessor* next) : rgw::putobj::Pipe(next), filter(s, scripts_meta) 
  {}

  ~RGWPutObjFilter() override = default;

  int process(bufferlist&& data, uint64_t logical_offset) override;
};
} // namespace rgw::lua

