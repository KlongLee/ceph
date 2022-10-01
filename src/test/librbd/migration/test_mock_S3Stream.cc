// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "test/librbd/test_mock_fixture.h"
#include "test/librbd/test_support.h"
#include "include/rbd_types.h"
#include "common/ceph_mutex.h"
#include "librbd/migration/HttpClient.h"
#include "librbd/migration/S3Stream.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "json_spirit/json_spirit.h"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/beast/http.hpp>

namespace librbd {
namespace {

struct MockTestImageCtx : public MockImageCtx {
  MockTestImageCtx(ImageCtx &image_ctx) : MockImageCtx(image_ctx) {
  }
};

} // anonymous namespace

namespace migration {

template <>
struct HttpClient<MockTestImageCtx> {
  static HttpClient* s_instance;
  static HttpClient* create(MockTestImageCtx*, const std::string&) {
    ceph_assert(s_instance != nullptr);
    return s_instance;
  }

  HttpProcessorInterface* http_processor = nullptr;
  void set_http_processor(HttpProcessorInterface* http_processor) {
    this->http_processor = http_processor;
  }

  MOCK_METHOD1(open, void(Context*));
  MOCK_METHOD1(close, void(Context*));
  MOCK_METHOD2(get_size, void(uint64_t*, Context*));
  MOCK_METHOD3(do_read, void(const io::Extents&, bufferlist*, Context*));
  void read(io::Extents&& extents, bufferlist* bl, Context* ctx) {
    do_read(extents, bl, ctx);
  }

  HttpClient() {
    s_instance = this;
  }
};

HttpClient<MockTestImageCtx>* HttpClient<MockTestImageCtx>::s_instance = nullptr;

} // namespace migration
} // namespace librbd

#include "librbd/migration/S3Stream.cc"

namespace librbd {
namespace migration {

using ::testing::_;
using ::testing::Invoke;
using ::testing::InSequence;
using ::testing::WithArgs;

class TestMockMigrationS3Stream : public TestMockFixture {
public:
  typedef S3Stream<MockTestImageCtx> MockS3Stream;
  typedef HttpClient<MockTestImageCtx> MockHttpClient;

  using EmptyBody = boost::beast::http::empty_body;
  using EmptyRequest = boost::beast::http::request<EmptyBody>;

  librbd::ImageCtx *m_image_ctx;

  void SetUp() override {
    TestMockFixture::SetUp();

    ASSERT_EQ(0, open_image(m_image_name, &m_image_ctx));
    json_object["url"] = "http://some.site/bucket/file";
    json_object["access_key"] = "0555b35654ad1656d804";
    json_object["secret_key"] = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==";
  }

  void expect_open(MockHttpClient& mock_http_client, int r) {
    EXPECT_CALL(mock_http_client, open(_))
      .WillOnce(Invoke([r](Context* ctx) { ctx->complete(r); }));
  }

  void expect_close(MockHttpClient& mock_http_client, int r) {
    EXPECT_CALL(mock_http_client, close(_))
      .WillOnce(Invoke([r](Context* ctx) { ctx->complete(r); }));
  }

  void expect_get_size(MockHttpClient& mock_http_client, uint64_t size, int r) {
    EXPECT_CALL(mock_http_client, get_size(_, _))
      .WillOnce(Invoke([size, r](uint64_t* out_size, Context* ctx) {
        *out_size = size;
        ctx->complete(r);
      }));
  }

  void expect_read(MockHttpClient& mock_http_client, io::Extents byte_extents,
                   const bufferlist& bl, int r) {
    uint64_t len = 0;
    for (auto [_, byte_len] : byte_extents) {
      len += byte_len;
    }
    EXPECT_CALL(mock_http_client, do_read(byte_extents, _, _))
      .WillOnce(WithArgs<1, 2>(Invoke(
        [len, bl, r](bufferlist* out_bl, Context* ctx) {
          *out_bl = bl;
          ctx->complete(r < 0 ? r : len);
        })));
  }

  json_spirit::mObject json_object;
};

TEST_F(TestMockMigrationS3Stream, OpenClose) {
  MockTestImageCtx mock_image_ctx(*m_image_ctx);

  InSequence seq;

  auto mock_http_client = new MockHttpClient();
  expect_open(*mock_http_client, 0);

  expect_close(*mock_http_client, 0);

  MockS3Stream mock_http_stream(&mock_image_ctx, json_object);

  C_SaferCond ctx1;
  mock_http_stream.open(&ctx1);
  ASSERT_EQ(0, ctx1.wait());

  C_SaferCond ctx2;
  mock_http_stream.close(&ctx2);
  ASSERT_EQ(0, ctx2.wait());
}

TEST_F(TestMockMigrationS3Stream, GetSize) {
  MockTestImageCtx mock_image_ctx(*m_image_ctx);

  InSequence seq;

  auto mock_http_client = new MockHttpClient();
  expect_open(*mock_http_client, 0);

  expect_get_size(*mock_http_client, 128, 0);

  expect_close(*mock_http_client, 0);

  MockS3Stream mock_http_stream(&mock_image_ctx, json_object);

  C_SaferCond ctx1;
  mock_http_stream.open(&ctx1);
  ASSERT_EQ(0, ctx1.wait());

  C_SaferCond ctx2;
  uint64_t size;
  mock_http_stream.get_size(&size, &ctx2);
  ASSERT_EQ(0, ctx2.wait());
  ASSERT_EQ(128, size);

  C_SaferCond ctx3;
  mock_http_stream.close(&ctx3);
  ASSERT_EQ(0, ctx3.wait());
}

TEST_F(TestMockMigrationS3Stream, Read) {
  MockTestImageCtx mock_image_ctx(*m_image_ctx);

  InSequence seq;

  auto mock_http_client = new MockHttpClient();
  expect_open(*mock_http_client, 0);

  bufferlist expect_bl;
  expect_bl.append(std::string(192, '1'));
  expect_read(*mock_http_client, {{0, 128}, {256, 64}}, expect_bl, 0);

  expect_close(*mock_http_client, 0);

  MockS3Stream mock_http_stream(&mock_image_ctx, json_object);

  C_SaferCond ctx1;
  mock_http_stream.open(&ctx1);
  ASSERT_EQ(0, ctx1.wait());

  C_SaferCond ctx2;
  bufferlist bl;
  mock_http_stream.read({{0, 128}, {256, 64}}, &bl, &ctx2);
  ASSERT_EQ(192, ctx2.wait());
  ASSERT_EQ(expect_bl, bl);

  C_SaferCond ctx3;
  mock_http_stream.close(&ctx3);
  ASSERT_EQ(0, ctx3.wait());
}

TEST_F(TestMockMigrationS3Stream, ProcessRequest) {
  MockTestImageCtx mock_image_ctx(*m_image_ctx);

  InSequence seq;

  auto mock_http_client = new MockHttpClient();
  expect_open(*mock_http_client, 0);

  expect_close(*mock_http_client, 0);

  MockS3Stream mock_http_stream(&mock_image_ctx, json_object);

  C_SaferCond ctx1;
  mock_http_stream.open(&ctx1);
  ASSERT_EQ(0, ctx1.wait());

  EmptyRequest request;
  request.method(boost::beast::http::verb::get);
  request.target("/bucket/resource");
  mock_http_client->http_processor->process_request(request);

  // basic test for date and known portion of authorization
  ASSERT_EQ(1U, request.count(boost::beast::http::field::date));
  ASSERT_EQ(1U, request.count(boost::beast::http::field::authorization));
  ASSERT_TRUE(boost::algorithm::starts_with(
    request[boost::beast::http::field::authorization],
    "AWS 0555b35654ad1656d804:"));

  C_SaferCond ctx2;
  mock_http_stream.close(&ctx2);
  ASSERT_EQ(0, ctx2.wait());
}

} // namespace migration
} // namespace librbd
