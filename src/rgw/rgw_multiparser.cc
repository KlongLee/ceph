#include "include/types.h"

#include <string.h>
#include <iostream>

#include "rgw_multi.h"

using namespace std;

#define dout_subsys ceph_subsys_rgw
                                  
int main(int argc, char **argv) {
  RGWMultiXMLParser parser;

  if (!parser.init())
    exit(1);

  char buf[1024];

  for (;;) {
    int done;
    int len;

    len = fread(buf, 1, sizeof(buf), stdin);
    if (ferror(stdin)) {
      fprintf(stderr, "Read error\n");
      exit(-1);
    }
    done = feof(stdin);

    bool result = parser.parse(buf, len, done);
    if (!result) {
      cerr << "failed to parse!" << std::endl;
    }

    if (done)
      break;
  }

  exit(0);
}

