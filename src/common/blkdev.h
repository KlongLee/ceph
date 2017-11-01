#ifndef __CEPH_COMMON_BLKDEV_H
#define __CEPH_COMMON_BLKDEV_H

enum blkdev_prop_t {
  BLKDEV_PROP_DEV,
  BLKDEV_PROP_DISCARD_GRANULARITY,
  BLKDEV_PROP_MODEL,
  BLKDEV_PROP_ROTATIONAL,
  BLKDEV_PROP_SERIAL,
  BLKDEV_PROP_VENDOR,
  BLKDEV_PROP_NUMPROPS
};

class BlkDev {
public:
  BlkDev(int fd);

  /* GoogleMock requires a virtual destructor */
  virtual ~BlkDev() {}

  // from an fd
  int discard(int64_t offset, int64_t len) const;
  int get_size(int64_t *psize) const;
  int get_devid(dev_t *id) const;
  int partition(char* partition, size_t max) const;
  bool support_discard() const;
  bool is_nvme() const;
  bool is_rotational() const;
  int dev(char *dev, size_t max) const;
  int model(char *model, size_t max) const;
  int serial(char *serial, size_t max) const;

  /* virtual for testing purposes */
  virtual const char *sysfsdir() const;
  virtual int wholedisk(char* device, size_t max) const;

protected:
  int64_t get_int_property(blkdev_prop_t prop) const;
  int64_t get_string_property( blkdev_prop_t prop, char *val,
    size_t maxlen) const;

private:
  int fd;
};

#endif
