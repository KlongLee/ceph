# -*- coding: utf-8 -*-
# pylint: disable=too-many-public-methods

from __future__ import absolute_import

from .helper import DashboardTestCase, JObj, JLeaf, JList


class RbdTest(DashboardTestCase):

    @classmethod
    def authenticate(cls):
        cls._ceph_cmd(['dashboard', 'set-login-credentials', 'admin', 'admin'])
        cls._post('/api/auth', {'username': 'admin', 'password': 'admin'})

    @classmethod
    def create_pool(cls, name, pg_num, pool_type, application='rbd'):
        data = {
            'pool': name,
            'pg_num': pg_num,
            'pool_type': pool_type,
            'application_metadata': application
        }
        if pool_type == 'erasure':
            data['flags'] = ['ec_overwrites']
        cls._post("/api/pool", data)

    @classmethod
    def create_image(cls, pool, name, size, **kwargs):
        data = {'name': name, 'pool_name': pool, 'size': size}
        data.update(kwargs)
        return cls._task_post('/api/block/image', data)

    @classmethod
    def clone_image(cls, parent_pool, parent_image, parent_snap, pool, name,
                    **kwargs):
        # pylint: disable=too-many-arguments
        data = {'child_image_name': name, 'child_pool_name': pool}
        data.update(kwargs)
        return cls._task_post('/api/block/image/{}/{}/snap/{}/clone'
                              .format(parent_pool, parent_image, parent_snap),
                              data)

    @classmethod
    def copy_image(cls, src_pool, src_image, dest_pool, dest_image, **kwargs):
        # pylint: disable=too-many-arguments
        data = {'dest_image_name': dest_image, 'dest_pool_name': dest_pool}
        data.update(kwargs)
        return cls._task_post('/api/block/image/{}/{}/copy'
                              .format(src_pool, src_image), data)

    @classmethod
    def remove_image(cls, pool, image):
        return cls._task_delete('/api/block/image/{}/{}'.format(pool, image))

    # pylint: disable=too-many-arguments
    @classmethod
    def edit_image(cls, pool, image, name=None, size=None, features=None):
        return cls._task_put('/api/block/image/{}/{}'.format(pool, image),
                             {'name': name, 'size': size, 'features': features})

    @classmethod
    def flatten_image(cls, pool, image):
        return cls._task_post('/api/block/image/{}/{}/flatten'.format(pool, image))

    @classmethod
    def create_snapshot(cls, pool, image, snapshot):
        return cls._task_post('/api/block/image/{}/{}/snap'.format(pool, image),
                              {'snapshot_name': snapshot})

    @classmethod
    def remove_snapshot(cls, pool, image, snapshot):
        return cls._task_delete('/api/block/image/{}/{}/snap/{}'.format(pool, image, snapshot))

    @classmethod
    def update_snapshot(cls, pool, image, snapshot, new_name, is_protected):
        return cls._task_put('/api/block/image/{}/{}/snap/{}'.format(pool, image, snapshot),
                             {'new_snap_name': new_name, 'is_protected': is_protected})

    @classmethod
    def setUpClass(cls):
        super(RbdTest, cls).setUpClass()
        cls.authenticate()
        cls.create_pool('rbd', 10, 'replicated')
        cls.create_pool('rbd_iscsi', 10, 'replicated')

        cls.create_image('rbd', 'img1', 2**30)
        cls.create_image('rbd', 'img2', 2*2**30)
        cls.create_image('rbd_iscsi', 'img1', 2**30)
        cls.create_image('rbd_iscsi', 'img2', 2*2**30)

        osd_metadata = cls.ceph_cluster.mon_manager.get_osd_metadata()
        cls.bluestore_support = True
        for osd in osd_metadata:
            if osd['osd_objectstore'] != 'bluestore':
                cls.bluestore_support = False
                break

    @classmethod
    def tearDownClass(cls):
        super(RbdTest, cls).tearDownClass()
        cls._ceph_cmd(['osd', 'pool', 'delete', 'rbd', 'rbd', '--yes-i-really-really-mean-it'])
        cls._ceph_cmd(['osd', 'pool', 'delete', 'rbd_iscsi', 'rbd_iscsi',
                       '--yes-i-really-really-mean-it'])
        cls._ceph_cmd(['osd', 'pool', 'delete', 'rbd_data', 'rbd_data',
                       '--yes-i-really-really-mean-it'])

    def _validate_image(self, img, **kwargs):
        """
        Example of an RBD image json:

        {
            "size": 1073741824,
            "obj_size": 4194304,
            "num_objs": 256,
            "order": 22,
            "block_name_prefix": "rbd_data.10ae2ae8944a",
            "name": "img1",
            "pool_name": "rbd",
            "features": 61,
            "features_name": ["deep-flatten", "exclusive-lock", "fast-diff", "layering",
                              "object-map"]
        }
        """
        schema = JObj(sub_elems={
            'size': JLeaf(int),
            'obj_size': JLeaf(int),
            'num_objs': JLeaf(int),
            'order': JLeaf(int),
            'block_name_prefix': JLeaf(str),
            'name': JLeaf(str),
            'id': JLeaf(str),
            'pool_name': JLeaf(str),
            'features': JLeaf(int),
            'features_name': JList(JLeaf(str)),
            'stripe_count': JLeaf(int, none=True),
            'stripe_unit': JLeaf(int, none=True),
            'parent': JObj(sub_elems={'pool_name': JLeaf(str),
                                      'image_name': JLeaf(str),
                                      'snap_name': JLeaf(str)}, none=True),
            'data_pool': JLeaf(str, none=True),
            'snapshots': JList(JLeaf(dict)),
            'timestamp': JLeaf(str, none=True),
            'disk_usage': JLeaf(int, none=True),
            'total_disk_usage': JLeaf(int, none=True),
        })
        self.assertSchema(img, schema)

        for k, v in kwargs.items():
            if isinstance(v, list):
                self.assertSetEqual(set(img[k]), set(v))
            else:
                self.assertEqual(img[k], v)

    def _validate_snapshot(self, snap, **kwargs):
        self.assertIn('id', snap)
        self.assertIn('name', snap)
        self.assertIn('is_protected', snap)
        self.assertIn('timestamp', snap)
        self.assertIn('size', snap)
        self.assertIn('children', snap)

        for k, v in kwargs.items():
            if isinstance(v, list):
                self.assertSetEqual(set(snap[k]), set(v))
            else:
                self.assertEqual(snap[k], v)

    def _validate_snapshot_list(self, snap_list, snap_name=None, **kwargs):
        found = False
        for snap in snap_list:
            self.assertIn('name', snap)
            if snap_name and snap['name'] == snap_name:
                found = True
                self._validate_snapshot(snap, **kwargs)
                break
        if snap_name and not found:
            self.fail("Snapshot {} not found".format(snap_name))

    def test_list(self):
        data = self._view_cache_get('/api/block/image')
        self.assertStatus(200)
        self.assertEqual(len(data), 2)

        for pool_view in data:
            self.assertEqual(pool_view['status'], 0)
            self.assertIsNotNone(pool_view['value'])
            self.assertIn('pool_name', pool_view)
            self.assertIn(pool_view['pool_name'], ['rbd', 'rbd_iscsi'])
            image_list = pool_view['value']
            self.assertEqual(len(image_list), 2)

            for img in image_list:
                self.assertIn('name', img)
                self.assertIn('pool_name', img)
                self.assertIn(img['pool_name'], ['rbd', 'rbd_iscsi'])
                if img['name'] == 'img1':
                    self._validate_image(img, size=1073741824,
                                         num_objs=256, obj_size=4194304,
                                         features_name=['deep-flatten',
                                                        'exclusive-lock',
                                                        'fast-diff',
                                                        'layering',
                                                        'object-map'])
                elif img['name'] == 'img2':
                    self._validate_image(img, size=2147483648,
                                         num_objs=512, obj_size=4194304,
                                         features_name=['deep-flatten',
                                                        'exclusive-lock',
                                                        'fast-diff',
                                                        'layering',
                                                        'object-map'])
                else:
                    assert False, "Unexcepted image '{}' in result list".format(img['name'])

    def test_create(self):
        rbd_name = 'test_rbd'
        self.create_image('rbd', rbd_name, 10240)
        self.assertStatus(201)

        img = self._get('/api/block/image/rbd/test_rbd')
        self.assertStatus(200)

        self._validate_image(img, name=rbd_name, size=10240,
                             num_objs=1, obj_size=4194304,
                             features_name=['deep-flatten',
                                            'exclusive-lock',
                                            'fast-diff', 'layering',
                                            'object-map'])

        self.remove_image('rbd', rbd_name)

    def test_create_rbd_in_data_pool(self):
        if not self.bluestore_support:
            self.skipTest('requires bluestore cluster')

        self.create_pool('data_pool', 12, 'erasure')

        rbd_name = 'test_rbd_in_data_pool'
        self.create_image('rbd', rbd_name, 10240, data_pool='data_pool')
        self.assertStatus(201)

        img = self._get('/api/block/image/rbd/test_rbd_in_data_pool')
        self.assertStatus(200)

        self._validate_image(img, name=rbd_name, size=10240,
                             num_objs=1, obj_size=4194304,
                             data_pool='data_pool',
                             features_name=['data-pool', 'deep-flatten',
                                            'exclusive-lock',
                                            'fast-diff', 'layering',
                                            'object-map'])

        self.remove_image('rbd', rbd_name)
        self.assertStatus(204)
        self._ceph_cmd(['osd', 'pool', 'delete', 'data_pool', 'data_pool',
                        '--yes-i-really-really-mean-it'])

    def test_create_rbd_twice(self):
        res = self.create_image('rbd', 'test_rbd_twice', 10240)

        res = self.create_image('rbd', 'test_rbd_twice', 10240)
        self.assertStatus(409)
        self.assertEqual(res, {"errno": 17, "status": 409, "component": "rbd",
                               "detail": "[errno 17] error creating image"})
        self.remove_image('rbd', 'test_rbd_twice')
        self.assertStatus(204)

    def test_snapshots_and_clone_info(self):
        self.create_snapshot('rbd', 'img1', 'snap1')
        self.create_snapshot('rbd', 'img1', 'snap2')
        self._rbd_cmd(['snap', 'protect', 'rbd/img1@snap1'])
        self._rbd_cmd(['clone', 'rbd/img1@snap1', 'rbd_iscsi/img1_clone'])

        img = self._get('/api/block/image/rbd/img1')
        self.assertStatus(200)
        self._validate_image(img, name='img1', size=1073741824,
                             num_objs=256, obj_size=4194304, parent=None,
                             features_name=['deep-flatten', 'exclusive-lock',
                                            'fast-diff', 'layering',
                                            'object-map'])
        for snap in img['snapshots']:
            if snap['name'] == 'snap1':
                self._validate_snapshot(snap, is_protected=True)
                self.assertEqual(len(snap['children']), 1)
                self.assertDictEqual(snap['children'][0],
                                     {'pool_name': 'rbd_iscsi',
                                      'image_name': 'img1_clone'})
            elif snap['name'] == 'snap2':
                self._validate_snapshot(snap, is_protected=False)

        img = self._get('/api/block/image/rbd_iscsi/img1_clone')
        self.assertStatus(200)
        self._validate_image(img, name='img1_clone', size=1073741824,
                             num_objs=256, obj_size=4194304,
                             parent={'pool_name': 'rbd', 'image_name': 'img1',
                                     'snap_name': 'snap1'},
                             features_name=['deep-flatten', 'exclusive-lock',
                                            'fast-diff', 'layering',
                                            'object-map'])
        self.remove_image('rbd_iscsi', 'img1_clone')
        self.assertStatus(204)

    def test_disk_usage(self):
        self._rbd_cmd(['bench', '--io-type', 'write', '--io-total', '50M', 'rbd/img2'])
        self.create_snapshot('rbd', 'img2', 'snap1')
        self._rbd_cmd(['bench', '--io-type', 'write', '--io-total', '20M', 'rbd/img2'])
        self.create_snapshot('rbd', 'img2', 'snap2')
        self._rbd_cmd(['bench', '--io-type', 'write', '--io-total', '10M', 'rbd/img2'])
        self.create_snapshot('rbd', 'img2', 'snap3')
        self._rbd_cmd(['bench', '--io-type', 'write', '--io-total', '5M', 'rbd/img2'])
        img = self._get('/api/block/image/rbd/img2')
        self.assertStatus(200)
        self._validate_image(img, name='img2', size=2147483648,
                             total_disk_usage=268435456, disk_usage=67108864)

    def test_delete_non_existent_image(self):
        res = self.remove_image('rbd', 'i_dont_exist')
        self.assertStatus(409)
        self.assertEqual(res, {"errno": 2, "status": 409, "component": "rbd",
                               "detail": "[errno 2] error removing image"})

    def test_image_delete(self):
        self.create_image('rbd', 'delete_me', 2**30)
        self.assertStatus(201)
        self.create_snapshot('rbd', 'delete_me', 'snap1')
        self.assertStatus(201)
        self.create_snapshot('rbd', 'delete_me', 'snap2')
        self.assertStatus(201)

        img = self._get('/api/block/image/rbd/delete_me')
        self.assertStatus(200)
        self._validate_image(img, name='delete_me', size=2**30)
        self.assertEqual(len(img['snapshots']), 2)

        self.remove_snapshot('rbd', 'delete_me', 'snap1')
        self.assertStatus(204)
        self.remove_snapshot('rbd', 'delete_me', 'snap2')
        self.assertStatus(204)

        img = self._get('/api/block/image/rbd/delete_me')
        self.assertStatus(200)
        self._validate_image(img, name='delete_me', size=2**30)
        self.assertEqual(len(img['snapshots']), 0)

        self.remove_image('rbd', 'delete_me')
        self.assertStatus(204)

    def test_image_rename(self):
        self.create_image('rbd', 'edit_img', 2**30)
        self.assertStatus(201)
        self._get('/api/block/image/rbd/edit_img')
        self.assertStatus(200)
        self.edit_image('rbd', 'edit_img', 'new_edit_img')
        self.assertStatus(200)
        self._get('/api/block/image/rbd/edit_img')
        self.assertStatus(404)
        self._get('/api/block/image/rbd/new_edit_img')
        self.assertStatus(200)
        self.remove_image('rbd', 'new_edit_img')
        self.assertStatus(204)

    def test_image_resize(self):
        self.create_image('rbd', 'edit_img', 2**30)
        self.assertStatus(201)
        img = self._get('/api/block/image/rbd/edit_img')
        self.assertStatus(200)
        self._validate_image(img, size=2**30)
        self.edit_image('rbd', 'edit_img', size=2*2**30)
        self.assertStatus(200)
        img = self._get('/api/block/image/rbd/edit_img')
        self.assertStatus(200)
        self._validate_image(img, size=2*2**30)
        self.remove_image('rbd', 'edit_img')
        self.assertStatus(204)

    def test_image_change_features(self):
        self.create_image('rbd', 'edit_img', 2**30, features=["layering"])
        self.assertStatus(201)
        img = self._get('/api/block/image/rbd/edit_img')
        self.assertStatus(200)
        self._validate_image(img, features_name=["layering"])
        self.edit_image('rbd', 'edit_img',
                        features=["fast-diff", "object-map", "exclusive-lock"])
        img = self._get('/api/block/image/rbd/edit_img')
        self.assertStatus(200)
        self._validate_image(img, features_name=['exclusive-lock',
                                                 'fast-diff', 'layering',
                                                 'object-map'])
        self.edit_image('rbd', 'edit_img',
                        features=["journaling", "exclusive-lock"])
        img = self._get('/api/block/image/rbd/edit_img')
        self.assertStatus(200)
        self._validate_image(img, features_name=['exclusive-lock',
                                                 'journaling', 'layering'])
        self.remove_image('rbd', 'edit_img')
        self.assertStatus(204)

    def test_update_snapshot(self):
        self.create_snapshot('rbd', 'img1', 'snap5')
        self.assertStatus(201)
        img = self._get('/api/block/image/rbd/img1')
        self._validate_snapshot_list(img['snapshots'], 'snap5', is_protected=False)

        self.update_snapshot('rbd', 'img1', 'snap5', 'snap6', None)
        self.assertStatus(200)
        img = self._get('/api/block/image/rbd/img1')
        self._validate_snapshot_list(img['snapshots'], 'snap6', is_protected=False)

        self.update_snapshot('rbd', 'img1', 'snap6', None, True)
        self.assertStatus(200)
        img = self._get('/api/block/image/rbd/img1')
        self._validate_snapshot_list(img['snapshots'], 'snap6', is_protected=True)

        self.update_snapshot('rbd', 'img1', 'snap6', 'snap5', False)
        self.assertStatus(200)
        img = self._get('/api/block/image/rbd/img1')
        self._validate_snapshot_list(img['snapshots'], 'snap5', is_protected=False)

        self.remove_snapshot('rbd', 'img1', 'snap5')
        self.assertStatus(204)

    def test_snapshot_rollback(self):
        self.create_image('rbd', 'rollback_img', 2**30,
                          features=["layering", "exclusive-lock", "fast-diff",
                                    "object-map"])
        self.assertStatus(201)
        self.create_snapshot('rbd', 'rollback_img', 'snap1')
        self.assertStatus(201)

        img = self._get('/api/block/image/rbd/rollback_img')
        self.assertStatus(200)
        self.assertEqual(img['disk_usage'], 0)

        self._rbd_cmd(['bench', '--io-type', 'write', '--io-total', '5M',
                       'rbd/rollback_img'])

        img = self._get('/api/block/image/rbd/rollback_img')
        self.assertStatus(200)
        self.assertGreater(img['disk_usage'], 0)

        self._task_post('/api/block/image/rbd/rollback_img/snap/snap1/rollback')
        self.assertStatus([201, 200])

        img = self._get('/api/block/image/rbd/rollback_img')
        self.assertStatus(200)
        self.assertEqual(img['disk_usage'], 0)

        self.remove_snapshot('rbd', 'rollback_img', 'snap1')
        self.assertStatus(204)
        self.remove_image('rbd', 'rollback_img')
        self.assertStatus(204)

    def test_clone(self):
        self.create_image('rbd', 'cimg', 2**30, features=["layering"])
        self.assertStatus(201)
        self.create_snapshot('rbd', 'cimg', 'snap1')
        self.assertStatus(201)
        self.update_snapshot('rbd', 'cimg', 'snap1', None, True)
        self.assertStatus(200)
        self.clone_image('rbd', 'cimg', 'snap1', 'rbd', 'cimg-clone',
                         features=["layering", "exclusive-lock", "fast-diff",
                                   "object-map"])
        self.assertStatus([200, 201])

        img = self._get('/api/block/image/rbd/cimg-clone')
        self.assertStatus(200)
        self._validate_image(img, features_name=['exclusive-lock',
                                                 'fast-diff', 'layering',
                                                 'object-map'],
                             parent={'pool_name': 'rbd', 'image_name': 'cimg',
                                     'snap_name': 'snap1'})

        res = self.remove_image('rbd', 'cimg')
        self.assertStatus(409)
        self.assertIn('errno', res)
        self.assertEqual(res['errno'], 39)

        self.remove_image('rbd', 'cimg-clone')
        self.assertStatus(204)
        self.update_snapshot('rbd', 'cimg', 'snap1', None, False)
        self.assertStatus(200)
        self.remove_snapshot('rbd', 'cimg', 'snap1')
        self.assertStatus(204)
        self.remove_image('rbd', 'cimg')
        self.assertStatus(204)

    def test_copy(self):
        self.create_image('rbd', 'coimg', 2**30,
                          features=["layering", "exclusive-lock", "fast-diff",
                                    "object-map"])
        self.assertStatus(201)

        self._rbd_cmd(['bench', '--io-type', 'write', '--io-total', '5M',
                       'rbd/coimg'])

        self.copy_image('rbd', 'coimg', 'rbd_iscsi', 'coimg-copy',
                        features=["layering", "fast-diff", "exclusive-lock",
                                  "object-map"])
        self.assertStatus([200, 201])

        img = self._get('/api/block/image/rbd/coimg')
        self.assertStatus(200)
        self._validate_image(img, features_name=['layering', 'exclusive-lock',
                                                 'fast-diff', 'object-map'])

        img_copy = self._get('/api/block/image/rbd_iscsi/coimg-copy')
        self._validate_image(img_copy, features_name=['exclusive-lock',
                                                      'fast-diff', 'layering',
                                                      'object-map'],
                             disk_usage=img['disk_usage'])

        self.remove_image('rbd', 'coimg')
        self.assertStatus(204)
        self.remove_image('rbd_iscsi', 'coimg-copy')
        self.assertStatus(204)

    def test_flatten(self):
        self.create_snapshot('rbd', 'img1', 'snapf')
        self.update_snapshot('rbd', 'img1', 'snapf', None, True)
        self.clone_image('rbd', 'img1', 'snapf', 'rbd_iscsi', 'img1_snapf_clone')

        img = self._get('/api/block/image/rbd_iscsi/img1_snapf_clone')
        self.assertStatus(200)
        self.assertIsNotNone(img['parent'])

        self.flatten_image('rbd_iscsi', 'img1_snapf_clone')
        self.assertStatus(200)

        img = self._get('/api/block/image/rbd_iscsi/img1_snapf_clone')
        self.assertStatus(200)
        self.assertIsNone(img['parent'])

        self.update_snapshot('rbd', 'img1', 'snapf', None, False)
        self.remove_snapshot('rbd', 'img1', 'snapf')
        self.assertStatus(204)

        self.remove_image('rbd_iscsi', 'img1_snapf_clone')
        self.assertStatus(204)

    def test_default_features(self):
        default_features = self._get('/api/block/image/default_features')
        self.assertEqual(default_features, ['deep-flatten', 'exclusive-lock',
                                             'fast-diff', 'layering',
                                             'object-map'])
