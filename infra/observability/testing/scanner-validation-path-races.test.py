"""Deterministic interleavings against real disposable fds, not production paths."""
import builtins, importlib.util, io, os, pathlib, shutil, tempfile, unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('validation_paths',pathlib.Path(__file__).resolve().parents[1]/'scanner-validation-paths.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class BoundaryRaces(unittest.TestCase):
    def setUp(self):
        self.parent=pathlib.Path(tempfile.mkdtemp(prefix='validation-path-race-')).resolve()
        os.chmod(self.parent,0o700)
        self.root=self.parent/('trivy-validation-'+'a'*16+'-'+'b'*16)
        parentIdentity=m.identity(os.stat(self.parent))
        made=m.main({'operation':'create','parent':str(self.parent),'parentIdentity':parentIdentity,
                     'name':self.root.name,'owner':'synthetic-owner'})
        self.q={'root':str(self.root),'parentIdentity':parentIdentity,'owner':'synthetic-owner',**made}
    def tearDown(self):
        shutil.rmtree(self.parent)  # test-owned parent only; rmtree does not traverse symlinks
    def test_read_directory_replaced_after_fd_open(self):
        db=self.root/'cache/db';db.mkdir(mode=0o700)
        (db/'metadata.json').write_text('{"source":"authorized"}')
        outside=self.parent/'outside';outside.mkdir(mode=0o700)
        (outside/'metadata.json').write_text('{"source":"MUST_NOT_READ"}')
        real=m.regular_read
        def swap(fd,name,limit=1048576):
            if name=='metadata.json':
                db.rename(self.root/'cache/held');db.symlink_to(outside,target_is_directory=True)
            return real(fd,name,limit)
        with patch.object(m,'regular_read',swap):
            with self.assertRaises((RuntimeError,OSError)):
                m.main({**self.q,'operation':'read','relative':'cache/db/metadata.json'})
        self.assertEqual((outside/'metadata.json').read_text(),'{"source":"MUST_NOT_READ"}')
    def test_cleanup_entry_replaced_after_directory_fd_open(self):
        entry=self.root/'report/item';entry.mkdir(mode=0o700);(entry/'owned').write_text('owned')
        outside=self.parent/'outside';outside.mkdir(mode=0o700);(outside/'sentinel').write_text('keep')
        real=m.remove_contents;inode=os.stat(entry).st_ino;swapped=False
        def swap(fd,device,remaining):
            nonlocal swapped
            if os.fstat(fd).st_ino==inode and not swapped:
                swapped=True;entry.rename(self.parent/'held');entry.symlink_to(outside,target_is_directory=True)
            return real(fd,device,remaining)
        with patch.object(m,'remove_contents',swap):
            with self.assertRaises(RuntimeError):m.main({**self.q,'operation':'cleanup'})
        self.assertTrue(swapped);self.assertEqual((outside/'sentinel').read_text(),'keep')
    def test_cleanup_root_replaced_before_rmdir(self):
        real=m.remove_contents;inode=os.stat(self.root).st_ino
        def swap(fd,device,remaining):
            real(fd,device,remaining)
            if os.fstat(fd).st_ino==inode:
                self.root.rename(self.parent/'held');self.root.symlink_to(self.parent,target_is_directory=True)
        with patch.object(m,'remove_contents',swap):
            with self.assertRaisesRegex(RuntimeError,'ROOT_REPLACED'):m.main({**self.q,'operation':'cleanup'})
        self.assertTrue(self.parent.is_dir())
    def test_same_device_bind_mount_is_rejected_by_mount_id_inventory(self):
        data='1 0 8:1 / / rw - ext4 /dev/test rw\n2 1 8:1 /else '+str(self.root/'cache')+' rw - ext4 /dev/test rw\n'
        real=builtins.open
        def opened(name,*args,**kw):return io.StringIO(data) if name=='/proc/self/mountinfo' else real(name,*args,**kw)
        with patch.object(m.sys,'platform','linux'),patch('builtins.open',opened):
            with self.assertRaisesRegex(RuntimeError,'NESTED_MOUNT'):m.main({**self.q,'operation':'inspect'})
    def test_mount_prefix_collision_is_not_containment(self):
        data='1 0 8:1 / / rw - ext4 /dev/test rw\n2 1 8:1 /else '+str(self.root)+'-other/cache rw - ext4 /dev/test rw\n'
        real=builtins.open
        def opened(name,*args,**kw):return io.StringIO(data) if name=='/proc/self/mountinfo' else real(name,*args,**kw)
        with patch.object(m.sys,'platform','linux'),patch('builtins.open',opened):
            self.assertEqual(m.main({**self.q,'operation':'inspect'})['domains'][0]['mounts'][0]['mountId'],'1')
    def test_root_replacement_and_traversal_before_read(self):
        with self.assertRaises(RuntimeError):m.main({**self.q,'operation':'read','relative':'cache/../../outside'})
        saved=self.parent/'saved';self.root.rename(saved);self.root.symlink_to(self.parent,target_is_directory=True)
        with self.assertRaises(OSError):m.main({**self.q,'operation':'inspect'})
    def test_descriptor_operation_absent_fails_closed(self):
        with patch.object(os,'supports_dir_fd',set()):
            with self.assertRaisesRegex(RuntimeError,'UNSUPPORTED'):m.main({**self.q,'operation':'inspect'})
    def test_helper_direct_request_cannot_authorize_home_via_tmpdir(self):
        with patch.dict(os.environ,{'TMPDIR':os.path.expanduser('~')}):
            with self.assertRaisesRegex(RuntimeError,'NATIVE_TEMP_PARENT'):
                m.main({'operation':'create','parent':os.path.expanduser('~'),'name':self.root.name})
    def test_helper_direct_cleanup_cannot_target_root_or_home(self):
        for root in ['/',os.path.expanduser('~')]:
            with self.assertRaisesRegex(RuntimeError,'INVALID_RUN_NAME'):
                m.main({**self.q,'operation':'cleanup','root':root})

if __name__=='__main__':unittest.main(verbosity=2)
