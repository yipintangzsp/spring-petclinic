"""Descriptor-relative maintenance of a private validation tree. Never executes scanners.

O_NOFOLLOW applies to every component, including parents. Deletion uses held directory
descriptors, checks inode identity again before unlinkat/rmdir, and never follows links.
This is a filesystem operation helper, NOT an execution sandbox for arbitrary programs.
"""
import json, os, pathlib, re, stat, subprocess, sys

FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
def native_temp_roots():
    candidates=['/tmp']+(['/var/tmp'] if sys.platform.startswith('linux') else [])
    if sys.platform == 'darwin':
        try:
            candidates.append(subprocess.check_output(['/usr/bin/getconf','DARWIN_USER_TEMP_DIR'],
                env={'PATH':'/usr/bin:/bin','LANG':'C'},text=True,timeout=5).strip())
        except (OSError,subprocess.SubprocessError):pass
    return tuple(os.path.realpath(p) for p in candidates if os.path.isdir(p))
NATIVE_TEMP_ROOTS=native_temp_roots()
def validation_location(parent,name):
    require(bool(re.fullmatch(r'trivy-validation-[a-f0-9]{16}-[a-f0-9]{16}',name)), 'INVALID_RUN_NAME')
    require(any(parent != base and os.path.commonpath([base,parent]) == base for base in NATIVE_TEMP_ROOTS),
            'NATIVE_TEMP_PARENT_REQUIRED')
def identity(st): return {"dev": st.st_dev, "ino": st.st_ino}
def require(value, reason):
    if not value: raise RuntimeError(reason)
def private(st):
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077,
            "PRIVATE_DIRECTORY_REQUIRED")
def components(name):
    require(isinstance(name, str) and name and not os.path.isabs(name), "RELATIVE_PATH_REQUIRED")
    parts = name.split('/')
    require(all(p not in ('', '.', '..') for p in parts), "PATH_TRAVERSAL_DENIED")
    return parts
def absolute_dir(name):
    require(os.path.isabs(name) and os.path.normpath(name) == name and name != '/', "UNSAFE_ROOT")
    fd = os.open('/', FLAGS)
    try:
        for part in components(name[1:]):
            nxt = os.open(part, FLAGS, dir_fd=fd); os.close(fd); fd = nxt
        return fd
    except BaseException:
        os.close(fd); raise
def descend(fd, parts, device):
    out = os.dup(fd)
    try:
        for part in parts:
            nxt = os.open(part, FLAGS, dir_fd=out); os.close(out); out = nxt
            st = os.fstat(out); private(st)
            require(st.st_dev == device, "UNREGISTERED_DEVICE")
        return out
    except BaseException:
        os.close(out); raise
def regular_read(fd, name, limit=1048576):
    leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        st = os.fstat(leaf)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.getuid()
                and st.st_size <= limit, "UNSAFE_REGULAR_FILE")
        data = b''
        while len(data) <= limit:
            chunk = os.read(leaf, min(65536, limit + 1 - len(data)))
            if not chunk: break
            data += chunk
        end = os.fstat(leaf)
        require(len(data) <= limit and (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
                (end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns), "FILE_CHANGED_DURING_READ")
        require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(st), "FILE_REPLACED")
        return data
    finally: os.close(leaf)
def mount_records(root):
    if not sys.platform.startswith('linux'): return None
    def unescape(s):
        for a, b in [('\\040', ' '), ('\\011', '\t'), ('\\012', '\n'), ('\\134', '\\')]: s = s.replace(a, b)
        return s
    records = []
    with open('/proc/self/mountinfo') as stream:
        for line in stream:
            left, right = line.rstrip().split(' - ', 1); a = left.split(); b = right.split()
            target = pathlib.PurePosixPath(unescape(a[4])); tree = pathlib.PurePosixPath(root)
            if target == tree or tree in target.parents:
                raise RuntimeError('UNAUTHORIZED_NESTED_MOUNT')
            if target in tree.parents:
                records.append({'mountId': a[0], 'device': a[2], 'target': str(target), 'fs': b[0]})
    require(records, 'MOUNT_IDENTITY_UNKNOWN')
    return sorted(records, key=lambda r: len(r['target']))[-1:]
def remove_contents(fd, device, remaining):
    for name in os.listdir(fd):
        remaining[0] -= 1; require(remaining[0] >= 0, 'CLEANUP_ENTRY_LIMIT')
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(st.st_dev == device, 'UNREGISTERED_DEVICE')
        if stat.S_ISDIR(st.st_mode):
            child = os.open(name, FLAGS, dir_fd=fd)
            try:
                require(identity(os.fstat(child)) == identity(st), 'CLEANUP_DIRECTORY_REPLACED')
                private(os.fstat(child)); remove_contents(child, device, remaining)
                require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(st),
                        'CLEANUP_DIRECTORY_REPLACED')
                os.rmdir(name, dir_fd=fd)
            finally: os.close(child)
        else:
            # unlinkat removes this entry only; symlink targets are never traversed.
            require(stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode), 'UNSAFE_CLEANUP_ENTRY')
            require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(st), 'CLEANUP_FILE_REPLACED')
            os.unlink(name, dir_fd=fd)
def main(q):
    require(all(f in os.supports_dir_fd for f in (os.open, os.stat, os.unlink, os.rmdir)),
            'UNSUPPORTED_DESCRIPTOR_OPERATIONS')
    if q['operation'] == 'read-budget':
        file = q['file']; require(os.path.isabs(file), 'ABSOLUTE_INPUT_REQUIRED')
        parent = absolute_dir(os.path.dirname(file))
        try: return {'text': regular_read(parent, os.path.basename(file)).decode()}
        finally: os.close(parent)
    if q['operation'] == 'create':
        validation_location(q['parent'],q['name'])
        parent = absolute_dir(q['parent'])
        fd = None
        try:
            private(os.fstat(parent))
            require(identity(os.fstat(parent)) == q['parentIdentity'], 'PARENT_OWNERSHIP_LOST')
            name = q['name']
            os.mkdir(name, 0o700, dir_fd=parent); fd = os.open(name, FLAGS, dir_fd=parent)
            directories = {}
            for part in ['cache', 'tmp', 'report', 'evidence', 'logs', 'manifests']:
                os.mkdir(part, 0o700, dir_fd=fd)
                directories[part] = identity(os.stat(part, dir_fd=fd, follow_symlinks=False))
            marker = os.open('.owner', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try: os.write(marker, q['owner'].encode())
            finally: os.close(marker)
            return {'identity': identity(os.fstat(fd)), 'directories': directories}
        finally:
            if fd is not None: os.close(fd)
            os.close(parent)
    root, expected = q['root'], q['identity']
    validation_location(os.path.dirname(root),os.path.basename(root))
    parent = absolute_dir(os.path.dirname(root)); fd = None
    try:
        private(os.fstat(parent))
        require(identity(os.fstat(parent)) == q['parentIdentity'], 'PARENT_OWNERSHIP_LOST')
        fd = os.open(os.path.basename(root), FLAGS, dir_fd=parent)
        private(os.fstat(fd)); require(identity(os.fstat(fd)) == expected, 'WORKSPACE_OWNERSHIP_LOST')
        device = expected['dev']; mounts = mount_records(root)
        marker = regular_read(fd, '.owner', 128).decode()
        require(marker == q['owner'], 'WORKSPACE_OWNERSHIP_LOST')
        domains = {}
        for name, expected_child in q['directories'].items():
            child = descend(fd, components(name), device)
            try:
                st = os.fstat(child); require(identity(st) == expected_child, 'DIRECTORY_OWNERSHIP_LOST')
                v = os.statvfs(child)
                domains[str(device)] = {'identity': 'dev:' + str(device), 'capacityBytes': v.f_blocks * v.f_frsize,
                    'availableBytes': v.f_bavail * v.f_frsize, 'inodesFree': v.f_favail, 'mounts': mounts}
            finally: os.close(child)
        result = {'domains': list(domains.values()), 'mountIdentitySupported': mounts is not None}
        if q['operation'] == 'read':
            parts = components(q['relative']); require(parts[0] in q['directories'], 'UNREGISTERED_PATH')
            target = descend(fd, parts[:-1], device)
            try:
                result['text'] = regular_read(target, parts[-1]).decode()
                check = descend(fd, parts[:-1], device)
                try: require(identity(os.fstat(check)) == identity(os.fstat(target)), 'READ_DIRECTORY_REPLACED')
                finally: os.close(check)
            finally: os.close(target)
        elif q['operation'] == 'cleanup':
            remove_contents(fd, device, [10000])
            require(identity(os.stat(os.path.basename(root), dir_fd=parent, follow_symlinks=False)) == expected,
                    'CLEANUP_ROOT_REPLACED')
            os.rmdir(os.path.basename(root), dir_fd=parent)
            result['ownedWorkspaceRemoved'] = True
        else: require(q['operation'] == 'inspect', 'UNKNOWN_OPERATION')
        if q['operation'] != 'cleanup':
            # Detect replacement of any ancestor/root while descriptors were held.
            check = absolute_dir(root)
            try: require(identity(os.fstat(check)) == expected, 'WORKSPACE_REPLACED_DURING_OPERATION')
            finally: os.close(check)
            for name, expected_child in q['directories'].items():
                check = descend(fd, components(name), device)
                try: require(identity(os.fstat(check)) == expected_child, 'DIRECTORY_OWNERSHIP_LOST')
                finally: os.close(check)
        return result
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)

if __name__ == '__main__':
    try:
        request = json.loads(sys.stdin.buffer.read(1048576))
        print(json.dumps({'ok': True, 'result': main(request)}))
    except Exception as error:
        # Do not print file contents, credentials or caller-controlled paths in diagnostics.
        print(json.dumps({'ok': False, 'error': type(error).__name__ + ':' + str(error) if isinstance(error, RuntimeError)
                         else type(error).__name__ + ':PATH_OPERATION_REJECTED'}))
        sys.exit(1)
