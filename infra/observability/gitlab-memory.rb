# Append after existing gitlab.rb settings, then run gitlab-ctl reconfigure.
# Keep existing environment variables; release unused allocator pages promptly.
gitlab_rails['env'] = (gitlab_rails['env'] || {}).merge('MALLOC_CONF' => 'dirty_decay_ms:1000,muzzy_decay_ms:1000')
sidekiq['concurrency'] = 5
