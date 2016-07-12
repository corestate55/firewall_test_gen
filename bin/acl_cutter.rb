#!/usr/bin/env ruby

found_acl = false
while (line = gets)
  # acl body of extended acl
  found_acl = false if found_acl && line =~ /^\S.+$/
  # acl header of both extended acl and standard acl
  # found_acl = true if line =~ /^(?:ip\s+)?access-list.+$/
  # acl header of extended acl
  found_acl = true if line =~ /^ip\s+access-list.+$/
  puts line if found_acl
end
