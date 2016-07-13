# -*- coding: utf-8 -*-

require 'pp'
require 'logger'
require 'cisco_acl_intp'

class FirewallTestGen
  def initialize(acl_file, opts={})
    set_logger
    @logger.info('Create FirewallTestGen.')
    parser = CiscoAclIntp::Parser.new(opts)
    parser.parse_file(acl_file)
    @acl_error_list = parser.error_list
    print_acl_errors
    @acl_table = parser.acl_table
    @action = :permit # default action for each ace
  end

  # syntax checker
  def print_acl_data
    @acl_table.each do |name, acl|
      puts "ACL Name: #{name}"
      puts acl.to_s
    end
  end

  def generate_test_patterns
    @acl_table.each do |name, acl|
      case acl
      when CiscoAclIntp::NamedExtAcl, CiscoAclIntp::NumberedExtAcl
        breakdown_ext_acl(name, acl)
      else
        @logger.error 'Does not implemented for Standard Acl.'
      end
    end
  end

  private

  def set_logger
    @logger = Logger.new('firewall_test_gen.log')
    # @logger.level = Logger::DEBUG
    @logger.level = Logger::ERROR
    @logger.formatter = proc do |severity, datetime, progname, message|
      "#{datetime}: #{severity}: #{message}\n"
    end
    @logger.datetime_format = '%Y-%m-%dT%H:%M:%S '
  end

  # alias/converter; convert the state (MATCH ACE Conditions) to Boolean
  def match
    true
  end

  def not_match
    !match
  end

  def expected_action(match)
    if match
      @action == :permit ? :permit : :deny
    else
      # double negation of match/action = NOT_match/DENY
      @action == :permit ? :deny : :permit
    end
  end

  # Each argments are test-case-list of each 'term' contained in an ACE.
  # Notice: each case-list must contains at least one 'MATCH' case.
  def product_testcase_by_ace(proto, src_ip, src_port, dst_ip, dst_port)
    @logger.debug '--- action ---'
    @logger.debug @action
    @logger.debug '--- protocol pattern ---'
    @logger.debug proto
    @logger.debug '--- src ip addr pattern ---'
    @logger.debug src_ip
    @logger.debug '--- src port pattern ---'
    @logger.debug src_port
    @logger.debug '--- dst ip addr pattern ---'
    @logger.debug dst_ip
    @logger.debug '--- dst port pattern ---'
    @logger.debug dst_port
    testcase_sets = proto.product(
        src_ip, src_port, dst_ip, dst_port).collect do |set|
      match_conditions = []
      values = []
      set.each do |each|
        val, match_cond = each
        match_conditions.push(match_cond)
        values.push(val)
      end
      # count false
      not_match_count = match_conditions.count {|item| !item }
      case not_match_count
      when 0 # match
        values.push(expected_action(match)).join(', ')
      when 1 # not match (one parameter)
        values.push(expected_action(not_match)).join(', ')
      else   # not match (2 or more parameter)
        next # omit redundant test-case...
      end
    end
    # clean-up not matched (nil) element
    testcase_sets.delete_if {|item| item.nil? }

    # print result (testcases)
    csv_header = 'protocol, source-ip, source-port, destination-ip, destination-port, expected-action'
    @logger.info csv_header
    @logger.info testcase_sets
    puts csv_header
    puts testcase_sets
  end

  def breakdown_ext_acl(name, acl)
    @logger.debug "ACL Name: #{name}, class:#{acl.class}"
    acl.list.each do |ace|
      @logger.debug "ace     : #{ace.to_s}"
      case ace
      when CiscoAclIntp::ExtendedAce
        @logger.debug "action  : #{ace.action.to_s}, class:#{ace.action.class}"
        @action = ace.action.downcase == 'deny' ? :deny : :permit
        @logger.debug "protocol: #{ace.protocol.to_s}, class:#{ace.protocol.class}"
        proto_pattern = gen_proto_pattern(ace.protocol)
        @logger.debug "src spec: #{ace.src_spec.to_s}, class:#{ace.src_spec.class}"
        src_ip_pattern, src_port_pattern = gen_srcdst_pattern(ace.src_spec)
        @logger.debug "dst spec: #{ace.dst_spec.to_s}, class:#{ace.dst_spec.class}"
        dst_ip_pattern, dst_port_pattern = gen_srcdst_pattern(ace.dst_spec)
        product_testcase_by_ace(
            proto_pattern,
            src_ip_pattern, src_port_pattern,
            dst_ip_pattern, dst_port_pattern
        )
      else
        next # nop
      end
    end
  end

  # @param proto_spec [CiscoAclIntp::AceIpProtoSpec]
  def gen_proto_pattern(proto_spec)
    if proto_spec.ip?
      [[:tcp, match], [:udp, match]]
    elsif proto_spec.tcp?
      [[:tcp, match], [:udp, not_match]]
    elsif proto_spec.udp?
      [[:tcp, not_match], [:udp, match]]
    elsif proto_spec.to_s.downcase == 'icmp'
      [[:icmp, match]] # TODO, is icmp check OK like that?
    end
  end

  # @param srcdst_spec [CiscoAclIntp::AceSrcDstSpec] ACL Src/Dst spec.
  def gen_srcdst_pattern(srcdst_spec)
    ip_pattern = gen_ip_pattern(srcdst_spec.ip_spec)
    port_pattern = gen_port_pattern(srcdst_spec.port_spec)
    [ip_pattern, port_pattern]
  end

  # @param ip_spec [CiscoAclIntp::AceIpSpec] IP addr spec.
  def gen_ip_pattern(ip_spec)
    @logger.debug "  IP spec   : #{ip_spec.ipaddr}, class:#{ip_spec.ipaddr.class}"

    ip = ip_spec.ipaddr
    if ip == '0.0.0.0/0'
      # any
      [['192.0.2.1', match]] # TODO
      # if acl at infilter, ANY-IP means any host at inside of interface
      # expected: when src=any/dst=any, 'any' means ANOTHER ip addr
    elsif ip == '0.0.0.0/32'
      # see also: http://www.wdic.org/w/WDIC/0.0.0.0
      # used in DHCP, when ip address request
      # (when a client doesn't have addr)
      # it means STRICT '0.0.0.0'.
      [['0.0.0.0', match]]
    elsif ip == '255.255.255.255/32'
      # ip broadcast
      [['255.255.255.254', not_match],
       ['255.255.255.255', match]]
    elsif ip.netmask == '/32'
      # host
      [[before_ip_of(ip), not_match],
       [ip.ip, match],
       [next_ip_of(ip), not_match]]
    else
      # some subnet (or continuous wildcard equivalent netmask)
      @logger.debug "##### ip.network = #{ip.network}"
      @logger.debug "##### ip.last  = #{ip.last}"
      [[before_ip_of(ip.network), not_match],
       [next_ip_of(ip.network), match],
       [before_ip_of(ip.last), match],
       [next_ip_of(ip.last), not_match]]
    end
  end

  # @param ip [String, NetAddr::CIDRv4] IPv4 Addr
  def before_ip_of(ip)
    ip_obj = objectify_netaddr(ip)
    NetAddr::CIDRv4.create(ip_obj.to_i - 1).ip # /32 IPv4
  end

  # @param ip [String, NetAddr::CIDRv4] IPv4 Addr
  def next_ip_of(ip)
    ip_obj = objectify_netaddr(ip)
    ip_obj.next_ip
  end

  # @param ip [String, NetAddr::CIDRv4] IPv4 Addr
  # @return [NetAddr::CIDRv4]
  def objectify_netaddr(ip)
    case ip
    when String
      NetAddr::CIDRv4.create(ip)
    when NetAddr::CIDRv4
      ip
    else
      nil # error (TODO)
    end

  end

  # @param port_spec [CiscoAclIntp::AcePortSpec] TCP/UDP Port spec.
  def gen_port_pattern(port_spec)
    @logger.debug "  Port spec : #{port_spec.to_s}, class:#{port_spec.class}"
    @logger.debug "    port #{port_spec.begin_port}-#{port_spec.end_port}"
    @logger.debug "    port #{port_spec.operator}, class:#{port_spec.operator.class}"

    case port_spec.operator
    when CiscoAclIntp::AcePortOpAny
      [[-1, match]] # TODO (is it ok? use value=-1)
    when CiscoAclIntp::AcePortOpEq
      pnum = port_spec.port.number
      [[pnum - 1, not_match],
       [pnum, match],
       [pnum + 1, not_match]]
    when CiscoAclIntp::AcePortOpNeq
      pnum = port_spec.port.number
      [[pnum - 1, match],
       [pnum, not_match],
       [pnum + 1, match]]
    when CiscoAclIntp::AcePortOpGt
      pnum = port_spec.port.number
      [[pnum - 1, not_match],
       [pnum, match]]
    when CiscoAclIntp::AcePortOpLt
      pnum = port_spec.port.number
      [[pnum, match],
       [pnum + 1, not_match]]
    when CiscoAclIntp::AcePortOpRange
      pnum1 = port_spec.begin_port.number
      pnum2 = port_spec.end_port.number
      [[pnum1 - 1, not_match],
       [pnum1, match],
       [pnum2, match],
       [pnum2 + 1, not_match]]
    else
      [] # no care when protocol:ip or tcp/udp port any
    end
  end

  # syntax checker
  def print_acl_errors
    unless @acl_error_list.empty?
      STDERR.puts 'Error(s) exists in acl'
      @acl_error_list.each { |each| STDERR.puts each.to_s }
    end
  end
end